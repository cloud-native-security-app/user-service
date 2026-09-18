//! Tests de integración de `repository` (feature `postgres_persistence`,
//! id 4) contra un Postgres real levantado vía `testcontainers-modules`.
//!
//! Todos los tests están marcados `#[ignore = "requiere Docker"]` (ver
//! `docs/conventions.md`) y se ejecutan con `cargo test -- --ignored`.
//!
//! Diseño de dos pools por contenedor (ver
//! `progress/explore_audit_log_permissions.md`):
//! - `superuser_pool`: el rol por defecto de la imagen del módulo
//!   (`postgres`/`postgres`/db `postgres`), usado para aplicar las
//!   migraciones (`sqlx::migrate!`) y para activar el login del rol de
//!   aplicación — nunca para ejercer el repositorio bajo prueba, porque el
//!   dueño de una tabla se salta cualquier `REVOKE`.
//! - `app_pool`: el rol `ms_usuarios_app` (creado en `NOLOGIN` por la
//!   migración de permisos, con su login activado en runtime con una
//!   contraseña generada para esta ejecución del test, nunca hardcodeada en
//!   una migración versionada). Es el pool que se le pasa a
//!   [`user_service::repository::Repository`] bajo prueba, para que los
//!   tests reflejen exactamente los permisos con los que corre el
//!   repositorio en producción.

use sqlx::postgres::{PgPoolOptions, PgQueryResult};
use sqlx::{Error as SqlxError, PgPool, Row};
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres as PostgresImage;

use user_service::domain::{AuditEntry, ScanHistoryEntry, ScanStatus, UserProfile};
use user_service::repository::{RepoError, Repository};

/// Mantiene vivo el contenedor y ambos pools durante todo el test — si se
/// descarta `_container`, `testcontainers` lo detiene de inmediato.
struct TestDb {
    _container: ContainerAsync<PostgresImage>,
    app_pool: PgPool,
}

async fn start_test_db() -> TestDb {
    let container = PostgresImage::default()
        .start()
        .await
        .expect("el contenedor Postgres debe arrancar");

    let host = container.get_host().await.expect("host del contenedor");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("puerto 5432 mapeado");

    // Credenciales por defecto de la imagen del módulo
    // (`testcontainers_modules::postgres::Postgres`): user=postgres,
    // password=postgres, db=postgres.
    let superuser_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let superuser_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&superuser_url)
        .await
        .expect("el pool de superusuario debe conectar");

    sqlx::migrate!("./migrations")
        .run(&superuser_pool)
        .await
        .expect("las migraciones deben aplicarse limpiamente sobre un contenedor nuevo");

    let app_password = generate_ephemeral_password();
    sqlx::query(&format!(
        "ALTER ROLE ms_usuarios_app LOGIN PASSWORD '{app_password}'"
    ))
    .execute(&superuser_pool)
    .await
    .expect("debe poder activarse el login del rol de aplicación para el test");

    let app_url = format!("postgres://ms_usuarios_app:{app_password}@{host}:{port}/postgres");
    let app_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&app_url)
        .await
        .expect("el rol de aplicación debe poder conectarse tras activar su login");

    superuser_pool.close().await;

    TestDb {
        _container: container,
        app_pool,
    }
}

/// Genera una contraseña efímera para el rol `ms_usuarios_app`, solo válida
/// dentro del contenedor Docker desechable de este test (nunca una
/// credencial real, ver `migrations/20260918120100_lock_audit_log_permissions.sql`).
fn generate_ephemeral_password() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("el reloj del sistema debe ser posterior a UNIX_EPOCH")
        .as_nanos();
    format!("testpw{nanos}{}", std::process::id())
}

/// `TIMESTAMPTZ` de PostgreSQL solo guarda precisión de microsegundos,
/// mientras que `chrono::Utc::now()` trae nanosegundos — truncamos aquí
/// para que el valor original ya coincida byte a byte con el que se lee de
/// vuelta tras el round-trip, sin necesitar un `assert` con tolerancia.
fn now_with_db_precision() -> chrono::DateTime<chrono::Utc> {
    use chrono::SubsecRound;
    chrono::Utc::now().trunc_subsecs(6)
}

fn sample_profile(user_id: &str) -> UserProfile {
    UserProfile {
        user_id: user_id.to_string(),
        email: format!("{user_id}@example.test"),
        display_name: "Test User".to_string(),
        created_at: now_with_db_precision(),
    }
}

fn sample_scan(scan_id: &str, user_id: &str, status: ScanStatus) -> ScanHistoryEntry {
    let now = now_with_db_precision();
    ScanHistoryEntry {
        scan_id: scan_id.to_string(),
        user_id: user_id.to_string(),
        target: "192.0.2.10".to_string(),
        status,
        requested_at: now,
        updated_at: now,
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn upsert_user_then_find_returns_the_stored_profile() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());
    let profile = sample_profile("test-user-1");

    repo.upsert_user(&profile)
        .await
        .expect("el upsert de un usuario nuevo debe funcionar");

    let found = repo
        .find_user(&profile.user_id)
        .await
        .expect("find_user no debe fallar");

    assert_eq!(found, Some(profile));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn find_user_returns_none_when_user_does_not_exist() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());

    let found = repo
        .find_user("no-existe")
        .await
        .expect("find_user no debe fallar para un usuario inexistente");

    assert_eq!(found, None);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn upsert_user_updates_email_and_display_name_on_conflict() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());
    let original = sample_profile("test-user-2");
    repo.upsert_user(&original)
        .await
        .expect("el primer upsert debe funcionar");

    let mut updated = original.clone();
    updated.email = "updated@example.test".to_string();
    updated.display_name = "Updated Name".to_string();
    repo.upsert_user(&updated)
        .await
        .expect("el segundo upsert (conflicto) debe funcionar");

    let found = repo
        .find_user(&original.user_id)
        .await
        .expect("find_user no debe fallar")
        .expect("el usuario debe existir");

    assert_eq!(found.email, "updated@example.test");
    assert_eq!(found.display_name, "Updated Name");
    assert_eq!(found.created_at, original.created_at);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn insert_scan_history_then_list_returns_the_entry() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());
    let profile = sample_profile("test-user-3");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse antes del histórico (FK)");

    let entry = sample_scan("scan-1", &profile.user_id, ScanStatus::Pendiente);
    repo.insert_scan_history(&entry)
        .await
        .expect("insert_scan_history no debe fallar");

    let history = repo
        .list_scan_history(&profile.user_id)
        .await
        .expect("list_scan_history no debe fallar");

    assert_eq!(history.len(), 1);
    assert_eq!(history[0].scan_id, entry.scan_id);
    assert_eq!(history[0].target, entry.target);
    assert_eq!(history[0].status, ScanStatus::Pendiente);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn list_scan_history_returns_empty_vec_for_user_without_scans() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());
    let profile = sample_profile("test-user-4");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse");

    let history = repo
        .list_scan_history(&profile.user_id)
        .await
        .expect("list_scan_history no debe fallar");

    assert!(history.is_empty());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn update_scan_status_transitions_to_the_new_status() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());
    let profile = sample_profile("test-user-5");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse");
    let entry = sample_scan("scan-5", &profile.user_id, ScanStatus::Pendiente);
    repo.insert_scan_history(&entry)
        .await
        .expect("insert_scan_history no debe fallar");

    repo.update_scan_status(&entry.scan_id, ScanStatus::EnProgreso)
        .await
        .expect("la transición de estado debe funcionar");

    let history = repo
        .list_scan_history(&profile.user_id)
        .await
        .expect("list_scan_history no debe fallar");

    assert_eq!(history.len(), 1);
    assert_eq!(history[0].status, ScanStatus::EnProgreso);
    assert!(history[0].updated_at >= entry.updated_at);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn update_scan_status_returns_not_found_for_unknown_scan_id() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());

    let result = repo
        .update_scan_status("no-existe", ScanStatus::Completado)
        .await;

    assert!(matches!(result, Err(RepoError::NotFound)));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn append_audit_entry_persists_it_and_it_is_readable() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());
    let profile = sample_profile("test-user-6");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse antes de auditar (FK)");

    let entry = AuditEntry::new(
        "audit-1",
        &profile.user_id,
        "192.0.2.10",
        "scan_requested",
        chrono::Utc::now(),
    );
    repo.append_audit_entry(&entry)
        .await
        .expect("append_audit_entry no debe fallar");

    // Lectura directa (SELECT, permitido para ms_usuarios_app) para
    // confirmar que la entrada quedó persistida con sus datos correctos —
    // `Repository` no expone un método de lectura de auditoría porque no
    // lo pide el acceptance de esta feature.
    let row = sqlx::query("SELECT user_id, target, action FROM audit_log WHERE id = $1")
        .bind(entry.id())
        .fetch_one(&db.app_pool)
        .await
        .expect("la fila de auditoría debe existir y ser legible");

    assert_eq!(row.get::<String, _>("user_id"), profile.user_id);
    assert_eq!(row.get::<String, _>("target"), "192.0.2.10");
    assert_eq!(row.get::<String, _>("action"), "scan_requested");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn update_and_delete_against_audit_log_fail_by_permissions_for_the_app_role() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone());
    let profile = sample_profile("test-user-7");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse antes de auditar (FK)");
    let entry = AuditEntry::new(
        "audit-2",
        &profile.user_id,
        "192.0.2.20",
        "scan_requested",
        chrono::Utc::now(),
    );
    repo.append_audit_entry(&entry)
        .await
        .expect("append_audit_entry no debe fallar");

    let update_result: Result<PgQueryResult, SqlxError> =
        sqlx::query("UPDATE audit_log SET action = $1 WHERE id = $2")
            .bind("tampered")
            .bind(entry.id())
            .execute(&db.app_pool)
            .await;
    assert_fails_with_permission_denied(update_result, "UPDATE");

    let delete_result: Result<PgQueryResult, SqlxError> =
        sqlx::query("DELETE FROM audit_log WHERE id = $1")
            .bind(entry.id())
            .execute(&db.app_pool)
            .await;
    assert_fails_with_permission_denied(delete_result, "DELETE");

    // Control positivo: el mismo rol y el mismo pool siguen pudiendo
    // SELECT — si esto fallara, el rechazo de arriba podría deberse a una
    // razón equivocada (p. ej. credenciales rotas), no a los permisos.
    let select_result = sqlx::query("SELECT id FROM audit_log WHERE id = $1")
        .bind(entry.id())
        .fetch_optional(&db.app_pool)
        .await
        .expect("SELECT debe seguir permitido para ms_usuarios_app");
    assert!(
        select_result.is_some(),
        "la fila de auditoría debe seguir intacta: ni el UPDATE ni el DELETE debieron aplicarse"
    );
}

/// Verifica que `result` es un error de base de datos con SQLSTATE `42501`
/// (`insufficient_privilege`) — nunca `Ok`, nunca otra variante de
/// `sqlx::Error` (lo que indicaría que el fallo fue por otra razón, p. ej.
/// un typo en el SQL, y el test estaría dando un falso positivo).
fn assert_fails_with_permission_denied(result: Result<PgQueryResult, SqlxError>, op: &str) {
    match result {
        Ok(_) => panic!(
            "{op} contra audit_log con el rol de aplicación tuvo éxito; \
             se esperaba que la base de datos lo rechazara por permisos"
        ),
        Err(SqlxError::Database(db_err)) => {
            assert_eq!(
                db_err.code().as_deref(),
                Some("42501"),
                "{op} contra audit_log falló, pero no por 'insufficient_privilege' \
                 (SQLSTATE 42501) sino: {db_err}"
            );
        }
        Err(other) => panic!(
            "{op} contra audit_log debía fallar con sqlx::Error::Database(..), \
             no con {other:?}"
        ),
    }
}
