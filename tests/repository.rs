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

use secrecy::SecretSlice;
use sqlx::postgres::{PgPoolOptions, PgQueryResult};
use sqlx::{Error as SqlxError, PgPool, Row};
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres as PostgresImage;

use user_service::domain::{AuditEntry, ScanHistoryEntry, ScanStatus, UserProfile};
use user_service::repository::{parse_target, RepoError, Repository};
use uuid::Uuid;

/// Clave de cifrado de laboratorio (32 bytes, `0x07`) para los tests — el
/// valor no importa, solo el invariante de que el Repository recibe una
/// `SecretSlice` de 32 bytes (ver `docs/security-scope.md` §"Credenciales
/// de red").
fn test_encryption_key() -> SecretSlice<u8> {
    SecretSlice::from(vec![0x07u8; 32])
}

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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());

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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());

    let result = repo
        .update_scan_status("no-existe", ScanStatus::Completado)
        .await;

    assert!(matches!(result, Err(RepoError::NotFound)));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn append_audit_entry_persists_it_and_it_is_readable() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
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
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
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

#[tokio::test]
#[ignore = "requiere Docker"]
async fn record_scan_request_persists_history_and_audit_atomically() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
    let profile = sample_profile("test-user-8");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse antes de registrar un escaneo (FK)");

    let entry = sample_scan("scan-8", &profile.user_id, ScanStatus::Pendiente);
    let audit_entry = AuditEntry::new(
        "audit-8",
        &profile.user_id,
        &entry.target,
        "scan_requested",
        entry.requested_at,
    );

    repo.record_scan_request(&entry, &audit_entry)
        .await
        .expect("record_scan_request no debe fallar cuando ambas escrituras son válidas");

    let history = repo
        .list_scan_history(&profile.user_id)
        .await
        .expect("list_scan_history no debe fallar");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].scan_id, entry.scan_id);

    let audit = repo
        .list_audit_entries(&profile.user_id)
        .await
        .expect("list_audit_entries no debe fallar");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].id(), "audit-8");
    assert_eq!(audit[0].target(), entry.target);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn record_scan_request_rolls_back_history_when_audit_insert_fails() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
    let profile = sample_profile("test-user-9");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse antes de registrar un escaneo (FK)");

    let entry = sample_scan("scan-9", &profile.user_id, ScanStatus::Pendiente);
    // `user_id` inexistente: viola la FK de audit_log hacia users, así que
    // el INSERT de auditoría debe fallar y, con él, revertirse también el
    // INSERT de scan_history dentro de la misma transacción.
    let audit_entry = AuditEntry::new(
        "audit-9",
        "no-existe-como-usuario",
        &entry.target,
        "scan_requested",
        entry.requested_at,
    );

    let result = repo.record_scan_request(&entry, &audit_entry).await;
    assert!(
        result.is_err(),
        "se esperaba que record_scan_request fallara por la violación de FK en audit_log"
    );

    let history = repo
        .list_scan_history(&profile.user_id)
        .await
        .expect("list_scan_history no debe fallar");
    assert!(
        history.is_empty(),
        "el histórico no debe quedar persistido si la auditoría falló: la transacción debió revertirse"
    );

    let audit = repo
        .list_audit_entries(&profile.user_id)
        .await
        .expect("list_audit_entries no debe fallar");
    assert!(audit.is_empty());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn list_audit_entries_returns_empty_vec_for_user_without_entries() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
    let profile = sample_profile("test-user-10");
    repo.upsert_user(&profile)
        .await
        .expect("el usuario debe crearse");

    let audit = repo
        .list_audit_entries(&profile.user_id)
        .await
        .expect("list_audit_entries no debe fallar");

    assert!(audit.is_empty());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn list_audit_entries_does_not_return_another_users_entries() {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
    let owner = sample_profile("test-user-11-owner");
    let other = sample_profile("test-user-11-other");
    repo.upsert_user(&owner).await.expect("owner debe crearse");
    repo.upsert_user(&other).await.expect("other debe crearse");

    let entry = sample_scan("scan-11", &owner.user_id, ScanStatus::Pendiente);
    let audit_entry = AuditEntry::new(
        "audit-11",
        &owner.user_id,
        &entry.target,
        "scan_requested",
        entry.requested_at,
    );
    repo.record_scan_request(&entry, &audit_entry)
        .await
        .expect("record_scan_request no debe fallar");

    let other_audit = repo
        .list_audit_entries(&other.user_id)
        .await
        .expect("list_audit_entries no debe fallar");

    assert!(other_audit.is_empty());
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

// --- Tests de credenciales de red (feature `network_credentials_api`, id 10)

const TEST_SSH_REF: &str = "lab-only-ssh-ref-no-es-una-credencial-real";

struct NetworkCredentialTest {
    db: TestDb,
    repo: Repository,
    owner: UserProfile,
}

async fn start_network_credential_test(user_id: &str) -> NetworkCredentialTest {
    let db = start_test_db().await;
    let repo = Repository::new(db.app_pool.clone(), test_encryption_key());
    let owner = sample_profile(user_id);
    repo.upsert_user(&owner)
        .await
        .expect("el usuario owner debe crearse");
    NetworkCredentialTest { db, repo, owner }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn upsert_network_credential_then_resolve_exact_ip_returns_the_three_contract_fields() {
    let harness = start_network_credential_test("test-user-cred-1").await;

    let saved = harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.7",
            "netadmin",
            TEST_SSH_REF,
            true,
        )
        .await
        .expect("el upsert de credenciales debe funcionar");
    assert_eq!(saved.target_pattern, "203.0.113.7");
    assert_eq!(saved.network_user, "netadmin");
    assert!(saved.has_sudo);

    let target = parse_target("203.0.113.7").expect("target válido");
    let resolved = harness
        .repo
        .resolve_scan_target(&harness.owner.user_id, target)
        .await
        .expect("resolve no debe fallar");

    let resolved = resolved.expect("debe haber una credencial que matchee la IP exacta");
    assert_eq!(resolved.network_user, "netadmin");
    assert_eq!(resolved.ssh_credentials_ref, TEST_SSH_REF);
    assert!(resolved.has_sudo);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn resolve_scan_target_resolves_an_ip_inside_a_cidr_pattern() {
    let harness = start_network_credential_test("test-user-cred-2").await;
    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.0/24",
            "cidr-user",
            TEST_SSH_REF,
            false,
        )
        .await
        .expect("el upsert de credenciales debe funcionar");

    let target = parse_target("203.0.113.42").expect("target válido");
    let resolved = harness
        .repo
        .resolve_scan_target(&harness.owner.user_id, target)
        .await
        .expect("resolve no debe fallar")
        .expect("la IP dentro del CIDR debe matchear");

    assert_eq!(resolved.network_user, "cidr-user");
    assert_eq!(resolved.ssh_credentials_ref, TEST_SSH_REF);
    assert!(!resolved.has_sudo);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn resolve_scan_target_prefers_the_most_specific_matching_pattern() {
    let harness = start_network_credential_test("test-user-cred-3").await;
    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.0/24",
            "broad",
            TEST_SSH_REF,
            false,
        )
        .await
        .expect("el upsert del /24 debe funcionar");
    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.0/28",
            "specific",
            TEST_SSH_REF,
            true,
        )
        .await
        .expect("el upsert del /28 debe funcionar");

    let target = parse_target("203.0.113.7").expect("target válido");
    let resolved = harness
        .repo
        .resolve_scan_target(&harness.owner.user_id, target)
        .await
        .expect("resolve no debe fallar")
        .expect("debe matchear");

    assert_eq!(
        resolved.network_user, "specific",
        "con dos patrones que matchean, gana el más específico (/28 sobre /24)"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn resolve_scan_target_returns_none_when_no_credential_matches() {
    let harness = start_network_credential_test("test-user-cred-4").await;
    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "198.51.100.0/24",
            "netadmin",
            TEST_SSH_REF,
            false,
        )
        .await
        .expect("el upsert de credenciales debe funcionar");

    let target = parse_target("203.0.113.7").expect("target válido");
    let resolved = harness
        .repo
        .resolve_scan_target(&harness.owner.user_id, target)
        .await
        .expect("resolve no debe fallar");

    assert_eq!(
        resolved, None,
        "ningún patrón matchea un target fuera de la red configurada"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn upsert_network_credential_updates_the_existing_target_pattern_instead_of_duplicating() {
    let harness = start_network_credential_test("test-user-cred-5").await;

    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.0/24",
            "antes",
            TEST_SSH_REF,
            false,
        )
        .await
        .expect("primer upsert");
    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.0/24",
            "despues",
            TEST_SSH_REF,
            true,
        )
        .await
        .expect("segundo upsert sobre el mismo patrón");

    let listed = harness
        .repo
        .list_network_credentials(&harness.owner.user_id)
        .await
        .expect("list debe funcionar");

    assert_eq!(
        listed.len(),
        1,
        "el upsert no debe duplicar el (user_id, target_pattern)"
    );
    assert_eq!(listed[0].network_user, "despues");
    assert!(listed[0].has_sudo);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn list_network_credentials_is_scoped_to_the_user() {
    let harness = start_network_credential_test("test-user-cred-6").await;
    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.0/24",
            "netadmin",
            TEST_SSH_REF,
            false,
        )
        .await
        .expect("el upsert de credenciales debe funcionar");

    let listed = harness
        .repo
        .list_network_credentials("otro-usuario-que-no-configuro-nada")
        .await
        .expect("list no debe fallar");

    assert!(
        listed.is_empty(),
        "list solo devuelve credenciales del llamante"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn stored_ssh_reference_is_ciphertext_of_exactly_12_byte_nonce_not_plaintext() {
    let harness = start_network_credential_test("test-user-cred-7").await;
    harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            &harness.owner.user_id,
            "203.0.113.9",
            "netadmin",
            "credencial-que-no-debe-quedar-en-claro",
            false,
        )
        .await
        .expect("el upsert de credenciales debe funcionar");

    let row = sqlx::query(
        "SELECT ssh_credentials_ref_ciphertext, ssh_credentials_ref_nonce \
         FROM network_credentials WHERE user_id = $1 AND target_pattern = $2",
    )
    .bind(&harness.owner.user_id)
    .bind("203.0.113.9")
    .fetch_one(&harness.db.app_pool)
    .await
    .expect("la fila debe leerse con el rol de aplicación (SELECT otorgado)");

    let ciphertext: Vec<u8> = row.get("ssh_credentials_ref_ciphertext");
    let nonce: Vec<u8> = row.get("ssh_credentials_ref_nonce");

    assert_eq!(nonce.len(), 12, "nonce AES-256-GCM de 96 bits");
    assert_ne!(
        ciphertext, b"credencial-que-no-debe-quedar-en-claro",
        "la credencial SSH no debe persistirse en claro"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn delete_network_credential_removes_own_entry_and_it_stops_resolving() {
    let harness = start_network_credential_test("test-user-cred-8").await;
    let id = Uuid::new_v4();
    harness
        .repo
        .upsert_network_credential(
            id,
            &harness.owner.user_id,
            "203.0.113.0/24",
            "netadmin",
            TEST_SSH_REF,
            false,
        )
        .await
        .expect("el upsert de credenciales debe funcionar");

    harness
        .repo
        .delete_network_credential(id, &harness.owner.user_id)
        .await
        .expect("borrar la entrada propia debe funcionar");

    let target = parse_target("203.0.113.7").expect("target válido");
    let resolved = harness
        .repo
        .resolve_scan_target(&harness.owner.user_id, target)
        .await
        .expect("resolve no debe fallar");

    assert_eq!(resolved, None, "tras el delete, el objetivo ya no resuelve");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn delete_network_credential_returns_not_found_for_another_users_entry() {
    let harness = start_network_credential_test("test-user-cred-9-owner").await;
    let other = sample_profile("test-user-cred-9-other");
    harness
        .repo
        .upsert_user(&other)
        .await
        .expect("other debe crearse");

    let owner_id = Uuid::new_v4();
    harness
        .repo
        .upsert_network_credential(
            owner_id,
            &harness.owner.user_id,
            "203.0.113.0/24",
            "netadmin",
            TEST_SSH_REF,
            false,
        )
        .await
        .expect("el upsert del owner debe funcionar");

    let result = harness
        .repo
        .delete_network_credential(owner_id, &other.user_id)
        .await;

    assert!(
        matches!(result, Err(RepoError::NotFound)),
        "borrar una entrada ajena debe devolver NotFound (nunca 403 ni Ok): {result:?}"
    );

    let target = parse_target("203.0.113.7").expect("target válido");
    let resolved = harness
        .repo
        .resolve_scan_target(&harness.owner.user_id, target)
        .await
        .expect("resolve no debe fallar");
    assert!(
        resolved.is_some(),
        "la entrada del owner debe seguir intacta tras el delete fallido"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn delete_network_credential_returns_not_found_for_an_unknown_id() {
    let harness = start_network_credential_test("test-user-cred-10").await;

    let result = harness
        .repo
        .delete_network_credential(Uuid::new_v4(), &harness.owner.user_id)
        .await;

    assert!(matches!(result, Err(RepoError::NotFound)));
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn upsert_network_credential_for_an_unknown_user_fails_with_a_constraint_error() {
    let harness = start_network_credential_test("test-user-cred-11").await;

    let result = harness
        .repo
        .upsert_network_credential(
            Uuid::new_v4(),
            "usuario-que-no-existe",
            "203.0.113.0/24",
            "netadmin",
            TEST_SSH_REF,
            false,
        )
        .await;

    assert!(
        matches!(result, Err(RepoError::Constraint(_))),
        "la FK user_id debe rechazar credenciales para usuarios inexistentes: {result:?}"
    );
}
