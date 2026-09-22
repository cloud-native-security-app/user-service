//! Tests de integración de `api` (feature `user_profile_api`, id 5) contra
//! un Postgres real levantado vía `testcontainers-modules`, ejercidas por
//! HTTP real a través del router `axum` (`tower::ServiceExt::oneshot`) — no
//! se llama a los handlers como funciones sueltas.
//!
//! Todos los tests están marcados `#[ignore = "requiere Docker"]` (ver
//! `docs/conventions.md`) y se ejecutan con `cargo test -- --ignored`.
//!
//! Mismo patrón de arranque de contenedor + aplicación de migraciones que
//! `tests/repository.rs` (feature `postgres_persistence`, id 4): dos pools,
//! uno de superusuario para migrar y activar el login del rol de
//! aplicación, y el pool `ms_usuarios_app` real que recibe el [`Repository`]
//! bajo prueba — así el router se ejercita con los mismos permisos de base
//! de datos con los que corre en producción.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::Router;
use secrecy::{SecretSlice, SecretString};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres as PostgresImage;
use tower::ServiceExt;

use user_service::api::{self, FORWARDED_USER_HEADER, GATEWAY_SECRET_HEADER};
use user_service::repository::Repository;

/// Secreto de servicio sintético usado únicamente dentro de este test —
/// nunca una credencial real (ver `docs/security-scope.md`).
const TEST_GATEWAY_SECRET: &str = "test-gateway-shared-secret";

/// Mantiene vivo el contenedor y el pool de aplicación durante todo el
/// test — si se descarta `_container`, `testcontainers` lo detiene de
/// inmediato.
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

/// Clave de cifrado de laboratorio (32 bytes, `0x07`) para los tests — el
/// valor no importa, solo el invariante de que el Repository recibe una
/// `SecretSlice` de 32 bytes (ver `docs/security-scope.md` §"Credenciales
/// de red").
fn test_encryption_key() -> SecretSlice<u8> {
    SecretSlice::from(vec![0x07u8; 32])
}

/// Construye el router de la feature bajo prueba con el pool de aplicación
/// real del contenedor de test y el secreto de servicio sintético.
fn test_router(pool: PgPool) -> Router {
    api::router(
        Repository::new(pool, test_encryption_key()),
        SecretString::from(TEST_GATEWAY_SECRET.to_string()),
    )
}

/// Construye el valor JSON del header `X-Forwarded-User` con el mismo shape
/// que `gateway::usuarios_client::IdentityHeaderPayload` (`{"sub",
/// "email"}`), confirmado por lectura directa de ese repo hermano (feature
/// `identity_header_contract`).
fn identity_header(sub: &str, email: &str) -> String {
    json!({"sub": sub, "email": email}).to_string()
}

/// Igual que [`identity_header`], con un email sintético derivado de `sub`
/// para los tests que no necesitan controlar el email explícitamente.
fn identity_header_default(sub: &str) -> String {
    identity_header(sub, &format!("{sub}@example.test"))
}

fn request_with_headers(
    method: &str,
    identity: Option<&str>,
    secret: Option<&str>,
    body: Body,
) -> Request<Body> {
    request_to_with_headers(method, "/users/me", identity, secret, body)
}

/// Igual que [`request_to_with_headers`], pero `identity` es el `sub` del
/// llamante: internamente se serializa como el header JSON esperado por
/// [`user_service::api::require_gateway_and_identity`] vía
/// [`identity_header_default`].
fn request_to_with_headers(
    method: &str,
    uri: &str,
    identity: Option<&str>,
    secret: Option<&str>,
    body: Body,
) -> Request<Body> {
    let identity_header_value = identity.map(identity_header_default);
    request_to_with_identity_header(method, uri, identity_header_value.as_deref(), secret, body)
}

/// Construye la request con el valor crudo (ya serializado) del header de
/// identidad, para los tests que necesitan controlar `sub`/`email` de forma
/// independiente (p. ej. simular que el email verificado cambia entre dos
/// peticiones del mismo `sub`).
fn request_to_with_identity_header(
    method: &str,
    uri: &str,
    identity_header_value: Option<&str>,
    secret: Option<&str>,
    body: Body,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(secret) = secret {
        builder = builder.header(GATEWAY_SECRET_HEADER, secret);
    }
    if let Some(identity_header_value) = identity_header_value {
        builder = builder.header(FORWARDED_USER_HEADER, identity_header_value);
    }
    builder
        .header("content-type", "application/json")
        .body(body)
        .expect("la request de test debe construirse")
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("debe poder leerse el cuerpo de la respuesta");
    serde_json::from_slice(&bytes).expect("el cuerpo de la respuesta debe ser JSON válido")
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn put_then_get_reflects_the_stored_profile() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let put_body = json!({
        "display_name": "Test User"
    })
    .to_string();
    let put_request = request_with_headers(
        "PUT",
        Some("test-user-1"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(put_body),
    );

    let put_response = router
        .clone()
        .oneshot(put_request)
        .await
        .expect("la petición PUT no debe fallar a nivel de transporte");
    assert_eq!(put_response.status(), StatusCode::OK);
    let put_payload = body_json(put_response).await;
    assert_eq!(put_payload["user_id"], "test-user-1");
    assert_eq!(put_payload["email"], "test-user-1@example.test");
    assert_eq!(put_payload["display_name"], "Test User");

    let get_request = request_with_headers(
        "GET",
        Some("test-user-1"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );

    let get_response = router
        .oneshot(get_request)
        .await
        .expect("la petición GET no debe fallar a nivel de transporte");
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_payload = body_json(get_response).await;
    assert_eq!(get_payload["user_id"], "test-user-1");
    assert_eq!(get_payload["email"], "test-user-1@example.test");
    assert_eq!(get_payload["display_name"], "Test User");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn put_updates_email_and_display_name_on_a_second_call() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    // El email ya no viene del cuerpo de la petición (feature
    // `identity_header_contract`): viene de la identidad verificada en el
    // header. Un mismo `sub` puede traer un email distinto entre dos
    // peticiones (p. ej. si el email verificado por Google cambió), así
    // que este test simula ese caso variando el email del header, no el
    // del cuerpo.
    let first_put = request_to_with_identity_header(
        "PUT",
        "/users/me",
        Some(&identity_header(
            "test-user-update",
            "original@example.test",
        )),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"display_name": "Original"}).to_string()),
    );
    let first_response = router
        .clone()
        .oneshot(first_put)
        .await
        .expect("el primer PUT no debe fallar a nivel de transporte");
    assert_eq!(first_response.status(), StatusCode::OK);

    let second_put = request_to_with_identity_header(
        "PUT",
        "/users/me",
        Some(&identity_header("test-user-update", "updated@example.test")),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"display_name": "Updated"}).to_string()),
    );
    let second_response = router
        .oneshot(second_put)
        .await
        .expect("el segundo PUT no debe fallar a nivel de transporte");
    assert_eq!(second_response.status(), StatusCode::OK);
    let payload = body_json(second_response).await;
    assert_eq!(payload["email"], "updated@example.test");
    assert_eq!(payload["display_name"], "Updated");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn missing_gateway_secret_returns_401_before_touching_the_database() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let request = request_with_headers("GET", Some("test-user-2"), None, Body::empty());

    let response = router
        .oneshot(request)
        .await
        .expect("la petición no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let payload = body_json(response).await;
    assert!(payload["error"].is_string());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn wrong_gateway_secret_returns_401() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let request = request_with_headers(
        "GET",
        Some("test-user-3"),
        Some("this-is-not-the-configured-secret"),
        Body::empty(),
    );

    let response = router
        .oneshot(request)
        .await
        .expect("la petición no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn missing_identity_header_returns_400() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let request = request_with_headers("GET", None, Some(TEST_GATEWAY_SECRET), Body::empty());

    let response = router
        .oneshot(request)
        .await
        .expect("la petición no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Feature `identity_header_contract` (id 9): un header `X-Forwarded-User`
/// que no es JSON válido se trata igual que uno ausente — `400 Bad
/// Request`, nunca un panic ni un `500`. Complementa los tests unitarios de
/// `parse_caller_identity` en `src/api.rs` ejercitando el pipeline HTTP
/// completo (middleware + router reales).
#[tokio::test]
#[ignore = "requiere Docker"]
async fn non_json_identity_header_returns_400() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let request = request_to_with_identity_header(
        "GET",
        "/users/me",
        Some("not-json-at-all"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );

    let response = router
        .oneshot(request)
        .await
        .expect("la petición no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Feature `identity_header_contract` (id 9): un header JSON sin `sub` (o
/// con `sub` vacío) se trata como identidad ausente — `400 Bad Request`.
#[tokio::test]
#[ignore = "requiere Docker"]
async fn identity_header_without_sub_returns_400() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let missing_sub = request_to_with_identity_header(
        "GET",
        "/users/me",
        Some(r#"{"email":"user@example.test"}"#),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .clone()
        .oneshot(missing_sub)
        .await
        .expect("la petición no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let empty_sub = request_to_with_identity_header(
        "GET",
        "/users/me",
        Some(&identity_header("", "user@example.test")),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(empty_sub)
        .await
        .expect("la petición no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn get_profile_returns_404_when_the_caller_has_no_profile_yet() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let request = request_with_headers(
        "GET",
        Some("test-user-without-profile"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );

    let response = router
        .oneshot(request)
        .await
        .expect("la petición no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_user_cannot_read_another_users_profile_via_get() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let create_owner_profile = request_with_headers(
        "PUT",
        Some("owner-user"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"display_name": "Owner"}).to_string()),
    );
    let create_response = router
        .clone()
        .oneshot(create_owner_profile)
        .await
        .expect("la creación del perfil dueño no debe fallar a nivel de transporte");
    assert_eq!(create_response.status(), StatusCode::OK);

    let request_as_other_user = request_with_headers(
        "GET",
        Some("someone-else"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(request_as_other_user)
        .await
        .expect("la petición no debe fallar a nivel de transporte");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "el llamante 'someone-else' no tiene perfil propio, así que nunca debe ver el de 'owner-user'"
    );
}

async fn create_profile(router: &Router, user_id: &str) {
    let request = request_with_headers(
        "PUT",
        Some(user_id),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"display_name": "Test User"}).to_string()),
    );
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("la creación del perfil no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn post_scan_creates_history_and_audit_entry_atomically() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "scan-owner").await;

    let create_request = request_to_with_headers(
        "POST",
        "/users/me/scans",
        Some("scan-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"target": "192.0.2.50"}).to_string()),
    );
    let create_response = router
        .clone()
        .oneshot(create_request)
        .await
        .expect("la petición POST no debe fallar a nivel de transporte");
    assert_eq!(create_response.status(), StatusCode::OK);
    let created = body_json(create_response).await;
    assert_eq!(created["user_id"], "scan-owner");
    assert_eq!(created["target"], "192.0.2.50");
    assert_eq!(created["status"], "PENDIENTE");
    let scan_id = created["scan_id"]
        .as_str()
        .expect("scan_id debe ser un string generado por el servicio")
        .to_string();
    assert!(!scan_id.is_empty());

    let history_request = request_to_with_headers(
        "GET",
        "/users/me/scans",
        Some("scan-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let history_response = router
        .clone()
        .oneshot(history_request)
        .await
        .expect("GET histórico no debe fallar a nivel de transporte");
    assert_eq!(history_response.status(), StatusCode::OK);
    let history = body_json(history_response).await;
    let history = history.as_array().expect("histórico debe ser un array");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["scan_id"], scan_id);
    assert_eq!(history[0]["status"], "PENDIENTE");

    let audit_request = request_to_with_headers(
        "GET",
        "/users/me/audit",
        Some("scan-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let audit_response = router
        .oneshot(audit_request)
        .await
        .expect("GET auditoría no debe fallar a nivel de transporte");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let audit = body_json(audit_response).await;
    let audit = audit.as_array().expect("auditoría debe ser un array");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["target"], "192.0.2.50");
    assert_eq!(audit[0]["user_id"], "scan-owner");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn patch_scan_status_update_is_reflected_in_get_history() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "scan-patch-owner").await;

    let create_request = request_to_with_headers(
        "POST",
        "/users/me/scans",
        Some("scan-patch-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"target": "192.0.2.60"}).to_string()),
    );
    let create_response = router
        .clone()
        .oneshot(create_request)
        .await
        .expect("POST no debe fallar a nivel de transporte");
    let created = body_json(create_response).await;
    let scan_id = created["scan_id"].as_str().unwrap().to_string();

    let patch_request = request_to_with_headers(
        "PATCH",
        &format!("/scans/{scan_id}"),
        Some("scan-patch-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"status": "COMPLETADO"}).to_string()),
    );
    let patch_response = router
        .clone()
        .oneshot(patch_request)
        .await
        .expect("PATCH no debe fallar a nivel de transporte");
    assert_eq!(patch_response.status(), StatusCode::NO_CONTENT);

    let history_request = request_to_with_headers(
        "GET",
        "/users/me/scans",
        Some("scan-patch-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let history_response = router
        .oneshot(history_request)
        .await
        .expect("GET histórico no debe fallar a nivel de transporte");
    let history = body_json(history_response).await;
    let history = history.as_array().expect("histórico debe ser un array");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["scan_id"], scan_id);
    assert_eq!(history[0]["status"], "COMPLETADO");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn patch_scan_status_returns_404_for_unknown_scan_id() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let patch_request = request_to_with_headers(
        "PATCH",
        "/scans/no-existe",
        Some("someone"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"status": "COMPLETADO"}).to_string()),
    );
    let response = router
        .oneshot(patch_request)
        .await
        .expect("PATCH no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_user_cannot_patch_another_users_scan_status() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "patch-owner").await;
    create_profile(&router, "patch-intruder").await;

    let create_request = request_to_with_headers(
        "POST",
        "/users/me/scans",
        Some("patch-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"target": "192.0.2.80"}).to_string()),
    );
    let create_response = router
        .clone()
        .oneshot(create_request)
        .await
        .expect("POST no debe fallar a nivel de transporte");
    assert_eq!(create_response.status(), StatusCode::OK);
    let created = body_json(create_response).await;
    let scan_id = created["scan_id"].as_str().unwrap().to_string();

    let patch_as_intruder = request_to_with_headers(
        "PATCH",
        &format!("/scans/{scan_id}"),
        Some("patch-intruder"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"status": "COMPLETADO"}).to_string()),
    );
    let patch_response = router
        .clone()
        .oneshot(patch_as_intruder)
        .await
        .expect("PATCH no debe fallar a nivel de transporte");
    assert_eq!(
        patch_response.status(),
        StatusCode::FORBIDDEN,
        "'patch-intruder' no es dueño de este scan_id, así que nunca debe poder mutarlo"
    );

    let history_as_owner = request_to_with_headers(
        "GET",
        "/users/me/scans",
        Some("patch-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let history_response = router
        .oneshot(history_as_owner)
        .await
        .expect("GET histórico no debe fallar a nivel de transporte");
    let history = body_json(history_response).await;
    let history = history.as_array().expect("histórico debe ser un array");
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0]["status"], "PENDIENTE",
        "el intento de PATCH rechazado no debe haber mutado el estado del escaneo"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_user_cannot_read_another_users_scan_history_or_audit() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "history-owner").await;
    create_profile(&router, "history-intruder").await;

    let create_request = request_to_with_headers(
        "POST",
        "/users/me/scans",
        Some("history-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"target": "192.0.2.70"}).to_string()),
    );
    let create_response = router
        .clone()
        .oneshot(create_request)
        .await
        .expect("POST no debe fallar a nivel de transporte");
    assert_eq!(create_response.status(), StatusCode::OK);

    let history_as_intruder = request_to_with_headers(
        "GET",
        "/users/me/scans",
        Some("history-intruder"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let history_response = router
        .clone()
        .oneshot(history_as_intruder)
        .await
        .expect("GET histórico no debe fallar a nivel de transporte");
    assert_eq!(history_response.status(), StatusCode::OK);
    let history = body_json(history_response).await;
    assert!(
        history.as_array().expect("debe ser un array").is_empty(),
        "'history-intruder' nunca debe ver el histórico de 'history-owner'"
    );

    let audit_as_intruder = request_to_with_headers(
        "GET",
        "/users/me/audit",
        Some("history-intruder"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let audit_response = router
        .oneshot(audit_as_intruder)
        .await
        .expect("GET auditoría no debe fallar a nivel de transporte");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let audit = body_json(audit_response).await;
    assert!(
        audit.as_array().expect("debe ser un array").is_empty(),
        "'history-intruder' nunca debe ver la auditoría de 'history-owner'"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_routes_require_gateway_secret_and_identity_header() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let missing_secret = request_to_with_headers(
        "GET",
        "/users/me/scans",
        Some("someone"),
        None,
        Body::empty(),
    );
    let response = router
        .clone()
        .oneshot(missing_secret)
        .await
        .expect("la petición no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let missing_identity = request_to_with_headers(
        "GET",
        "/users/me/audit",
        None,
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(missing_identity)
        .await
        .expect("la petición no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// --- Tests HTTP de credenciales de red (feature `network_credentials_api`,
// id 10). El upsert de una credencial referencia la tabla `users` por clave
// foránea, así que cada test parte creando el perfil del llamante con
// `PUT /users/me` (mismo flujo real: primero perfil, luego credenciales),
// reutilizando el helper [`create_profile`].

const TEST_SSH_REF: &str = "lab-only-ssh-ref-http-no-es-una-credencial-real";

const CRED_BODY: &str = r#"{
    "target_pattern": "203.0.113.7",
    "network_user": "netadmin-http",
    "ssh_credentials_ref": "lab-only-ssh-ref-http-no-es-una-credencial-real",
    "has_sudo": true
}"#;

#[tokio::test]
#[ignore = "requiere Docker"]
async fn post_network_credential_then_scan_targets_resolves_the_exact_ip() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "netuser-1").await;

    let post = request_to_with_headers(
        "POST",
        "/users/me/network-credentials",
        Some("netuser-1"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(CRED_BODY),
    );
    let response = router
        .clone()
        .oneshot(post)
        .await
        .expect("POST credencial no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::OK);
    let created = body_json(response).await;
    assert_eq!(created["target_pattern"], "203.0.113.7");
    assert_eq!(created["network_user"], "netadmin-http");
    assert_eq!(created["has_sudo"], true);
    assert!(
        created.get("ssh_credentials_ref").is_none(),
        "la respuesta del POST no debe devolver la credencial SSH"
    );

    let resolve = request_to_with_headers(
        "GET",
        "/users/me/scan-targets?target=203.0.113.7",
        Some("netuser-1"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(resolve)
        .await
        .expect("GET scan-targets no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::OK);
    let resolved = body_json(response).await;
    let object = resolved.as_object().expect("debe ser un objeto");
    assert_eq!(
        object.len(),
        3,
        "el shape de scan-targets debe ser EXACTO: {{network_user, ssh_credentials_ref, has_sudo}}"
    );
    assert_eq!(resolved["network_user"], "netadmin-http");
    assert_eq!(resolved["ssh_credentials_ref"], TEST_SSH_REF);
    assert_eq!(resolved["has_sudo"], true);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_targets_resolves_an_ip_inside_a_cidr_pattern() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "netuser-2").await;

    let body = r#"{
        "target_pattern": "203.0.113.0/24",
        "network_user": "cidr-http",
        "ssh_credentials_ref": "lab-only-ssh-ref-http-no-es-una-credencial-real",
        "has_sudo": false
    }"#;
    let post = request_to_with_headers(
        "POST",
        "/users/me/network-credentials",
        Some("netuser-2"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(body),
    );
    let response = router
        .clone()
        .oneshot(post)
        .await
        .expect("POST credencial no debe fallar");
    assert_eq!(response.status(), StatusCode::OK);

    let resolve = request_to_with_headers(
        "GET",
        "/users/me/scan-targets?target=203.0.113.42",
        Some("netuser-2"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(resolve)
        .await
        .expect("GET scan-targets no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::OK);
    let resolved = body_json(response).await;
    assert_eq!(resolved["network_user"], "cidr-http");
    assert_eq!(resolved["has_sudo"], false);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_targets_returns_422_when_nothing_matches() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "netuser-3").await;

    // Credencial para otra subred: el objetivo consultado no matchea.
    let body = r#"{
        "target_pattern": "198.51.100.0/24",
        "network_user": "netadmin-http",
        "ssh_credentials_ref": "lab-only-ssh-ref-http-no-es-una-credencial-real",
        "has_sudo": false
    }"#;
    let post = request_to_with_headers(
        "POST",
        "/users/me/network-credentials",
        Some("netuser-3"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(body),
    );
    let response = router
        .clone()
        .oneshot(post)
        .await
        .expect("POST credencial no debe fallar");
    assert_eq!(response.status(), StatusCode::OK);

    let resolve = request_to_with_headers(
        "GET",
        "/users/me/scan-targets?target=203.0.113.7",
        Some("netuser-3"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(resolve)
        .await
        .expect("GET scan-targets no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_targets_returns_400_for_an_invalid_target() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "netuser-4").await;

    let resolve = request_to_with_headers(
        "GET",
        "/users/me/scan-targets?target=no-es-una-ip",
        Some("netuser-4"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(resolve)
        .await
        .expect("GET scan-targets no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn scan_targets_requires_gateway_secret_and_identity() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());

    let missing_secret = request_to_with_headers(
        "GET",
        "/users/me/scan-targets?target=203.0.113.7",
        Some("netuser-5"),
        None,
        Body::empty(),
    );
    let response = router
        .clone()
        .oneshot(missing_secret)
        .await
        .expect("la petición no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let missing_identity = request_to_with_headers(
        "GET",
        "/users/me/scan-targets?target=203.0.113.7",
        None,
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(missing_identity)
        .await
        .expect("la petición no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn list_network_credentials_returns_entries_without_the_ssh_reference() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "netuser-6").await;

    let post = request_to_with_headers(
        "POST",
        "/users/me/network-credentials",
        Some("netuser-6"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(CRED_BODY),
    );
    let response = router
        .clone()
        .oneshot(post)
        .await
        .expect("POST credencial no debe fallar");
    assert_eq!(response.status(), StatusCode::OK);

    let list = request_to_with_headers(
        "GET",
        "/users/me/network-credentials",
        Some("netuser-6"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(list)
        .await
        .expect("GET list credenciales no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    let entries = listed.as_array().expect("debe ser un array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["network_user"], "netadmin-http");
    assert!(
        entries[0].get("ssh_credentials_ref").is_none(),
        "list nunca debe incluir la credencial SSH"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn delete_network_credential_removes_own_entry_and_it_stops_resolving() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "netuser-7").await;

    let post = request_to_with_headers(
        "POST",
        "/users/me/network-credentials",
        Some("netuser-7"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(CRED_BODY),
    );
    let response = router
        .clone()
        .oneshot(post)
        .await
        .expect("POST credencial no debe fallar");
    assert_eq!(response.status(), StatusCode::OK);
    let id = body_json(response).await["id"]
        .as_str()
        .expect("id")
        .to_string();

    let delete = request_to_with_headers(
        "DELETE",
        &format!("/users/me/network-credentials/{id}"),
        Some("netuser-7"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .clone()
        .oneshot(delete)
        .await
        .expect("DELETE no debe fallar a nivel de transporte");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let resolve = request_to_with_headers(
        "GET",
        "/users/me/scan-targets?target=203.0.113.7",
        Some("netuser-7"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .oneshot(resolve)
        .await
        .expect("GET scan-targets no debe fallar a nivel de transporte");
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "tras borrar la credencial, el objetivo ya no debe resolver"
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn delete_network_credential_returns_404_for_another_users_entry() {
    let db = start_test_db().await;
    let router = test_router(db.app_pool.clone());
    create_profile(&router, "netuser-8-owner").await;
    create_profile(&router, "netuser-8-intruder").await;

    let post = request_to_with_headers(
        "POST",
        "/users/me/network-credentials",
        Some("netuser-8-owner"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(CRED_BODY),
    );
    let response = router
        .clone()
        .oneshot(post)
        .await
        .expect("POST credencial no debe fallar");
    assert_eq!(response.status(), StatusCode::OK);
    let id = body_json(response).await["id"]
        .as_str()
        .expect("id")
        .to_string();

    let delete_as_intruder = request_to_with_headers(
        "DELETE",
        &format!("/users/me/network-credentials/{id}"),
        Some("netuser-8-intruder"),
        Some(TEST_GATEWAY_SECRET),
        Body::empty(),
    );
    let response = router
        .clone()
        .oneshot(delete_as_intruder)
        .await
        .expect("DELETE no debe fallar a nivel de transporte");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "borrar una entrada ajena simplifica a 404 (nunca 403), sin revelar a quién pertenece"
    );

    // La entrada del owner sigue intacta.
    let resolve = router
        .oneshot(request_to_with_headers(
            "GET",
            "/users/me/scan-targets?target=203.0.113.7",
            Some("netuser-8-owner"),
            Some(TEST_GATEWAY_SECRET),
            Body::empty(),
        ))
        .await
        .expect("GET scan-targets no debe fallar a nivel de transporte");
    assert_eq!(resolve.status(), StatusCode::OK);
}
