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
use secrecy::SecretString;
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

/// Construye el router de la feature bajo prueba con el pool de aplicación
/// real del contenedor de test y el secreto de servicio sintético.
fn test_router(pool: PgPool) -> Router {
    api::router(
        Repository::new(pool),
        SecretString::from(TEST_GATEWAY_SECRET.to_string()),
    )
}

fn request_with_headers(
    method: &str,
    identity: Option<&str>,
    secret: Option<&str>,
    body: Body,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri("/users/me");
    if let Some(secret) = secret {
        builder = builder.header(GATEWAY_SECRET_HEADER, secret);
    }
    if let Some(identity) = identity {
        builder = builder.header(FORWARDED_USER_HEADER, identity);
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
        "email": "test-user-1@example.test",
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

    let first_put = request_with_headers(
        "PUT",
        Some("test-user-update"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(
            json!({"email": "original@example.test", "display_name": "Original"}).to_string(),
        ),
    );
    let first_response = router
        .clone()
        .oneshot(first_put)
        .await
        .expect("el primer PUT no debe fallar a nivel de transporte");
    assert_eq!(first_response.status(), StatusCode::OK);

    let second_put = request_with_headers(
        "PUT",
        Some("test-user-update"),
        Some(TEST_GATEWAY_SECRET),
        Body::from(json!({"email": "updated@example.test", "display_name": "Updated"}).to_string()),
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
        Body::from(json!({"email": "owner@example.test", "display_name": "Owner"}).to_string()),
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
