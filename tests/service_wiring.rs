//! Test de integración end-to-end de `service_wiring` (feature id 7) contra
//! un Postgres real levantado vía `testcontainers-modules`.
//!
//! A diferencia de `tests/api.rs` (que ejercita el router con
//! `tower::ServiceExt::oneshot`, sin bind real a un puerto), este test
//! levanta el servicio real: hace `bind` a `127.0.0.1:0` (puerto efímero),
//! arranca `axum::serve` en una tarea de fondo y ejerce el flujo completo
//! con un cliente HTTP real (`reqwest`) — como lo haría el Gateway en
//! producción.
//!
//! Mismo patrón de dos pools por contenedor que `tests/api.rs`/
//! `tests/repository.rs` (ver `progress/explore_audit_log_permissions.md`):
//! el pool de superusuario aplica las migraciones y activa el login del rol
//! de aplicación; el rol `ms_usuarios_app` (con su login activado en
//! runtime, contraseña efímera nunca hardcodeada) es el que sirve tráfico
//! HTTP real. Se refleja en [`Config`] con `migrations_database_url` (rol
//! superusuario/dueño) y `database_url` (rol `ms_usuarios_app`), la
//! decisión de diseño documentada en `src/wiring.rs`.
//!
//! Todos los tests están marcados `#[ignore = "requiere Docker"]` (ver
//! `docs/conventions.md`) y se ejecutan con `cargo test -- --ignored`.

use std::net::SocketAddr;

use reqwest::StatusCode;
use secrecy::SecretString;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres as PostgresImage;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use user_service::config::Config;
use user_service::wiring;

/// Secreto de servicio sintético usado únicamente dentro de este test —
/// nunca una credencial real (ver `docs/security-scope.md`).
const TEST_GATEWAY_SECRET: &str = "test-gateway-shared-secret";

/// Header con la identidad ya verificada que el Gateway reenvía (ver
/// `src/api.rs::FORWARDED_USER_HEADER`), duplicado aquí como literal para
/// no acoplar este test de caja negra a un `use` interno del router.
const FORWARDED_USER_HEADER: &str = "X-Forwarded-User";

/// Header con la credencial de servicio Gateway↔`ms-usuarios` (ver
/// `src/api.rs::GATEWAY_SECRET_HEADER`).
const GATEWAY_SECRET_HEADER: &str = "X-Gateway-Secret";

/// Mantiene vivos el contenedor Postgres y el servidor HTTP de fondo
/// durante todo el test: si se descarta `_container`, `testcontainers` lo
/// detiene de inmediato; si se descarta `_server`, se aborta la tarea que
/// sirve tráfico.
struct RunningService {
    _container: ContainerAsync<PostgresImage>,
    _server: JoinHandle<()>,
    base_url: String,
}

/// Levanta un contenedor Postgres de test, aplica las migraciones y activa
/// el login del rol de aplicación (mismo patrón que `tests/api.rs`), arma
/// la [`Config`] de dos pools y ensambla + sirve el servicio real de
/// `service_wiring` en un puerto efímero de loopback.
async fn start_running_service() -> RunningService {
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
    // password=postgres, db=postgres. Este es el rol "dueño" de las
    // tablas, usado exclusivamente para migrar (ver `src/wiring.rs`).
    let superuser_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let superuser_pool: PgPool = PgPoolOptions::new()
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

    superuser_pool.close().await;

    let app_url = format!("postgres://ms_usuarios_app:{app_password}@{host}:{port}/postgres");

    let config = Config {
        database_url: app_url,
        http_host: "127.0.0.1".to_string(),
        http_port: 0,
        gateway_shared_secret: SecretString::from(TEST_GATEWAY_SECRET.to_string()),
        migrations_database_url: superuser_url,
    };

    let app = wiring::build_router(&config)
        .await
        .expect("build_router debe ensamblar el servicio (migraciones + pools + router)");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a un puerto efímero de loopback debe funcionar");
    let addr: SocketAddr = listener
        .local_addr()
        .expect("debe poder leerse la dirección/puerto asignado por el sistema operativo");

    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("axum::serve no debe fallar durante el test");
    });

    RunningService {
        _container: container,
        _server: server,
        base_url: format!("http://{addr}"),
    }
}

/// Genera una contraseña efímera para el rol `ms_usuarios_app`, solo válida
/// dentro del contenedor Docker desechable de este test (nunca una
/// credencial real, ver
/// `migrations/20260918120100_lock_audit_log_permissions.sql`).
fn generate_ephemeral_password() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("el reloj del sistema debe ser posterior a UNIX_EPOCH")
        .as_nanos();
    format!("testpw{nanos}{}", std::process::id())
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn health_responds_200_without_any_authentication_header() {
    let service = start_running_service().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/health", service.base_url))
        .send()
        .await
        .expect("GET /health no debe fallar a nivel de transporte");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn full_flow_create_profile_scan_history_and_audit_over_real_http() {
    let service = start_running_service().await;
    let client = reqwest::Client::new();
    let user_id = "wiring-e2e-user";

    // 1. PUT /users/me — crea el perfil del llamante.
    let put_response = client
        .put(format!("{}/users/me", service.base_url))
        .header(GATEWAY_SECRET_HEADER, TEST_GATEWAY_SECRET)
        .header(FORWARDED_USER_HEADER, user_id)
        .json(&json!({
            "email": "wiring-e2e-user@example.test",
            "display_name": "Wiring E2E User"
        }))
        .send()
        .await
        .expect("PUT /users/me no debe fallar a nivel de transporte");
    assert_eq!(put_response.status(), StatusCode::OK);
    let profile: Value = put_response
        .json()
        .await
        .expect("el cuerpo de PUT /users/me debe ser JSON válido");
    assert_eq!(profile["user_id"], user_id);
    assert_eq!(profile["email"], "wiring-e2e-user@example.test");
    assert_eq!(profile["display_name"], "Wiring E2E User");

    // 2. POST /users/me/scans — registra una solicitud de escaneo (RF-13)
    //    y su entrada de auditoría (RF-15) atómicamente.
    let create_scan_response = client
        .post(format!("{}/users/me/scans", service.base_url))
        .header(GATEWAY_SECRET_HEADER, TEST_GATEWAY_SECRET)
        .header(FORWARDED_USER_HEADER, user_id)
        .json(&json!({"target": "192.0.2.100"}))
        .send()
        .await
        .expect("POST /users/me/scans no debe fallar a nivel de transporte");
    assert_eq!(create_scan_response.status(), StatusCode::OK);
    let created_scan: Value = create_scan_response
        .json()
        .await
        .expect("el cuerpo de POST /users/me/scans debe ser JSON válido");
    assert_eq!(created_scan["user_id"], user_id);
    assert_eq!(created_scan["target"], "192.0.2.100");
    assert_eq!(created_scan["status"], "PENDIENTE");
    let scan_id = created_scan["scan_id"]
        .as_str()
        .expect("scan_id debe ser un string generado por el servicio")
        .to_string();
    assert!(!scan_id.is_empty());

    // 3. GET /users/me/scans — el histórico del llamante refleja el
    //    escaneo recién solicitado (RF-13).
    let history_response = client
        .get(format!("{}/users/me/scans", service.base_url))
        .header(GATEWAY_SECRET_HEADER, TEST_GATEWAY_SECRET)
        .header(FORWARDED_USER_HEADER, user_id)
        .send()
        .await
        .expect("GET /users/me/scans no debe fallar a nivel de transporte");
    assert_eq!(history_response.status(), StatusCode::OK);
    let history: Value = history_response
        .json()
        .await
        .expect("el cuerpo de GET /users/me/scans debe ser JSON válido");
    let history = history.as_array().expect("el histórico debe ser un array");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["scan_id"], scan_id);
    assert_eq!(history[0]["target"], "192.0.2.100");
    assert_eq!(history[0]["status"], "PENDIENTE");

    // 4. GET /users/me/audit — la entrada de auditoría del escaneo
    //    solicitado es visible para su propio dueño (RF-15).
    let audit_response = client
        .get(format!("{}/users/me/audit", service.base_url))
        .header(GATEWAY_SECRET_HEADER, TEST_GATEWAY_SECRET)
        .header(FORWARDED_USER_HEADER, user_id)
        .send()
        .await
        .expect("GET /users/me/audit no debe fallar a nivel de transporte");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let audit: Value = audit_response
        .json()
        .await
        .expect("el cuerpo de GET /users/me/audit debe ser JSON válido");
    let audit = audit.as_array().expect("la auditoría debe ser un array");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["user_id"], user_id);
    assert_eq!(audit[0]["target"], "192.0.2.100");
}
