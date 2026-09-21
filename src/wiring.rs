//! Composition root: construye los pools de conexión a PostgreSQL definidos
//! por [`Config`], aplica las migraciones de `migrations/` y ensambla el
//! router `axum` completo del servicio (perfil, histórico, auditoría y
//! `GET /health`).
//!
//! ## Por qué dos pools
//!
//! `migrations/20260918120100_lock_audit_log_permissions.sql` deja el rol
//! de aplicación `ms_usuarios_app` sin permiso de `UPDATE`/`DELETE` sobre
//! `audit_log` (RF-15) — pero el dueño de una tabla en PostgreSQL se salta
//! cualquier `REVOKE`, así que el rol que aplica `sqlx::migrate!` (dueño de
//! las tablas) no puede ser el mismo que sirve tráfico HTTP real en
//! producción sin anular ese endurecimiento fuera de los tests. Por eso
//! [`build_router`] usa dos conexiones distintas:
//!
//! - [`Config::migrations_database_url`]: solo para aplicar migraciones al
//!   arrancar, nunca para servir tráfico.
//! - [`Config::database_url`]: el pool que recibe [`Repository`] y sirve
//!   las peticiones HTTP reales.
//!
//! En dev/test ambas variables pueden apuntar al mismo rol (o la segunda
//! puede omitirse por completo, ver `src/config.rs`); en producción el
//! operador las separa.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::api;
use crate::config::Config;
use crate::repository::Repository;

/// Aplica las migraciones pendientes de `migrations/` contra
/// [`Config::migrations_database_url`] y, si tiene éxito, construye el
/// router `axum` completo (perfil, histórico, auditoría y `GET /health`)
/// listo para servir tráfico sobre [`Config::database_url`].
///
/// `GET /health` queda deliberadamente fuera del middleware de
/// autenticación aplicado por [`api::router`]: un orquestador de
/// infraestructura (RNF-09) debe poder comprobar la salud del proceso sin
/// conocer la credencial de servicio Gateway↔`ms-usuarios`.
///
/// # Errores
///
/// Devuelve [`WiringError`] si no se puede conectar con cualquiera de los
/// dos pools, o si la aplicación de migraciones falla. Nunca hace
/// `panic!` ni deja el router a medio ensamblar.
pub async fn build_router(config: &Config) -> Result<Router, WiringError> {
    migrate(&config.migrations_database_url).await?;

    let database_pool = PgPoolOptions::new()
        .connect(&config.database_url)
        .await
        .map_err(|_| WiringError::DatabaseConnectionFailed)?;

    let health_pool = database_pool.clone();
    let repository = Repository::new(database_pool, config.credentials_encryption_key.clone());

    let api_router = api::router(repository, config.gateway_shared_secret.clone());
    let health_router = Router::new()
        .route("/health", get(health))
        .with_state(health_pool);

    Ok(health_router.merge(api_router))
}

/// Conecta con `migrations_database_url` y aplica las migraciones
/// pendientes de `migrations/` (`sqlx::migrate!`, embebidas en el binario en
/// tiempo de compilación). El pool se cierra al terminar: solo migra el
/// esquema, nunca sirve tráfico HTTP.
async fn migrate(migrations_database_url: &str) -> Result<(), WiringError> {
    let migrations_pool = PgPoolOptions::new()
        .connect(migrations_database_url)
        .await
        .map_err(|_| WiringError::MigrationsConnectionFailed)?;

    let result = sqlx::migrate!("./migrations").run(&migrations_pool).await;

    migrations_pool.close().await;

    result.map_err(|_| WiringError::MigrationFailed)
}

/// `GET /health` (RNF-09): responde `200 OK` si el pool de aplicación puede
/// ejercer una consulta trivial (`SELECT 1`) contra PostgreSQL, o
/// `503 Service Unavailable` si falla — no se limita a confirmar que el
/// proceso está vivo.
async fn health(State(pool): State<PgPool>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&pool).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Error devuelto por [`build_router`] cuando el servicio no puede
/// inicializar su capa de persistencia.
///
/// Ninguna variante incluye el mensaje crudo de `sqlx` (que podría incluir
/// la URL de conexión, con credenciales) — ver `docs/security-scope.md`.
#[derive(Debug, thiserror::Error)]
pub enum WiringError {
    /// No se pudo conectar a la base de datos con el pool de migraciones.
    #[error("no se pudo conectar a la base de datos para aplicar migraciones")]
    MigrationsConnectionFailed,
    /// La aplicación de migraciones pendientes falló.
    #[error("fallo al aplicar las migraciones de base de datos")]
    MigrationFailed,
    /// No se pudo conectar a la base de datos con el pool de aplicación.
    #[error("no se pudo conectar a la base de datos de aplicación")]
    DatabaseConnectionFailed,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::{SecretBox, SecretString};
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    /// Puerto de loopback que no tiene nada escuchando: usado para
    /// verificar, sin depender de Docker, que un fallo de conectividad se
    /// traduce en un `WiringError`/`503` tipado en vez de un panic (mismo
    /// patrón que `repository.rs`).
    const UNREACHABLE_URL: &str = "postgres://user:pass@127.0.0.1:1/db";

    #[tokio::test]
    async fn health_returns_503_when_postgres_is_unreachable() {
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy(UNREACHABLE_URL)
            .expect("connect_lazy no debe fallar de forma síncrona");

        let status = health(State(pool)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn build_router_returns_typed_error_when_migrations_database_is_unreachable() {
        let config = Config {
            database_url: UNREACHABLE_URL.to_string(),
            http_host: "127.0.0.1".to_string(),
            http_port: 0,
            gateway_shared_secret: SecretString::from("test-secret".to_string()),
            credentials_encryption_key: SecretBox::from(vec![0x07u8; 32].into_boxed_slice()),
            migrations_database_url: UNREACHABLE_URL.to_string(),
        };

        let result = build_router(&config).await;

        assert!(matches!(
            result,
            Err(WiringError::MigrationsConnectionFailed)
        ));
    }
}
