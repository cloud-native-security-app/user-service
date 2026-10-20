//! Biblioteca del microservicio `ms-usuarios`.
//!
//! Mantiene el perfil de cada usuario autenticado (identidad ya verificada
//! por el Gateway/IDaaS vía Google OAuth 2.0 / OIDC, RF-01), el histórico de
//! escaneos que ha solicitado (RF-13) y el registro inmutable de auditoría
//! de quién solicitó qué escaneo y cuándo (RF-15).
//!
//! `src/main.rs` es un envoltorio delgado que solo inicializa el runtime
//! `tokio` y `tracing`, y delega el resto de la orquestación a [`run`].
//!
//! Ver `docs/architecture.md` para el detalle de cada capa (`config`,
//! `domain`, `repository`, `audit`, `api`).

#![deny(missing_docs)]

pub mod api;
pub mod audit;
pub mod config;
pub mod domain;
pub mod repository;
pub mod wiring;

/// Arranca el servicio `ms-usuarios`.
///
/// Composition root del servicio: carga la [`config::Config`] desde
/// variables de entorno, delega en [`wiring::build_router`] la aplicación
/// de migraciones y el ensamblado del router `axum` completo (perfil,
/// histórico, auditoría y `GET /health`), y pone el servidor HTTP a
/// escuchar en `Config::http_host`/`Config::http_port`.
///
/// Un fallo en cualquiera de esos pasos (configuración inválida, Postgres
/// inalcanzable, migraciones fallidas, o el propio bind del puerto) se
/// reporta como un [`RunError`] explícito — el proceso nunca queda
/// sirviendo tráfico a medio inicializar.
///
/// # Errores
///
/// Ver [`RunError`] para el detalle de cada causa posible.
pub async fn run() -> Result<(), RunError> {
    let config = config::Config::from_env()?;
    let app = wiring::build_router(&config).await?;

    let listener = tokio::net::TcpListener::bind((config.http_host.as_str(), config.http_port))
        .await
        .map_err(RunError::Bind)?;

    axum::serve(listener, app).await.map_err(RunError::Serve)
}

/// Error devuelto por [`run`] cuando el servicio no puede arrancar.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// La configuración del servicio no pudo cargarse desde variables de
    /// entorno.
    #[error("no se pudo cargar la configuración: {0}")]
    Config(#[from] config::ConfigError),
    /// La inicialización de la capa de persistencia (migraciones o pool de
    /// aplicación) falló.
    #[error("no se pudo inicializar la base de datos: {0}")]
    Wiring(#[from] wiring::WiringError),
    /// El servidor HTTP no pudo hacer bind del host/puerto configurado.
    #[error("no se pudo hacer bind del servidor HTTP: {0}")]
    Bind(std::io::Error),
    /// El servidor HTTP terminó con un error durante su ejecución.
    #[error("el servidor HTTP terminó con un error: {0}")]
    Serve(std::io::Error),
}
