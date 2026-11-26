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
pub mod messaging;
pub mod report_email;
pub mod repository;
pub mod security_events;
pub mod wiring;

use tokio_util::sync::CancellationToken;

/// Arranca el servicio `ms-usuarios`.
///
/// Composition root del servicio: carga la [`config::Config`] desde
/// variables de entorno, delega en [`wiring::build_app`] la aplicación
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
    let shutdown = CancellationToken::new();
    let wiring::App { router, consumer } = wiring::build_app(&config, shutdown.clone()).await?;

    let listener = tokio::net::TcpListener::bind((config.http_host.as_str(), config.http_port))
        .await
        .map_err(RunError::Bind)?;

    let signal_token = shutdown.clone();
    let served = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!(
                "shutdown signal received: stopping the HTTP server and the queue consumer"
            );
            signal_token.cancel();
        })
        .await;

    // Also reached when the server fails: stop the consumer and let an
    // in-flight email finish before the process exits.
    shutdown.cancel();
    if let Some(consumer) = consumer {
        if consumer.await.is_err() {
            tracing::error!("the report email consumer task ended abnormally");
        }
    }
    served.map_err(RunError::Serve)
}

/// Completes on Ctrl-C (`SIGINT`) or, on Unix, `SIGTERM` (what ECS sends to
/// stop a task). If a handler cannot be installed it is logged and that path
/// stays inactive (the other one still works).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "could not install the Ctrl-C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "could not install the SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
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
