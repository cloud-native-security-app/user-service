//! Envoltorio delgado del binario `ms-usuarios`.
//!
//! Inicializa el runtime `tokio` y `tracing`, y delega el resto de la
//! orquestación a [`user_service::run`]. Sin lógica de negocio propia (ver
//! `docs/architecture.md`).

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    if let Err(error) = user_service::run().await {
        tracing::error!(%error, "ms-usuarios no pudo arrancar");
        std::process::exit(1);
    }
}
