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

/// Arranca el servicio `ms-usuarios`.
///
/// Composition root del servicio: en su forma final construirá la
/// configuración, el pool de conexión a Postgres y el router `axum`, y
/// pondrá el servidor HTTP a escuchar (ver feature `service_wiring`).
///
/// Por ahora es un stub sin efectos: existe únicamente para que
/// `src/main.rs` tenga un punto de entrada estable de la biblioteca desde
/// el scaffolding inicial.
///
/// # Errores
///
/// Devuelve `Err` si la orquestación real (aún no implementada) falla al
/// construir sus dependencias.
pub async fn run() -> Result<(), RunError> {
    Ok(())
}

/// Error devuelto por [`run`] cuando el servicio no puede arrancar.
///
/// Sin variantes por ahora: se completará en la feature `service_wiring`
/// cuando `run` orqueste `config`, `repository` y `api` de verdad.
#[derive(Debug)]
pub enum RunError {}

impl std::fmt::Display for RunError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl std::error::Error for RunError {}
