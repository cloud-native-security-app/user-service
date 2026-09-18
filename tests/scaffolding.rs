//! Test de integración mínimo de la feature `scaffolding`.
//!
//! Verifica, desde fuera del crate (como lo hará el resto de `tests/` en
//! features posteriores), que `user_service` expone los módulos previstos
//! en `docs/architecture.md` (`config`, `domain`, `repository`, `audit`,
//! `api`, `wiring`) y una función `run()` pública que compila y ejecuta sin
//! panics.
//!
//! Desde la feature `service_wiring` (id 7), `run()` ya no es un stub sin
//! efectos: orquesta `Config::from_env()` de verdad (ver
//! `tests/service_wiring.rs` para el flujo end-to-end completo contra
//! Postgres real, `#[ignore = "requiere Docker"]`). Este test, sin
//! variables de entorno configuradas (este binario de test corre en su
//! propio proceso, aislado de otros archivos de `tests/`), solo comprueba
//! que la ausencia de configuración se reporta como un [`RunError`] tipado
//! — nunca un panic ni un proceso que arranca a medias.

// El único propósito de este `use` es comprobar en tiempo de compilación
// que `user_service` expone estos módulos como `pub`, por eso se permite
// `unused_imports` aquí en vez de tratarlo como código muerto.
#[allow(unused_imports)]
use user_service::{api, audit, config, domain, repository, wiring, RunError};

#[tokio::test]
async fn run_returns_a_typed_config_error_when_no_environment_is_configured() {
    let result = user_service::run().await;

    assert!(matches!(result, Err(RunError::Config(_))));
}
