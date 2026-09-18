//! Test de integración mínimo de la feature `scaffolding`.
//!
//! Verifica, desde fuera del crate (como lo hará el resto de `tests/` en
//! features posteriores), que `user_service` expone los módulos previstos
//! en `docs/architecture.md` (`config`, `domain`, `repository`, `audit`,
//! `api`) y una función `run()` pública que compila y ejecuta sin panics.

// Los módulos son stubs sin ítems públicos todavía (se completan en
// features posteriores): el único propósito de este `use` es comprobar en
// tiempo de compilación que `user_service` los expone como `pub`, por eso
// se permite `unused_imports` aquí en vez de tratarlo como código muerto.
#[allow(unused_imports)]
use user_service::{api, audit, config, domain, repository};

#[tokio::test]
async fn run_completes_without_error_in_scaffolding_stub() {
    let result = user_service::run().await;

    assert!(result.is_ok());
}
