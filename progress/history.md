# Bitácora histórica (append-only)

> Cada vez que se cierra una sesión, su resumen se añade aquí.
> No edites entradas anteriores. Solo añades al final.

---

_Todavía no hay sesiones de implementación. El arnés (`AGENTS.md`,
`feature_list.json`, `docs/`, `CHECKPOINTS.md`, `.claude/agents/`) se
estableció replicando el patrón de `broker` y `nmap-service`, adaptado al
alcance de `ms-usuarios` (perfiles, histórico de escaneos y auditoría,
Postgres + sqlx + axum). La primera entrada real de esta bitácora la añade
la sesión que implemente la feature 1 (`scaffolding`)._

## Sesión — feature 1 (scaffolding) — 2026-09-18

**Estado final:** `done` (aprobada, ver `progress/review_1.md`).

- Se inicializó el crate `user_service` (edition 2021) con `Cargo.toml`
  declarando tokio (rt-multi-thread, macros), axum, sqlx (postgres,
  runtime-tokio-rustls), tracing, tracing-subscriber, serde (derive),
  serde_json y `testcontainers` como dev-dependency.
- `src/lib.rs` activa `#![deny(missing_docs)]` y expone los módulos `pub`
  `config`, `domain`, `repository`, `audit`, `api` (todos stubs
  documentados, sin lógica de negocio de features posteriores) y `pub async
  fn run() -> Result<(), RunError>` como punto de entrada estable de la
  biblioteca (stub sin efectos; la orquestación real es la feature
  `service_wiring`).
- `src/main.rs` es un envoltorio delgado: inicializa el runtime `tokio` y
  `tracing_subscriber`, y llama a `user_service::run()`.
- `migrations/README.md` documenta que la carpeta se completará en la
  feature `postgres_persistence`.
- `tests/scaffolding.rs` verifica desde un crate externo que los 5 módulos
  son `pub` y que `run()` compila y devuelve `Ok(())`.
- `./init.sh` corrió en verde: `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test` (1 test), `cargo test --
  --ignored` (sin tests de Docker todavía) y `cargo doc --no-deps`.
- Revisión: por indisponibilidad de la herramienta `Agent` en esta sesión,
  la revisión se realizó siguiendo al pie de la letra el protocolo de
  `.claude/agents/reviewer.md` (mismos docs, mismos checkpoints, misma
  ejecución de `./init.sh`), documentada en `progress/review_1.md` con
  veredicto `APPROVED` y esta limitación anotada explícitamente.
- Nota posterior del líder: se lanzó además un `reviewer` independiente real
  (el implementer no tiene acceso a `Agent`) que repitió la revisión desde
  cero y confirmó `APPROVED` de forma genuinamente independiente.

## Sesión — feature 2 (config) — 2026-09-18

**Estado final:** `done` (aprobada, ver `progress/review_2.md`).

- `Cargo.toml`: añadidas dependencias `secrecy = "0.10.3"` (redacción de
  secretos) y `thiserror = "2.0"` (errores tipados).
- `src/config.rs`: `Config::from_env()` lee `DATABASE_URL`, `HTTP_HOST`,
  `HTTP_PORT` y `GATEWAY_SHARED_SECRET` desde variables de entorno; una
  variable faltante o un puerto inválido produce `ConfigError` (thiserror,
  variantes `MissingVar`/`InvalidPort`) en vez de panic. La credencial de
  servicio Gateway↔ms-usuarios se guarda como `secrecy::SecretString`, y
  `Config` implementa `Debug` manualmente para garantizar que el secreto
  real nunca aparece en un `{:?}`.
- 4 tests unitarios: carga válida, variable faltante, puerto inválido, y
  verificación explícita de que el `Debug` de `Config` no filtra el
  secreto.
- No se tocó lógica de otras features (`domain`, `repository`, `audit`,
  `api` siguen como stubs de la feature 1).
- `./init.sh` en verde (fmt, clippy, tests, doc).
- Revisión: `reviewer` independiente lanzado por el líder, veredicto
  `APPROVED` en `progress/review_2.md` (sin cambios requeridos; se anotó
  como pendiente no bloqueante que el líder añadiera esta entrada de
  historial al cerrar la sesión, lo cual se hace aquí).
