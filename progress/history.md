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

## Sesión — feature 3 (domain_model) — 2026-09-18

**Estado final:** `done` (aprobada, ver `progress/review_3.md`).

- `src/domain.rs`: `UserProfile { user_id, email, display_name, created_at }`,
  `ScanHistoryEntry { scan_id, user_id, target, status: ScanStatus,
  requested_at, updated_at }` con `ScanStatus` como enum cerrado (`Pendiente`,
  `EnProgreso`, `Completado`, `Fallido`, los 4 estados de RF-07; un string
  desconocido falla la deserialización en vez de caer en un default), y
  `AuditEntry { id, user_id, target, action, recorded_at }` con campos
  privados y solo getters de lectura — sin `&mut self` ni setters, append-only
  por diseño del propio tipo.
- Todos los tipos derivan `Serialize`/`Deserialize`.
- `Cargo.toml`: añadida dependencia `chrono` (feature `serde`) para los
  timestamps.
- 10 tests unitarios: round-trip de serialización de los tres tipos,
  encoding estable de `ScanStatus`, y rechazo de una variante desconocida al
  deserializar.
- No se tocó lógica de otras features (`config` intacto desde la feature 2;
  `repository`, `audit`, `api` siguen como stubs).
- `./init.sh` en verde (fmt, clippy, tests, doc).
- Revisión: `reviewer` independiente lanzado por el líder, veredicto
  `APPROVED` en `progress/review_3.md`.

## Sesión — feature 4 (postgres_persistence) — 2026-09-18

**Estado final:** `done` (aprobada, ver `progress/review_4.md`).

- Investigación previa: el líder lanzó dos exploradores en paralelo
  (`progress/explore_testcontainers_postgres.md`,
  `progress/explore_audit_log_permissions.md`) para resolver de antemano dos
  problemas difíciles: cómo levantar Postgres con `testcontainers-modules` +
  aplicar migraciones `sqlx` en tests, y cómo diseñar el refuerzo de
  permisos de `audit_log` a nivel de rol de base de datos sin que el test
  fuera un falso positivo (el dueño de una tabla se salta cualquier
  `REVOKE`).
- `migrations/20260918120000_create_core_schema.sql`: tablas `users`,
  `scan_history`, `audit_log` con FKs (`scan_history.user_id -> users`,
  `audit_log.user_id -> users`), `status` como `TEXT` + `CHECK` alineado con
  el encoding `SCREAMING_SNAKE_CASE` de `ScanStatus`.
- `migrations/20260918120100_lock_audit_log_permissions.sql`: crea
  (idempotentemente) el rol `ms_usuarios_app` en `NOLOGIN` sin contraseña
  embebida, revoca todo de `PUBLIC` y del propio rol, y concede
  `SELECT, INSERT, UPDATE` en `users`/`scan_history` pero **solo
  `SELECT, INSERT`** en `audit_log` — nunca `UPDATE`/`DELETE`.
- `src/repository.rs`: `Repository { pool: PgPool }` con `upsert_user`,
  `find_user`, `insert_scan_history`, `update_scan_status`,
  `list_scan_history`, `append_audit_entry` y `RepoError` (`thiserror`,
  `From<sqlx::Error>`) — sin ningún método mutador para `audit_log`; un
  id/usuario inexistente devuelve `Ok(None)`/`Vec` vacío, nunca error;
  fallos de conexión son `RepoError` distinguible, nunca panic.
- `tests/repository.rs`: 9 tests `#[ignore = "requiere Docker"]` contra
  Postgres real vía `testcontainers-modules` (pool superusuario para migrar
  y fixtures, pool del rol `ms_usuarios_app` con login activado en runtime
  para ejercer el repositorio real): upsert+find, conflicto de upsert,
  insert+list de histórico, transición de estado, `update_scan_status`
  sobre id inexistente, append+lectura de auditoría, y el test explícito de
  que `UPDATE`/`DELETE` contra `audit_log` con el pool del rol de
  aplicación falla con SQLSTATE `42501` — con control positivo de que
  `SELECT`/`INSERT` sí funcionan con ese mismo rol.
- `Cargo.toml`: `testcontainers` subido a `0.27`, añadido
  `testcontainers-modules` (feature `postgres`), añadida la feature
  `chrono` a `sqlx`.
- Alcance: no se tocó `src/config.rs` (sigue con una sola `database_url`);
  `Repository` recibe el `PgPool` ya construido por el llamante. Queda
  anotado para la feature `service_wiring` (id 7): con qué rol se aplican
  las migraciones en producción, dado que el rol de aplicación no es dueño
  de las tablas y no podría migrar el esquema por sí mismo.
- `./init.sh` completo en verde, incluyendo `cargo test -- --ignored` (9/9)
  contra Docker real.
- Revisión: `reviewer` independiente lanzado por el líder verificó
  específicamente que no hay ruta de fuga (ownership, herencia, `PUBLIC` no
  revocado) por la que `ms_usuarios_app` pudiera mutar `audit_log`, y
  re-ejecutó los tests de integración contra Docker real. Veredicto
  `APPROVED` en `progress/review_4.md`.
