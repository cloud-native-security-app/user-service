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

## Sesión — feature 5 (user_profile_api) — 2026-09-18

**Estado final:** `done` (aprobada, ver `progress/review_5.md`).

- `src/api.rs`: `pub fn router(repository: Repository, gateway_shared_secret: SecretString) -> axum::Router`
  con `PUT /users/me` (upsert del perfil del llamante) y `GET /users/me`
  (perfil del llamante), reutilizando `Repository::upsert_user`/`find_user`
  de la feature 4 sin modificarlos.
- Middleware `require_gateway_and_identity`: exige el header `X-Gateway-Secret`
  (comparado en tiempo constante vía `subtle` contra `Config.gateway_shared_secret`)
  y el header `X-Forwarded-User` — ambos ANTES de tocar la base de datos.
  Ausencia/valor incorrecto de la credencial -> `401`; ausencia del header
  de identidad -> `400`/`401`. El `user_id` sale únicamente de ese header,
  nunca del cuerpo/query.
- `ApiError`/`ApiErrorBody` nunca serializan email, `display_name` ni
  detalle interno de `RepoError` hacia el cliente HTTP — un fallo de
  `RepoError` colapsa a un error genérico.
- `tests/api.rs`: 7 tests de integración `#[ignore = "requiere Docker"]`
  contra Postgres real (mismo patrón de `tests/repository.rs`), ejerciendo
  el router real vía `tower::ServiceExt::oneshot`: PUT crea el perfil, GET
  posterior lo refleja, falta credencial de servicio -> 401 antes de tocar
  la DB, falta header de identidad -> 400/401, entre otros.
- `Cargo.toml`: añadidas `subtle` (dependencia) y `tower`/`http`
  (dev-dependencias).
- Alcance: no se tocó `src/repository.rs`, `src/domain.rs`, `src/config.rs`
  ni `src/audit.rs`; no se implementó nada de `scan_history_api` (id 6) ni
  `service_wiring` (id 7) — `router(...)` queda listo para que la feature 7
  lo ensamble con un `Config`/pool reales.
- `./init.sh` completo en verde, incluyendo `cargo test -- --ignored`
  (7/7 de `tests/api.rs` + 9/9 de `tests/repository.rs`, sin regresión)
  contra Docker real.
- Revisión: `reviewer` independiente lanzado por el líder confirmó el orden
  real de validación (credencial antes que identidad, ambas antes que la
  DB) y la ausencia de fuga de datos personales en errores/logs. Veredicto
  `APPROVED` en `progress/review_5.md`.

## Sesión — feature 6 (scan_history_api) — 2026-09-18

**Estado final:** `done` (aprobada tras una ronda de correcciones, ver
`progress/review_6.md`).

- `src/repository.rs`: nuevos métodos `record_scan_request(entry,
  audit_entry)` (transacción atómica real vía `pool.begin()`/`tx.commit()`:
  inserta `scan_history` + `audit_log` en la misma transacción; si el
  `INSERT` de auditoría falla, el histórico queda revertido — verificado con
  un test que provoca una violación real de FK y confirma que la fila de
  `scan_history` no persiste), `list_audit_entries(user_id)`, y
  `find_scan_owner(scan_id)` (añadido en la ronda de corrección, ver abajo).
- `src/api.rs`: 4 rutas nuevas bajo el mismo middleware
  `require_gateway_and_identity` de la feature 5 — `POST /users/me/scans`
  (`scan_id`/`id` de auditoría generados por el servicio vía `Uuid::new_v4()`,
  nunca por el cliente), `PATCH /scans/{scan_id}` (actualiza estado, `404`
  si no existe), `GET /users/me/scans` y `GET /users/me/audit` (filtran
  estrictamente por el `user_id` del header, probado con dos identidades
  distintas).
- `Cargo.toml`: añadida dependencia `uuid` (feature `v4`).
- **Ronda de corrección:** la primera revisión (`CHANGES_REQUESTED`) detectó
  que `PATCH /scans/{scan_id}` exigía el header de identidad pero lo
  descartaba sin usarlo para autorizar — con la credencial de servicio
  válida y cualquier identidad no vacía se podía mutar el estado de un
  escaneo de **otro** usuario, violando la autorización a nivel de fila de
  `docs/security-scope.md`. El líder escaló la decisión de diseño al
  usuario (verificar ownership con `403` vs. tratar la ruta como
  service-to-service sin identidad de usuario); el usuario eligió verificar
  ownership. Se añadió `find_scan_owner` y la comparación contra la
  identidad del header (`403` si no coincide, `404` si el `scan_id` no
  existe, `200`/`204` si coincide), con un test de dos identidades que
  confirma el rechazo y que el estado no cambió tras el intento.
- `./init.sh` completo en verde, incluyendo `cargo test -- --ignored`
  contra Docker real, sin regresión en las features 4 y 5 ni en el resto de
  tests de la propia feature 6.
- Revisión: `reviewer` independiente — primera ronda `CHANGES_REQUESTED`
  (ownership de `PATCH`), segunda ronda `APPROVED` tras el fix, confirmando
  el `403`/`404`/`200` correctos y el test de dos identidades. Veredicto
  final en `progress/review_6.md`.

## Sesión — feature 7 (service_wiring) — 2026-09-18

**Estado final:** `done` (aprobada, ver `progress/review_7.md`).

- Decisión de arquitectura escalada al usuario y resuelta: `Config` (feature
  2) ganó un campo opcional `migrations_database_url`
  (`MIGRATIONS_DATABASE_URL`, con fallback a `database_url` si está
  ausente) para separar el rol que migra el esquema (dueño de las tablas,
  necesario para crear el rol `ms_usuarios_app` y aplicar el
  `REVOKE`/`GRANT` de `audit_log`) del rol que sirve tráfico HTTP real en
  producción (`ms_usuarios_app`, restringido) — sin esta separación, el
  `REVOKE` de la feature 4 solo habría tenido efecto en los tests, nunca en
  producción.
- `src/wiring.rs` (nuevo, composition root): `build_router(&Config)` aplica
  `sqlx::migrate!` con el pool de `migrations_database_url`, construye por
  separado el pool de `database_url` para `Repository`, y ensambla
  `api::router(...)` + `GET /health` (fuera del middleware de auth, con un
  `SELECT 1` real que responde `503` si Postgres no está disponible, nunca
  solo "proceso vivo"). `WiringError` (thiserror) nunca expone el error
  crudo de `sqlx` (que podría contener la connection string con
  usuario/contraseña) — mensajes estáticos, sin interpolación.
- `src/lib.rs`: `run()` deja de ser un stub — orquesta `Config::from_env()`
  → `wiring::build_router` → bind TCP → `axum::serve`; un fallo en
  cualquier paso (config inválida, Postgres inalcanzable, migración
  fallida, bind del puerto) impide que el proceso llegue a servir tráfico a
  medias.
- `tests/service_wiring.rs` (nuevo, `#[ignore = "requiere Docker"]`): test
  end-to-end real — bind real a `127.0.0.1:0`, `axum::serve` en background,
  ejercido vía `reqwest` con el flujo completo `PUT /users/me` → `POST
  /users/me/scans` → `GET /users/me/scans` → `GET /users/me/audit`, más un
  test de que `GET /health` responde `200` sin ningún header de
  autenticación.
- `tests/scaffolding.rs` (heredado de la feature 1): actualizado para
  reflejar que `run()` ya no es un stub sin efectos — ahora confirma que,
  sin configuración, `run()` devuelve `RunError::Config` en vez de
  panicar. El reviewer confirmó que este cambio es scope legítimo de esta
  feature.
- `Cargo.toml`: añadido `reqwest` (rustls-tls) como dev-dependency.
- `./init.sh` completo en verde, incluyendo `cargo test -- --ignored`
  contra Docker real, sin regresión en las features 4, 5 y 6.
- Revisión: `reviewer` independiente confirmó específicamente la ausencia
  de fuga de credenciales de base de datos en `WiringError`/logs, la
  separación real de los dos pools, y que el health check hace una
  comprobación real de conectividad. Veredicto `APPROVED` en
  `progress/review_7.md`.
