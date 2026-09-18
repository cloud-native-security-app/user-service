# Review — feature 7 (service_wiring)

**Veredicto:** APPROVED

## Verificación ejecutada

- `./init.sh` completo: `cargo fmt --check` OK, `cargo clippy --all-targets -- -D warnings` OK
  (0 warnings, incluye `tests/service_wiring.rs`), `cargo test` (21 unit tests) OK,
  `cargo test -- --ignored` con Docker real confirmado (`docker ps` disponible) OK:
  13 tests de `tests/api.rs`, 13 de `tests/repository.rs` (sin regresión de las
  features 4/5/6) y 2 nuevos de `tests/service_wiring.rs`
  (`health_responds_200_without_any_authentication_header`,
  `full_flow_create_profile_scan_history_and_audit_over_real_http`), todos verdes.
  `cargo doc --no-deps` genera sin errores.
- `git status`: sin archivos sospechosos sin trackear.

## Revisión línea a línea de `src/wiring.rs`

- `build_router` (líneas 51-68): `migrate(&config.migrations_database_url)` se llama
  primero y de forma aislada (líneas 74-85) — abre su propio `PgPoolOptions` pool, corre
  `sqlx::migrate!("./migrations")` y lo **cierra** (`migrations_pool.close().await`,
  línea 82) antes de que la función retorne. El pool de tráfico se construye por
  separado con `config.database_url` (líneas 54-57) y es el único que se le pasa a
  `Repository::new` / `api::router`. No hay mezcla entre ambos roles: el pool que migra
  nunca sirve tráfico HTTP, y el pool de aplicación nunca ejecuta `sqlx::migrate!`. Esto
  es exactamente la separación de roles pedida (rol dueño de tablas vs. `ms_usuarios_app`
  restringido) y queda documentada en el doc-comment del módulo (líneas 6-23),
  consistente con `migrations/20260918120100_lock_audit_log_permissions.sql`.
- `GET /health` (líneas 63-65, 87-96): se monta en un `Router` separado
  (`health_router`) que nunca pasa por `.route_layer(middleware::from_fn_with_state(...,
  require_gateway_and_identity))` — ese middleware solo se aplica dentro de
  `api::router` (`src/api.rs:101-104`) a las rutas registradas *antes* de esa llamada
  en ese mismo `Router`; el `.merge()` posterior (línea 67) no retroactivamente aplica
  el layer a las rutas de `health_router`. Confirmado empíricamente por el test
  `health_responds_200_without_any_authentication_header` en
  `tests/service_wiring.rs:151-164`, que hace un `GET /health` real sin ningún header
  y obtiene `200`. El chequeo es real: `health()` ejecuta `SELECT 1` contra el pool de
  aplicación (línea 92) y devuelve `503` si falla (test unitario
  `health_returns_503_when_postgres_is_unreachable`, líneas 131-141, usando
  `connect_lazy` contra un puerto sin listener) — no es un simple "el proceso está vivo".
- **Fuga de credenciales**: revisado con cuidado. `WiringError` (líneas 103-114) tiene
  3 variantes, todas unitarias con mensaje `#[error(...)]` estático, sin interpolar
  `{0}` de ningún error interno de `sqlx`. Los tres `map_err` (líneas 57, 78, 84)
  descartan explícitamente el error original de `sqlx` (`|_| WiringError::...`) — que
  es justo donde viviría una connection string con usuario/contraseña si `sqlx`
  la incluyera en su `Display`. El doc-comment de `WiringError` (líneas 100-102) deja
  explícito el motivo. `main.rs:12` solo loggea `%error` sobre `RunError`, cuya cadena
  `Display` (`src/lib.rs:55-66`) para la variante `Wiring` delega en el `Display` de
  `WiringError`, que a su vez son los mensajes estáticos ya descritos — ninguna
  variable de entorno ni URL de conexión aparece en ningún log o mensaje de error de
  esta feature. No se detecta ningún vector de fuga de credenciales nuevo.

## `src/lib.rs` / `run()`

- Orden estricto: `Config::from_env()` → `wiring::build_router` (que internamente migra
  y luego conecta el pool de tráfico) → `TcpListener::bind` → `axum::serve`. Si
  cualquiera de los dos primeros pasos falla, la función retorna `Err` antes de llegar
  al `bind`, por lo tanto el proceso nunca llega a escuchar tráfico a medio inicializar
  — cumple el criterio de aceptación de la feature 7 ("el proceso no arranca a medias").
- Sin `unwrap()`/`panic!()` fuera de `#[cfg(test)]` en `src/lib.rs`, `src/wiring.rs`,
  `src/config.rs`, `src/main.rs` (verificado con grep dirigido; los únicos `unwrap`/
  `expect` en `src/` están dentro de módulos de test o son casos ya aceptados de
  features previas dentro de `#[cfg(test)]`).

## `tests/service_wiring.rs`

- Usa `TcpListener::bind("127.0.0.1:0")` real (línea 118) y `axum::serve` en una tarea
  de fondo (`tokio::spawn`, líneas 125-129) — no `tower::ServiceExt::oneshot`. El
  cliente es `reqwest::Client` real contra `http://{addr}`.
- El flujo completo (`full_flow_create_profile_scan_history_and_audit_over_real_http`)
  corre contra un Postgres real levantado con `testcontainers_modules::postgres`,
  aplica las migraciones con el rol superusuario y activa el login efímero del rol
  `ms_usuarios_app` (mismo patrón que `tests/api.rs`), y ejercita PUT perfil → POST scan
  → GET scans → GET audit vía HTTP real, verificando contenido del cuerpo JSON en cada
  paso (no solo el status code).
- El test de `/health` confirma explícitamente 200 sin ningún header de autenticación
  (`GATEWAY_SECRET_HEADER`/`FORWARDED_USER_HEADER` no se envían).

## Cambio en `tests/scaffolding.rs`

Razonable. El test original (`run_completes_without_error_in_scaffolding_stub`)
verificaba `run().await.is_ok()` porque `run()` era literalmente un stub sin efectos de
la feature 1; con `run()` orquestando de verdad, ese `assert` ya no puede sostenerse sin
un entorno completo (Postgres real + env vars), lo que habría convertido este test
liviano en uno que requiere Docker (violando el propósito original del archivo, que es
un test rápido sin `#[ignore]`). El reemplazo conserva la garantía original ("no
panic") y además la hace más específica (falla con el error tipado correcto,
`RunError::Config`, no cualquier otro), y sigue confirmando en tiempo de compilación
que `wiring` y `RunError` son `pub`. No diluye cobertura: la cobertura del flujo feliz
real de `run()` está cubierta por `tests/service_wiring.rs` (`#[ignore = "requiere
Docker"]`), que es el lugar correcto para un test que necesita Postgres real. Este es
scope legítimo de la feature 7, tal como la documentó el implementer.

## Checkpoints

- C1: [x] — 4 archivos base + 4 docs existen; `./init.sh` termina en 0.
- C2: [x] — 1 sola feature `in_progress` (la 7, en revisión); las `done` tienen tests
  verdes; `progress/current.md` describe la sesión activa sin basura de sesiones previas.
- C3: [x] — `src/` solo tiene los módulos previstos (`config`, `domain`, `repository`,
  `audit`, `api`, `wiring`); `reqwest` en `Cargo.toml` está bajo `[dev-dependencies]` y
  justificado por el test e2e de esta feature; sin `println!`/`dbg!`; sin
  `unwrap()`/`panic!()` fuera de test; `cargo doc --no-deps` sin warnings.
- C4: [x] — test de integración end-to-end nuevo para `wiring` sobre Postgres real vía
  `testcontainers`; test de `UPDATE`/`DELETE` contra `audit_log` (heredado de la feature
  4) sigue verde, sin regresión; `cargo test` > 0 y verde; `cargo clippy --all-targets
  -- -D warnings` sin advertencias.
- C5: [x] — sin archivos sueltos sospechosos; `progress/current.md` refleja
  correctamente el estado de la feature 7 y no se marcó `done` prematuramente en
  `feature_list.json` (queda en `in_progress`, a la espera de este veredicto).

## Cambios requeridos

Ninguno.
