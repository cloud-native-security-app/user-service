# Review — feature 4 (postgres_persistence)

**Veredicto:** APPROVED

## Resumen de la verificación

- `./init.sh` completo termina en verde, incluida la sección de integración
  con Docker real (`docker ps` confirma daemon disponible; `cargo test --
  --ignored` corrió 9/9 tests contra un contenedor Postgres real vía
  `testcontainers-modules`, incluido el test crítico de rechazo de permisos
  `42501` sobre `audit_log`). `docker ps -a` tras la corrida no deja
  contenedores Postgres huérfanos (testcontainers los limpia al `drop`).
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo
  test`, `cargo test -- --ignored`, `cargo doc --no-deps`: todos en verde.

## Migraciones SQL

- `migrations/20260918120000_create_core_schema.sql`: tablas `users`,
  `scan_history` (FK a `users.user_id`), `audit_log` (FK a `users.user_id`)
  correctas. `status` como `TEXT` + `CHECK` coincide con el encoding
  `SCREAMING_SNAKE_CASE` de `ScanStatus`. Sin contraseñas ni credenciales
  hardcodeadas.
- `migrations/20260918120100_lock_audit_log_permissions.sql`: crea
  `ms_usuarios_app` en `NOLOGIN` (sin contraseña — activarla es
  responsabilidad de cada entorno fuera de `sqlx`, decisión correctamente
  documentada y diferida a `service_wiring`, id 7). Aplica `REVOKE ALL ...
  FROM PUBLIC` antes de conceder nada (cierra el camino de "GRANT a PUBLIC
  no revocado"). Para `audit_log` específicamente: `REVOKE ALL ON audit_log
  FROM ms_usuarios_app;` seguido de `GRANT SELECT, INSERT ON audit_log TO
  ms_usuarios_app;` — nunca se concede `UPDATE`/`DELETE`/`TRUNCATE`. El rol
  no es dueño de ninguna tabla (las crea el superusuario en la primera
  migración; la segunda no hace `ALTER TABLE ... OWNER TO`), así que el
  camino de fuga "dueño se salta el REVOKE" queda cerrado. El rol tampoco
  hereda membresía de ningún otro rol con privilegios más amplios. No
  encontré ningún camino por el que `ms_usuarios_app` pudiera mutar
  `audit_log` a pesar del `REVOKE`.

## `src/repository.rs`

- Los 6 métodos del acceptance existen con las firmas correctas:
  `upsert_user`, `find_user`, `insert_scan_history`, `update_scan_status`,
  `list_scan_history`, `append_audit_entry`.
- No existe ningún método `update`/`delete` público para `audit_log` — solo
  `append_audit_entry` (insert). Reforzado por rustdoc explícito en el
  propio código (líneas 153-167).
- `find_user`/`list_scan_history` devuelven `Ok(None)`/`Ok(vec![])` para un
  id inexistente, nunca error (confirmado también por los tests de
  integración `find_user_returns_none_when_user_does_not_exist` y
  `list_scan_history_returns_empty_vec_for_user_without_scans`).
- `update_scan_status` devuelve `RepoError::NotFound` cuando `rows_affected()
  == 0` (línea 122-124), en vez de un `Ok` silencioso o un error genérico.
- `RepoError` (`thiserror`) traduce fallos de conectividad a
  `ConnectionFailed` y errores de base de datos a `Constraint(sqlstate)` —
  el `From<sqlx::Error>` (líneas 298-312) nunca incluye el mensaje crudo de
  Postgres (que podría contener valores de columna, incluido email), solo
  el código `SQLSTATE`. Ningún `unwrap()`/`expect()`/`panic!()` fuera de
  `#[cfg(test)] mod tests` (verificado con grep; los dos `expect()` que
  aparecen fuera de comentarios rustdoc están dentro del módulo de test,
  líneas 330 y 355).
- Ningún mensaje de error, log o variante de `RepoError` incluye email o
  nombre del usuario — coincide con `docs/security-scope.md`.

## `tests/repository.rs`

- Cubre exactamente lo pedido: upsert+find (incluye actualización en
  conflicto), insert+list de histórico, transición de estado (+ 404 lógico
  vía `RepoError::NotFound` para `scan_id` inexistente), append+lectura de
  auditoría, y el test explícito de `UPDATE`/`DELETE` contra `audit_log`.
- El test de permisos (`update_and_delete_against_audit_log_fail_by_permissions_for_the_app_role`)
  usa realmente `db.app_pool` (el rol `ms_usuarios_app`, no el superusuario)
  para los intentos de `UPDATE`/`DELETE`, y verifica el código
  `SQLSTATE 42501` específico vía `assert_fails_with_permission_denied`
  (no solo "algo falló": distingue `Ok`, `Err(Database)` con otro código, y
  `Err(otra variante)` como fallos del propio test).
- Incluye el control positivo pedido: tras el intento fallido de
  `UPDATE`/`DELETE`, el mismo pool/rol hace un `SELECT` que confirma que la
  fila sigue intacta — descarta que el "rechazo" observado se deba a
  credenciales rotas u otro problema no relacionado con permisos.
- El diseño de dos pools (superusuario para migrar + activar login;
  `ms_usuarios_app` para ejercer el repositorio y el intento de mutación)
  respeta exactamente la decisión ya tomada por el líder en
  `progress/explore_audit_log_permissions.md`.

## Alcance respetado

- No se tocó `src/config.rs`, `src/domain.rs`, `src/api.rs`, `src/audit.rs`,
  `src/lib.rs` ni `src/main.rs` (confirmado por `git status`/`git diff
  --stat`: solo `Cargo.{toml,lock}`, `feature_list.json`,
  `migrations/README.md`, `progress/current.md`, `src/repository.rs` como
  modificados, más los archivos nuevos esperados).
- La nota abierta sobre con qué rol se aplican las migraciones en
  producción queda correctamente diferida a `service_wiring` (id 7), tanto
  en `progress/current.md` como en un comentario en la propia migración de
  permisos — no es un defecto de esta feature.

## Checkpoints

- C1: [x] — 4 archivos base + 4 docs existen, `./init.sh` exit 0.
- C2: [x] — Solo feature 4 en `in_progress`; features 1-3 `done` con tests
  que pasan; `progress/current.md` describe la sesión activa, sin basura de
  sesiones previas.
- C3: [x] — `src/` solo tiene los módulos previstos (`config`, `domain`,
  `repository`, `audit`, `api` + `lib`/`main`); las dependencias nuevas
  (`testcontainers` 0.27, `testcontainers-modules`, feature `chrono` de
  `sqlx`) están justificadas por el acceptance de esta feature; sin
  `println!`/`dbg!`/`unwrap()`/`panic!()` fuera de tests; `cargo doc
  --no-deps` sin warnings.
- C4: [x] — Hay test de integración real para `repository` contra Postgres
  vía `testcontainers` (el de `api` queda pendiente porque ese módulo aún
  no tiene lógica — features 5/6 sin empezar, no es un defecto de esta
  feature). Existe el test explícito de rechazo `UPDATE`/`DELETE` sobre
  `audit_log` por permisos, con el rol no-dueño real. `cargo test` muestra
  >0 tests, todos verdes (13 unitarios + 9 de integración + 1 stub).
  `cargo clippy --all-targets -- -D warnings` sin advertencias.
- C5: [x] — Sin archivos sospechosos sin trackear (`target/` cubierto por
  `.gitignore`); la entrada de `progress/history.md` para esta sesión y el
  cambio de estado a `done` en `feature_list.json` quedan, según el
  protocolo del propio repo, a cargo del líder tras esta aprobación — no
  bloquean el veredicto de esta revisión.

## Cambios requeridos

Ninguno.
