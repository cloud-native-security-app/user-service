# Review — feature 2 (config)

**Veredicto:** APPROVED

## Contexto revisado

- Docs leídos: `docs/architecture.md`, `docs/conventions.md`, `docs/security-scope.md`, `CHECKPOINTS.md`.
- Archivos tocados según `progress/current.md`: `Cargo.toml` (+`secrecy = "0.10.3"`, +`thiserror = "2.0"`), `src/config.rs`, `feature_list.json` (status `pending` -> `in_progress`, correcto), `progress/current.md`.
- Otros módulos (`src/domain.rs`, `src/repository.rs`, `src/audit.rs`, `src/api.rs`, `src/lib.rs`, `src/main.rs`) siguen siendo los stubs de la feature 1, sin tocar. Confirmado con `git diff --stat HEAD` (solo 5 archivos modificados) y lectura directa de esos módulos.

## Revisión línea por línea de `src/config.rs` contra el acceptance de la feature 2

1. **Carga desde variables de entorno** (`DATABASE_URL`, `HTTP_HOST`, `HTTP_PORT`, `GATEWAY_SHARED_SECRET`): `Config::from_env()` (líneas 72-90) usa `read_required` (línea 96-98) para las 4 variables. Correcto y consistente con `docs/architecture.md` capa `config`.
2. **Sin panics ante variable faltante**: `read_required` devuelve `Result` (`ConfigError::MissingVar`), nunca `unwrap()/expect()/panic!()`. Revisé todo `src/config.rs` fuera de `#[cfg(test)]`: no hay ningún `unwrap()`, `expect()` ni `panic!()` en el camino de carga (líneas 1-120). Los únicos `.expect()` están dentro de `mod tests` (líneas 177, 230), permitido por `docs/conventions.md`.
3. **Puerto inválido**: además de lo pedido explícitamente, `HTTP_PORT` no numérico produce `ConfigError::InvalidPort` tipado (líneas 78-82) en vez de un panic de parseo — mejora razonable, no contradice el acceptance.
4. **Credencial redactada (`SecretString`)**: `gateway_shared_secret: SecretString` (línea 43). Verifiqué que `secrecy::SecretString` implementa `Debug`/`Display` redactados internamente (crate `secrecy` los oculta con `[REDACTED]`/`Secret([REDACTED])`), y además `Config` implementa `Debug` manual (líneas 46-59) que delega el campo a `&self.gateway_shared_secret` en vez de exponerlo — no hay ningún campo derivado, `Display`, `Clone` con acceso al valor plano, ni un segundo campo `String` paralelo que filtre el secreto. `ConfigError` (líneas 106-120) solo lleva el **nombre** de la variable (`&'static str`), nunca su valor, así que un error de configuración no puede filtrar el secreto ni por accidente. Comprobación empírica: el test `debug_format_of_config_never_contains_the_raw_secret` (líneas 227-240) formatea `Config` con `{:?}` y afirma que el string crudo no aparece — pasa (ver ejecución de `./init.sh` abajo).
5. **Nada hardcodeado**: los 4 valores de configuración vienen exclusivamente de `std::env::var` vía `read_required`; no hay ningún valor de conexión, host, puerto o secreto embebido en el código (solo nombres de variables de entorno, que no son secretos).
6. **Tests requeridos**: los 4 tests unitarios en `mod tests` cubren exactamente lo pedido — carga válida (`from_env_loads_valid_config_successfully`), variable faltante -> error tipado (`from_env_returns_typed_error_when_required_var_is_missing`), y Debug no filtra el secreto (`debug_format_of_config_never_contains_the_raw_secret`), más un extra razonable para puerto inválido. Los tests usan un `Mutex` + `EnvGuard` con `Drop` para serializar y limpiar el entorno global entre tests — buena práctica, evita flakiness por orden de ejecución de `cargo test`.
7. **`unsafe` en los tests** (`std::env::set_var`/`remove_var`, líneas 147-151, 158-163, 191-193, 211-213): justificado con comentario explicando por qué es seguro (mutex serializa acceso), cumple la regla de `docs/conventions.md` de no usar código inseguro/riesgoso sin comentario explicando el porqué. Está en código de test, no en la lib pública.
8. **Rustdoc**: todo ítem público (`Config`, sus campos, `Config::from_env`, `ConfigError` y sus variantes, incluida la documentación de `# Errores`) tiene `///`, consistente con `#![deny(missing_docs)]` de `src/lib.rs` — confirmado porque `cargo doc --no-deps` no falla (ver abajo).
9. **Convenciones de nombres**: `snake_case` para funciones/constantes internas salvo las constantes `UPPER_SNAKE` (`DATABASE_URL_VAR`, etc.), `PascalCase` para `Config`/`ConfigError` — correcto.

No se filtra ningún dato personal (email/identidad de Google) ni token de sesión en este módulo — no aplica todavía (eso lo tocan las features `user_profile_api`/`scan_history_api`), y el log de auditoría no se toca en absoluto en este diff.

## Ejecución de `./init.sh`

Resultado: **verde**, exit code 0.
- `cargo fmt --check`: sin diferencias.
- `cargo clippy --all-targets -- -D warnings`: sin warnings.
- `cargo test`: 4 tests nuevos de `config::tests` + 1 test de `tests/scaffolding.rs` (heredado de la feature 1), todos `ok`.
- `cargo test -- --ignored`: 0 tests (aún no hay tests de integración con Docker, correcto para el alcance de esta feature).
- `cargo doc --no-deps`: genera sin errores.

## Checkpoints (`CHECKPOINTS.md`)

### C1 — El arnés está completo
- C1.1 (4 archivos base): [x]
- C1.2 (4 docs): [x]
- C1.3 (`./init.sh` exit 0): [x]

### C2 — El estado es coherente
- C2.1 (máx. 1 feature `in_progress`): [x] — solo la feature 2 está `in_progress`.
- C2.2 (toda feature `done` tiene tests que pasan): [x] — feature 1 (`scaffolding`) sigue teniendo `tests/scaffolding.rs` en verde.
- C2.3 (`progress/current.md` refleja la sesión activa, sin basura): [x]

### C3 — El código respeta la arquitectura
- C3.1 (`src/` solo módulos previstos): [x] — `config`, `domain`, `repository`, `audit`, `api` (más `main.rs`/`lib.rs`); `wiring` aún no existe, correcto porque es de la feature 7.
- C3.2 (deps justificadas): [x] — `secrecy` y `thiserror` justificadas explícitamente por el acceptance de la feature 2 (redacción de credencial, errores tipados).
- C3.3 (sin `println!`/`dbg!`/`unwrap`/`panic!` fuera de tests sin justificar, sin TODOs huérfanos): [x] — ver punto 2 arriba.
- C3.4 (`cargo doc --no-deps` sin warnings): [x]

### C4 — La verificación es real
- C4.1 (test de integración por módulo que cruza IO — `repository`, `api`): [ ] ← Razón: todavía no aplica; `repository` y `api` siguen siendo stubs sin IO (features 4 y 5, pendientes). No es una regresión de esta feature, solo un checkpoint que se completará más adelante.
- C4.2 (tests de `repository`/`api` contra Postgres real vía `testcontainers`): [ ] ← Razón: mismo motivo que C4.1, no aplica todavía.
- C4.3 (test que verifica que `audit_log` rechaza `UPDATE`/`DELETE`): [ ] ← Razón: pertenece a la feature 4 (`postgres_persistence`), no implementada todavía.
- C4.4 (`cargo test` muestra >0 tests y todos verdes): [x]
- C4.5 (`cargo clippy --all-targets -- -D warnings` sin advertencias): [x]

### C5 — La sesión se cerró bien
- C5.1 (sin archivos sin trackear sospechosos): [x] — `git status --porcelain` solo muestra modificaciones a archivos ya trackeados.
- C5.2 (`progress/history.md` tiene una entrada por la última sesión): [ ] ← Razón: `progress/history.md` todavía solo tiene la entrada de la feature 1; la entrada de la sesión de la feature 2 no se ha añadido. Esto es responsabilidad del `leader` al cerrar la sesión tras esta revisión, no un defecto del implementer, pero queda pendiente antes de considerar la sesión cerrada.
- C5.3 (última feature trabajada reflejada en su estado correcto): [x] — `feature_list.json` la tiene en `in_progress`, que es correcto hasta que el `leader` la marque `done` tras este veredicto.

## Cambios requeridos

Ninguno bloqueante para el código de la feature 2. Nota no bloqueante para el `leader`: al cerrar la sesión, añadir la entrada correspondiente en `progress/history.md` (C5.2) y actualizar `feature_list.json` a `done` una vez incorporado este veredicto.
