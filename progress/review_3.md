# Review — feature 3 (domain_model)

**Veredicto:** APPROVED

## Verificación de acceptance (feature_list.json, id=3)

- `UserProfile { user_id, email, display_name, created_at }` — `src/domain.rs:23-32`. Coincide exactamente con el acceptance.
- `ScanHistoryEntry { scan_id, user_id, target, status: ScanStatus, requested_at, updated_at }` — `src/domain.rs:59-72`. `ScanStatus` — `src/domain.rs:46-55` — enum cerrado con exactamente 4 variantes (`Pendiente`, `EnProgreso`, `Completado`, `Fallido`), sin variante `Other`/`Unknown` ni `#[serde(other)]`, por lo que un string desconocido falla la deserialización en vez de caer en un default. Confirmado con el test `scan_status_rejects_unknown_string_instead_of_defaulting` (`src/domain.rs:244-251`), que pasa.
- `AuditEntry { id, user_id, target, action, recorded_at }` — `src/domain.rs:84-90`. Campos **privados**; revisé exhaustivamente el `impl AuditEntry` (`src/domain.rs:92-138`) y no hay ningún `&mut self`, ningún setter, ni ningún campo `pub` expuesto directamente — solo `AuditEntry::new` (constructor) y getters de solo lectura (`id`, `user_id`, `target`, `action`, `recorded_at`, todos con `&self`). Cumple "append-only por diseño" a nivel de tipo.
- Los tres tipos derivan `Serialize, Deserialize` (`src/domain.rs:22`, `:44`, `:58`, `:83`).
- Tests: round-trip de serialización JSON para `UserProfile`, `ScanHistoryEntry` y `AuditEntry` (líneas 151-201); encoding estable de `ScanStatus` en `SCREAMING_SNAKE_CASE` (líneas 204-241) verificado en ambas direcciones (serialize y deserialize) más el test de rechazo de variante desconocida. Todo pasa (`cargo test`: 10/10 verde, incluidos los 5 nuevos de `domain::tests`).

## Cumplimiento de `docs/architecture.md` y `docs/conventions.md`

- `domain.rs` sigue siendo un módulo puro sin IO, tal como exige la capa 2 de `docs/architecture.md`.
- Rustdoc en todo ítem público (`UserProfile`, `ScanStatus` y sus variantes, `ScanHistoryEntry`, `AuditEntry`, `AuditEntry::new` y cada getter) — `cargo doc --no-deps` (ejecutado vía `init.sh`) genera sin warnings, cumpliendo `#![deny(missing_docs)]` de `src/lib.rs`.
- Nombres en `PascalCase`/`snake_case` correctos, imports agrupados (`std`→externos→`crate::`, aunque aquí no hay `crate::` imports) conforme a `docs/conventions.md`.
- Ningún `unwrap()`/`expect()`/`panic!()` fuera de `#[cfg(test)] mod tests` (verificado con grep línea por línea: todas las ocurrencias están dentro del bloque de tests, líneas 147+).
- Dependencia nueva `chrono` (con feature `serde`) en `Cargo.toml` está justificada por la necesidad de `DateTime<Utc>` en los tres tipos de dominio, documentada en `progress/current.md`.
- No se tocó lógica de otras features: `config.rs`, `api.rs`, `audit.rs`, `repository.rs`, `lib.rs`, `main.rs` permanecen exactamente como en la feature 2 (diff limitado a `src/domain.rs`, `Cargo.toml`, `Cargo.lock`, `feature_list.json`, `progress/current.md`).

## Datos personales / seguridad (`docs/security-scope.md`)

- No hay ningún `tracing::*!`, `println!`, mensaje de error ni panic en `domain.rs` que incluya `email`/`display_name`/`user_id` — el módulo no hace logging en absoluto (es dominio puro sin IO).
- Los tests usan identidades sintéticas (`test-user-1@example.test`, `google-oauth2|123456`), conforme a la regla de no usar identidades reales de Google.
- Nota no bloqueante para features futuras: `UserProfile`/`ScanHistoryEntry`/`AuditEntry` derivan `Debug` (necesario para uso normal en Rust, p. ej. en asserts de test). El comentario del módulo (líneas 5-9) dice correctamente que ningún tipo deriva `Display`, pero un futuro `tracing::debug!(?profile, ...)` en la capa `api`/`repository` sí imprimiría el email vía el `Debug` derivado. No es una violación de esta feature (aquí no se loggea nada), pero recomiendo que cuando se implemente `api`/`repository` (features 4-6) se evite `?profile`/`{:?}` sobre estos tipos en cualquier log, igual que `config.rs` hizo explícitamente para `gateway_shared_secret` con `SecretString`.

## `./init.sh`

Ejecutado de punta a punta: `cargo fmt --check` limpio, `cargo clippy --all-targets -- -D warnings` sin advertencias, `cargo test` → 10 tests unitarios verdes (5 de `config`, 5 de `domain`) + 1 test de integración del stub de scaffolding, `cargo test -- --ignored` sin tests (ninguno aplica todavía), `cargo doc --no-deps` sin errores. **Exit code 0.**

## Checkpoints (CHECKPOINTS.md)

### C1 — El arnés está completo
- C1.1 (4 archivos base): [x]
- C1.2 (4 docs): [x]
- C1.3 (`./init.sh` exit 0): [x]

### C2 — El estado es coherente
- C2.1 (a lo sumo una feature `in_progress`): [x] — solo la 3.
- C2.2 (toda feature `done` tiene tests que pasan): [x] — features 1 y 2 (`scaffolding`, `config`) siguen con sus tests verdes.
- C2.3 (`progress/current.md` describe la sesión activa, sin basura): [x].

### C3 — El código respeta la arquitectura
- C3.1 (`src/` solo módulos previstos): [x] — `config`, `domain`, `repository`, `audit`, `api` (todavía sin `wiring`, correcto para esta etapa).
- C3.2 (dependencias justificadas): [x] — `chrono` justificada por `domain_model`.
- C3.3 (sin `println!`/`dbg!`/`unwrap()`/`panic!()` fuera de test, sin TODOs sueltos): [x].
- C3.4 (`cargo doc --no-deps` sin warnings): [x].

### C4 — La verificación es real
- C4.1 (test de integración por módulo que cruza IO — `repository`, `api`): [ ] ← Razón: `repository.rs` y `api.rs` siguen siendo stubs (features 4/5/6 aún `pending`); no aplica todavía a esta feature, pero el checkpoint global sigue abierto hasta que esas features se implementen.
- C4.2 (tests de integración contra Postgres real vía `testcontainers`): [ ] ← Razón: misma que C4.1, no hay todavía código de `repository`/`api` que testear con IO real.
- C4.3 (test que verifica rechazo de `UPDATE`/`DELETE` sobre `audit_log`): [ ] ← Razón: pertenece a `postgres_persistence` (feature 4, `pending`), aún no implementada.
- C4.4 (`cargo test` > 0 tests, todos verdes): [x] — 10 tests unitarios + 1 de integración del stub, todos verdes.
- C4.5 (`cargo clippy --all-targets -- -D warnings` sin advertencias): [x].

### C5 — La sesión se cerró bien
- C5.1 (sin archivos sospechosos sin trackear): [x] — `git status` limpio, sin `*.tmp` ni `target/` trackeado.
- C5.2 (`progress/history.md` tiene entrada de la última sesión): [ ] ← Razón: `progress/history.md` todavía no tiene entrada para la feature 3; corresponde añadirla al cerrar la sesión (tarea del `leader`, no bloquea la aprobación de esta feature).
- C5.3 (última feature trabajada refleja su estado correcto): [x] — `feature_list.json` mantiene la feature 3 en `in_progress`, correcto hasta que el `leader` la marque `done` tras esta revisión.

## Cambios requeridos

Ninguno. Los checkpoints C4.1-C4.3 y C5.2 quedan `[ ]` porque corresponden a trabajo de features posteriores (`postgres_persistence`, `user_profile_api`, `scan_history_api`) o al cierre de sesión del `leader`, no a un defecto de la feature 3 revisada aquí.
