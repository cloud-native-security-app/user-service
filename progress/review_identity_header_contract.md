# Review — feature 9 (identity_header_contract)

**Veredicto:** APPROVED

## Metodología

- Leídos `docs/architecture.md`, `docs/conventions.md`, `docs/security-scope.md`,
  `CHECKPOINTS.md`, `feature_list.json` (id 9, texto exacto de `acceptance`),
  `progress/impl_identity_header_contract.md`.
- Leído (solo lectura) `gateway/src/usuarios_client.rs` para confirmar el shape
  real de `IdentityHeaderPayload`.
- Revisado `git diff HEAD` de `src/api.rs`, `tests/api.rs`,
  `tests/service_wiring.rs`, `feature_list.json`, `progress/current.md`.
- Ejecutado `./init.sh` 3 veces consecutivas (con Docker real disponible).
- Ejecutado explícitamente `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`.
- Para el baseline de conteo de tests: `git stash` de los cambios de la
  feature 9, `cargo test` / `cargo test -- --ignored` sobre `HEAD` (feature 8
  `containerization`, `done`), luego `git stash pop` para restaurar los
  cambios del implementer intactos.

## Criterios de aceptación (texto exacto de `feature_list.json` id 9), uno a uno

### 1. `CallerIdentity` con `sub`+`email`, shape exacto a `gateway::usuarios_client::IdentityHeaderPayload`

**Cumple.** `src/api.rs:118-125`:

```rust
#[derive(Clone, Deserialize)]
struct CallerIdentity {
    sub: String,
    email: String,
}
```

poblada en `parse_caller_identity` (`src/api.rs:167-174`) vía
`serde_json::from_str::<CallerIdentity>(raw)`. Confirmado contra
`gateway/src/usuarios_client.rs:214-218`:

```rust
struct IdentityHeaderPayload<'a> { sub: &'a str, email: &'a str }
```

serializado con `serde_json::to_string` (mismo módulo, `identity_header_value`,
línea 466-472) — mismos dos campos, mismos nombres, mismo tipo de contenido
(`String`/`&str`). Shape idéntico confirmado por lectura directa del repo
hermano, no por suposición del implementer.

### 2. Header ausente/vacío/no-JSON/JSON sin `sub` → `ApiError::MissingIdentity`, nunca panic; `sub` vacío también cuenta como ausente

**Cumple.** `parse_caller_identity` (`src/api.rs:167-174`):

```rust
fn parse_caller_identity(headers: &HeaderMap) -> Option<CallerIdentity> {
    let raw = read_header(headers, FORWARDED_USER_HEADER)?;
    let identity: CallerIdentity = serde_json::from_str(raw).ok()?;
    if identity.sub.is_empty() { return None; }
    Some(identity)
}
```

- Ausente: `read_header` devuelve `None` (early return `?`).
- Vacío (`""`): pasa `read_header`, pero `""` no es JSON válido →
  `serde_json::from_str` falla → `.ok()?` → `None`. Mismo camino de código
  que "no-JSON", correcto y suficiente (no hace falta una rama separada).
- No-JSON: mismo `.ok()?`.
- JSON sin `sub`: `CallerIdentity` no deriva `Default` y `sub`/`email` no son
  `Option`, así que `serde_json::from_str` falla por campo faltante →
  `.ok()?` → `None`.
- `sub` vacío pero JSON válido: capturado explícitamente por el `if
  identity.sub.is_empty()`.

`require_gateway_and_identity` (`src/api.rs:142-148`) traduce `None` a
`ApiError::MissingIdentity` (ya existente, sin cambio de tipo), que sigue
mapeando a `400 Bad Request` (`src/api.rs:410`). Cero `unwrap`/`expect`/
`panic!` en esta ruta (confirmado por grep dirigido sobre `src/*.rs` fuera de
bloques `#[cfg(test)]`: los únicos hits son menciones en comentarios rustdoc
del tipo "nunca hace `panic!`").

### 3. `user_id` persistido en `users`/`scan_history`/`audit_log` es el `sub` limpio — verificado con test de integración real end-to-end contra Postgres

**Cumple.** Todos los usos de la identidad para `user_id` pasan de
`identity.0` (string opaco = header completo) a `identity.sub`
(`src/api.rs`: `put_profile` línea 215, `get_profile` línea 246, `create_scan`
líneas 276/284, `patch_scan_status` línea 328, `list_scans` línea 351,
`list_audit` línea 366).

Verificación end-to-end real (no solo unitaria): `tests/service_wiring.rs::
full_flow_create_profile_scan_history_and_audit_over_real_http` (test
`#[ignore = "requiere Docker"]`, ya existente de la feature `service_wiring`,
actualizado en esta feature) levanta el servicio real sobre un Postgres real
vía `testcontainers`, construye el header `X-Forwarded-User` como JSON
(`identity_header(user_id, email)`, `sub = "wiring-e2e-user"`) y hace HTTP
real de punta a punta:

- `PUT /users/me` → `assert_eq!(profile["user_id"], user_id)` (línea 197) —
  el valor persistido y devuelto es el `sub` limpio, no el JSON.
- `POST /users/me/scans` → `assert_eq!(created_scan["user_id"], user_id)`
  (línea 218).
- `GET /users/me/audit` → `assert_eq!(audit[0]["user_id"], user_id)` (línea
  262).

Esto es una prueba real de regresión: con el código anterior (header tratado
como string opaco), el `sub` recibido por el servidor real habría sido el
JSON completo `{"sub":"wiring-e2e-user","email":"..."}"` y estas aserciones
habrían fallado. Complementado por aserciones equivalentes en
`tests/api.rs` (líneas 208, 225, 488, 532) sobre `users`/`scan_history`/
`audit_log` vía las tres rutas de esta feature. Ejecutado y confirmado en
verde (ver sección "Ejecución" abajo).

### 4. Caso del handler que tomaba el email del cuerpo — detectado, resuelto y documentado

**Cumple.** El implementer detectó que `put_profile`
(`UpsertProfileRequest { email, display_name }`) tomaba `email` del cuerpo de
`PUT /users/me`, inconsistente con la regla ya aplicada a `user_id` en
`docs/security-scope.md` ("nunca se confía en un `user_id` que venga solo en
el cuerpo/query... sin contrastarlo"). Decisión: mover `email` a la identidad
verificada del header (`identity.email`), documentada en tres lugares
independientes:

- `progress/impl_identity_header_contract.md` §"Decisión documentada", con
  la justificación de seguridad y el análisis de compatibilidad con
  `gateway` (revisado en solo lectura: `UsuariosClient::upsert_profile`
  envía el perfil completo como JSON opaco vía `serde_json::Value`; al no
  haber `deny_unknown_fields` en `UpsertProfileRequest`, un campo `email`
  extra en el cuerpo se ignora sin romper al gateway).
- Rustdoc de `UpsertProfileRequest` y `put_profile` (`src/api.rs:190-208`),
  que explicita el cambio de contrato observable.
- `progress/current.md`, en el plan y la bitácora de la sesión.

No está "colado": es un cambio de contrato explícito, justificado contra
`docs/security-scope.md`, y verificado contra el consumidor real
(`gateway`). Trade-off correctamente señalado por el implementer como
pendiente de confirmación del líder/reviewer — lo confirmo aceptable: es la
aplicación consistente del mismo principio de "la identidad verificada es el
único origen de verdad" que ya regía `user_id`.

### 5. Tests existentes actualizados al nuevo formato de header, sin cambio de comportamiento observable más allá del fix

**Cumple.** Revisado el `git diff` completo de `tests/api.rs` y
`tests/service_wiring.rs`:

- Los cambios son estructurales de construcción del header (nuevos helpers
  `identity_header`/`identity_header_default`/
  `request_to_with_identity_header`) y de quitar `email` del cuerpo de los
  `PUT` (consecuencia directa y documentada del punto 4) — ningún `assert_eq!`
  fue relajado, eliminado o su valor esperado cambiado de forma que oculte
  una regresión. Ejemplos verificados línea a línea:
  - `put_then_get_reflects_the_stored_profile`: mismos asserts sobre
    `user_id`/`email`/`display_name`, solo cambia de dónde viene el `email`
    esperado (header en vez de cuerpo, con el mismo valor
    `test-user-1@example.test`).
  - `put_updates_email_and_display_name_on_a_second_call`: se reescribió
    para variar el `email` vía el header en la segunda llamada en vez del
    cuerpo — la intención del test (el email se actualiza en un segundo
    upsert) se preserva exactamente, con un comentario explicando el porqué.
  - `a_user_cannot_read_another_users_profile_via_get`,
    `create_profile` (helper): solo se quita `email` del cuerpo del `PUT`
    (ya no es un campo válido), sin tocar ninguna aserción de autorización.
- `tests/service_wiring.rs`: mismo patrón — un helper `identity_header` nuevo,
  el resto de la lógica del test end-to-end (incluidas todas las
  aserciones sobre `user_id`, `target`, `status`, `scan_id`) intacta.

### 6. Tests nuevos cubren los 4 casos: JSON válido, no-JSON, JSON sin `sub`, `sub` vacío

**Cumple, con cobertura doble (unitaria + integración).**

Unitarios (`src/api.rs::tests`, sin Docker):
- `parse_caller_identity_returns_sub_and_email_for_valid_json` — JSON válido.
- `parse_caller_identity_returns_none_for_non_json_header` — no-JSON.
- `parse_caller_identity_returns_none_when_sub_is_missing` — JSON sin `sub`.
- `parse_caller_identity_returns_none_when_sub_is_empty` — `sub` vacío.
- (bonus) `parse_caller_identity_returns_none_when_header_is_absent`.

Integración (`tests/api.rs`, `#[ignore = "requiere Docker"]`, pipeline HTTP
real con middleware real):
- `non_json_identity_header_returns_400`.
- `identity_header_without_sub_returns_400` (cubre explícitamente tanto JSON
  sin `sub` como `sub` vacío, dos sub-casos dentro del mismo test).

Los 4 casos exigidos están cubiertos, con redundancia deliberada entre el
nivel unitario (función pura) y el nivel HTTP end-to-end.

### 7. `./init.sh` 2-3 veces → exit 0 estable; recuentos exactos vs. baseline; sin regresión en `user_profile_api`/`scan_history_api`/`service_wiring`

**Cumple.** Ejecuté `./init.sh` **3 veces consecutivas**: exit code `0` las
3 veces (incluye `fmt --check`, `clippy -D warnings`, `cargo test`, `cargo
test -- --ignored` con Docker real, `cargo doc --no-deps`).

**Recuento exacto, baseline vs. feature 9** (baseline = `HEAD`, feature 8
`containerization` `done`, obtenido con `git stash` + `cargo test` +
`cargo test -- --ignored` + `git stash pop`, sin tocar el working tree del
implementer):

| | Baseline (HEAD, antes de f.9) | Feature 9 (actual) | Delta |
|---|---|---|---|
| `cargo test` (unitarios, sin Docker) — lib | 21 | 26 | +5 |
| `cargo test` (unitarios) — `tests/scaffolding.rs` | 1 | 1 | 0 |
| **Total unitarios** | **22** | **27** | **+5** |
| `cargo test -- --ignored` — `tests/api.rs` | 13 | 15 | +2 |
| `cargo test -- --ignored` — `tests/repository.rs` | 13 | 13 | **0** |
| `cargo test -- --ignored` — `tests/service_wiring.rs` | 2 | 2 | **0** |
| **Total integración (`--ignored`)** | **28** | **30** | **+2** |

El `+5` unitario coincide exactamente con los 5 tests nuevos de
`parse_caller_identity` (criterio 6). El `+2` de integración coincide
exactamente con los 2 tests HTTP nuevos de `tests/api.rs` (criterio 6).
`tests/repository.rs` (13) y `tests/service_wiring.rs` (2) quedan
**exactamente iguales** al baseline — confirma **sin regresión** en
`scan_history_api`/`postgres_persistence`/`service_wiring`: el conteo de 2
tests de `service_wiring` que cerró esa feature no cambió, solo se les
actualizó la construcción del header (criterio 5). El informe del
implementer ("26 unitarios + 1 de scaffolding" = 27; "15 + 13 + 2" = 30 en
`--ignored`) es exacto.

Gates adicionales verificados por mí directamente (no solo el reporte del
implementer):
- `cargo clippy --all-targets -- -D warnings` → limpio, 0 warnings.
- `cargo fmt --check` → sin diferencias.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` → sin errores/warnings.
- `grep` dirigido de `unwrap()`/`expect(`/`panic!` en `src/*.rs` fuera de
  `#[cfg(test)]`: cero ocurrencias reales (solo menciones en prosa rustdoc
  del tipo "nunca hace `panic!`").
- `git diff --stat HEAD`: solo `feature_list.json`, `progress/current.md`,
  `src/api.rs`, `tests/api.rs`, `tests/service_wiring.rs` (+ el informe
  nuevo en `progress/`). **`Cargo.toml`/`Cargo.lock` sin cambios** (no se
  agregó ninguna dependencia nueva, consistente con que esta feature es un
  fix de parseo, no una feature con superficie nueva).
- **Sin scope creep**: `grep -rn "network_credentials\|scan-targets\|scan_target" src/ tests/ migrations/` → sin resultados. La feature `network_credentials_api` (id 10) sigue `pending` y no fue tocada.

## Checkpoints (`CHECKPOINTS.md`)

- C1: [x] — 4 archivos base y 4 docs presentes; `./init.sh` exit 0 (x3).
- C2: [x] — 1 sola feature `in_progress` (la 9, correcto mientras espera
  revisión); features `done` mantienen sus tests en verde;
  `progress/current.md` describe la sesión activa sin basura de sesiones
  previas.
- C3: [x] — `src/` solo tiene los módulos previstos (`config`, `domain`,
  `repository`, `audit`, `api`, `wiring`, `lib`, `main`); `Cargo.toml` sin
  cambios (nada que justificar de nuevo); sin `println!`/`dbg!`/`unwrap`/
  `panic!` sueltos; `cargo doc --no-deps` sin warnings.
- C4: [x] — tests de integración cubren `repository`/`api` contra Postgres
  real vía `testcontainers`; el test de rechazo de `UPDATE`/`DELETE` sobre
  `audit_log` sigue presente y en verde
  (`update_and_delete_against_audit_log_fail_by_permissions_for_the_app_role`,
  sin cambios de esta feature); `cargo test` > 0 tests, todo verde; clippy
  limpio.
- C5: [x] — sin archivos sueltos sospechosos (`git status --short` solo
  muestra los 5 archivos modificados esperados + el informe nuevo en
  `progress/`); `progress/history.md` no tiene aún entrada de esta sesión
  porque la feature sigue `in_progress` a la espera de este veredicto — es
  el paso correcto siguiente para el líder tras `APPROVED` (marcar `done` en
  `feature_list.json` y mover el resumen de `progress/current.md` a
  `progress/history.md`), no una falla de esta revisión.

## Nitpick (no bloquea)

- `src/api.rs:310-311`, comentario rustdoc de `patch_scan_status`: sigue
  diciendo `el scan_id de la URL debe pertenecer a identity.0`, referencia
  al viejo tipo tupla `CallerIdentity(String)` que ya no existe (el campo
  ahora es `identity.sub`, ver línea 328). No es un enlace intra-doc roto
  (no genera warning en `cargo doc`) y no afecta comportamiento ni
  seguridad, pero es texto desactualizado — vale la pena corregirlo (a
  `identity.sub`) en la próxima sesión que toque este archivo.

## Conclusión

Los 7 criterios de aceptación de `feature_list.json` id 9 se cumplen con
evidencia verificada de forma independiente (no solo aceptando el reporte
del implementer): shape de `CallerIdentity` confirmado byte a byte contra
`gateway/src/usuarios_client.rs`, los 4 casos de fallo cubiertos con tests
unitarios + de integración, `user_id` persistido verificado end-to-end
contra Postgres real, cambio de contrato de `PUT /users/me` documentado y
justificado, tests existentes actualizados sin debilitar ningún assert,
`./init.sh` estable en verde x3 con recuento de tests que cuadra
exactamente con el delta esperado (+5 unitarios, +2 integración, 0
regresión), y clippy/fmt/doc limpios sin re-ejecutarlos yo misma no habría
sido suficiente confirmación. Sin scope creep hacia `network_credentials_api`.

**APPROVED.** El líder puede marcar `feature_list.json` id 9 como `done` y
mover el resumen de `progress/current.md` a `progress/history.md`. El único
punto pendiente es el nitpick cosmético de rustdoc arriba, que no bloquea el
cierre de esta feature.
