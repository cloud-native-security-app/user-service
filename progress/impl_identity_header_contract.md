# Informe de implementación — feature 9: identity_header_contract

**Estado:** implementada y auto-verificada por el implementer. `feature_list.json`
queda en `in_progress` (no se marca `done`; corresponde al líder/reviewer).

## Resumen del cambio

`gateway/src/usuarios_client.rs` (repo hermano, solo lectura) serializa la
identidad verificada como JSON en el header `X-Forwarded-User`:

```rust
struct IdentityHeaderPayload<'a> { sub: &'a str, email: &'a str }
```

confirmado leyendo `IdentityHeaderPayload` y `identity_header_value`
(`serde_json::to_string(&IdentityHeaderPayload { sub: &identity.sub, email:
&identity.email })`) en ese archivo.

Este repo trataba el header completo como string opaco (`CallerIdentity(String)`)
y usaba ese string entero como `user_id`. Se corrigió: `CallerIdentity` ahora
deserializa el header como JSON `{"sub", "email"}` — mismo shape — y el
`sub` limpio es el único `user_id` persistido.

## Cambios en `src/api.rs`

- `CallerIdentity` pasa de `CallerIdentity(String)` a
  `struct CallerIdentity { sub: String, email: String }` con `#[derive(Clone,
  Deserialize)]`.
- Nueva función pura `parse_caller_identity(&HeaderMap) -> Option<CallerIdentity>`:
  lee el header, lo deserializa como JSON, y devuelve `None` si está ausente,
  no es UTF-8, no es JSON válido, no trae `sub`, o `sub` es la cadena vacía.
  Nunca hace `panic!`. Se extrajo como función pura (sin `State`/IO) para
  poder testearla sin Docker/Postgres.
- `require_gateway_and_identity` ahora llama a `parse_caller_identity` en vez
  de tratar el header como string; `None` -> `ApiError::MissingIdentity`
  (sin cambios en el tipo de error ni en el status code, `400`).
- Todos los usos de `identity.0` (`user_id`) en `put_profile`, `get_profile`,
  `create_scan`, `patch_scan_status`, `list_scans`, `list_audit` pasan a
  `identity.sub`. El `user_id` persistido en `users`/`scan_history`/
  `audit_log` es ahora el `sub` limpio, nunca el JSON completo.

## Decisión documentada: `PUT /users/me` y el email

**Sí, `put_profile` tomaba `email` del cuerpo de la petición**
(`UpsertProfileRequest { email, display_name }`). Se decidió moverlo a la
identidad verificada del header (`CallerIdentity.email`), por lo mismo que ya
documentaba `docs/security-scope.md` para `user_id`: la identidad verificada
por el Gateway es el único origen de verdad, nunca un campo que el llamante
puede pasar libremente en el cuerpo. Antes de este fix, un llamante con un
`sub` válido pero cualquier email en el cuerpo podía escribir un email
arbitrario en el perfil — inconsistente con la regla ya aplicada a
`user_id`.

**Esto cambia el contrato observable de `PUT /users/me`:**
`UpsertProfileRequest` ya no tiene el campo `email`; el cuerpo esperado pasa
a ser únicamente `{"display_name": "..."}`. Un cuerpo que incluya `email` no
falla (no hay `deny_unknown_fields`) pero ese valor se ignora
silenciosamente — el `email` persistido siempre es el del header.
Documentado en el rustdoc de `UpsertProfileRequest`/`put_profile` en
`src/api.rs`.

**Compatibilidad con gateway:** revisado (solo lectura) —
`UsuariosClient::upsert_profile` envía el `UserProfile` completo (incluye
`user_id`, `email`, `created_at`) como cuerpo de `PUT /users/me`. Como no hay
`deny_unknown_fields`, esos campos extra simplemente se ignoran; el gateway
sigue funcionando sin cambios, y el `email`/`user_id` efectivos pasan a ser
siempre los del header verificado (que es exactamente lo que gateway ya
reenvía). No fue necesario ni se tocó código de `gateway`.

## Tests

### Nuevos (unitarios, sin Docker, en `src/api.rs::tests`)

- `parse_caller_identity_returns_sub_and_email_for_valid_json`
- `parse_caller_identity_returns_none_when_header_is_absent`
- `parse_caller_identity_returns_none_for_non_json_header`
- `parse_caller_identity_returns_none_when_sub_is_missing`
- `parse_caller_identity_returns_none_when_sub_is_empty`

### Nuevos (integración HTTP real, `#[ignore = "requiere Docker"]`, en `tests/api.rs`)

- `non_json_identity_header_returns_400`
- `identity_header_without_sub_returns_400` (cubre tanto JSON sin `sub` como
  `sub` vacío, vía el pipeline completo del middleware)

### Actualizados a construir el header en JSON

- `tests/api.rs`: se añadieron los helpers `identity_header(sub, email)`,
  `identity_header_default(sub)` y `request_to_with_identity_header(...)`
  (nivel bajo, header ya serializado). `request_with_headers`/
  `request_to_with_headers` siguen aceptando el `sub` como antes y construyen
  el JSON internamente — la mayoría de los ~15 tests existentes no
  necesitaron tocar sus llamadas.
  - `put_then_get_reflects_the_stored_profile` y
    `a_user_cannot_read_another_users_profile_via_get`: se quitó `email` del
    cuerpo del `PUT` (ahora viene del header por defecto
    `{sub}@example.test`, coincide con las aserciones existentes sin
    cambiarlas).
  - `create_profile` (helper compartido por los tests de `scan_history_api`):
    igual, se quitó `email` del cuerpo.
  - `put_updates_email_and_display_name_on_a_second_call`: reescrito para
    variar el `email` entre dos llamadas **vía el header** (mismo `sub`,
    email distinto — simula que el Gateway reenvía un email verificado
    distinto), en vez de vía el cuerpo. La intención del test (que el email
    se actualiza en un segundo upsert) se preserva.
- `tests/service_wiring.rs`: se añadió el mismo helper `identity_header`; el
  test end-to-end construye el header JSON una vez y lo reutiliza en las 4
  llamadas; se quitó `email` del cuerpo del `PUT`.

Ningún test perdió cobertura ni cambió su intención — solo la mecánica de
cómo se construye el header/cuerpo cambió para reflejar el contrato real.

## Verificación

- `cargo build --all-targets`: limpio.
- `cargo clippy --all-targets -- -D warnings`: sin warnings.
- `cargo fmt --check`: sin diferencias (tras `cargo fmt`).
- `cargo doc --no-deps` (con `RUSTDOCFLAGS="-D warnings"`): sin errores,
  `#![deny(missing_docs)]` respetado — rustdoc añadido/actualizado en
  `CallerIdentity` (y sus campos `sub`/`email`), `parse_caller_identity`,
  `FORWARDED_USER_HEADER` (doc de módulo), `UpsertProfileRequest`,
  `put_profile`.
- `cargo test`: 26 unitarios + 1 test rápido de `scaffolding` en verde (0
  fallos), resto marcado `#[ignore]`.
- `cargo test -- --ignored` (Docker real vía testcontainers): 15 tests de
  `tests/api.rs` + 13 de `tests/repository.rs` (sin cambios de esta
  feature, no regresionaron) + 2 de `tests/service_wiring.rs`, todos en
  verde.
- `./init.sh`: **3 corridas consecutivas, las 3 en verde** (exit code 0),
  incluyendo fmt/clippy/test/test --ignored/doc.
- Sin `unwrap`/`expect`/`panic!` nuevo fuera de tests. `parse_caller_identity`
  y `require_gateway_and_identity` propagan `None`/`ApiError::MissingIdentity`
  en cada caso de fallo, nunca panican.
- No se tocó `gateway/` (solo lectura, confirmado el contrato de
  `usuarios_client.rs`).
- No se tocó la feature `network_credentials_api` (id 10, sigue `pending`).

## Archivos modificados

- `src/api.rs`
- `tests/api.rs`
- `tests/service_wiring.rs`
- `feature_list.json` (status de la feature 9 -> `in_progress`)
- `progress/current.md`, `progress/impl_identity_header_contract.md` (este
  archivo)

## Pendiente para el líder/reviewer

- Revisar la decisión de mover `email` del cuerpo al header en
  `PUT /users/me` (cambio de contrato documentado arriba) y confirmar que es
  aceptable antes de marcar la feature `done`.
- Marcar `feature_list.json` id 9 como `done` tras revisión (protocolo:
  el implementer no se autoaprueba).
