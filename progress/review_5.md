# Review — feature 5 (user_profile_api)

**Veredicto:** APPROVED

## Checkpoints

### C1 — El arnés está completo
- C1.1 (AGENTS.md, init.sh, feature_list.json, progress/current.md existen): [x]
- C1.2 (4 docs existen): [x]
- C1.3 (`./init.sh` exit code 0): [x] — ejecutado completo, exit code 0, `[OK] Entorno listo.` (ver `/tmp/init_out.log` de la sesión de revisión).

### C2 — El estado es coherente
- C2.1 (como mucho 1 feature `in_progress`): [x] — solo feature 5, y correctamente sigue en `in_progress` (el implementer no se auto-cerró, respetando el protocolo del líder).
- C2.2 (toda feature `done` tiene tests que pasan): [x] — features 1-4 `done`, sus tests (incl. `tests/repository.rs`, 9/9) pasan sin regresión.
- C2.3 (`progress/current.md` coherente, no basura): [x] — describe la sesión activa de feature 5 con plan, bitácora y próximo paso claros.

### C3 — El código respeta la arquitectura
- C3.1 (`src/` solo contiene módulos previstos): [x] — `api.rs, audit.rs, config.rs, domain.rs, lib.rs, main.rs, repository.rs`. `src/repository.rs`, `src/domain.rs`, `src/config.rs` no aparecen en el diff (`git diff --stat` confirma solo `src/api.rs` modificado) — la feature 4 no fue tocada.
- C3.2 (dependencias en `Cargo.toml` justificadas): [x] — `subtle` (comparación en tiempo constante del secreto de servicio, acceptance de la feature 5), `tower`/`http` como dev-deps para ejercer el router real vía `oneshot` (`docs/verification.md` Nivel 3 exige HTTP real, no handlers sueltos).
- C3.3 (sin `println!`/`dbg!`/`unwrap()`/`panic!` fuera de tests sin justificar): [x] — único `unwrap()` está en `#[cfg(test)] mod tests` (línea 263, helper de construcción de `HeaderValue` en un test unitario, permitido por convención). El código de producción de `src/api.rs` usa `Option`/`Result` en todo el camino de headers; ver `read_header` documentado explícitamente como "nunca hace panic!".
- C3.4 (`cargo doc --no-deps` sin warnings): [x] — confirmado en la ejecución de `./init.sh`.

### C4 — La verificación es real
- C4.1 (test de integración por módulo IO): [x] — `tests/api.rs` (7 tests) además de `tests/repository.rs` (9 tests, feature 4).
- C4.2 (contra Postgres real vía testcontainers, nunca producción): [x] — mismo patrón de doble pool (superusuario para migrar + `ms_usuarios_app` real) que `tests/repository.rs`.
- C4.3 (test de inmutabilidad de auditoría): [x] — preexistente de la feature 4 (`update_and_delete_against_audit_log_fail_by_permissions_for_the_app_role`), sigue pasando sin regresión; esta feature no toca `audit_log`.
- C4.4 (`cargo test` > 0 tests, todos verdes): [x] — 7/7 en `tests/api.rs` + 9/9 en `tests/repository.rs` + resto del suite, todo verde contra Docker real (confirmado con `docker ps` disponible antes de correr).
- C4.5 (`cargo clippy --all-targets -- -D warnings` sin advertencias): [x].

### C5 — La sesión se cerró bien
- C5.1 (sin archivos sospechosos sin trackear): [x] — único untracked es `tests/api.rs`, el archivo de test esperado de esta feature.
- C5.2 (`progress/history.md` tiene entrada de la última sesión): [ ] — Razón: la sesión de la feature 5 aún no tiene entrada en `progress/history.md`; esto es correcto en este punto del protocolo (`progress/current.md` indica explícitamente que el resumen se mueve a `history.md` *después* de que el reviewer apruebe y el líder marque `done`). No es un defecto de esta revisión, es el paso que sigue.
- C5.3 (última feature trabajada reflejada en su estado correcto): [x] — `in_progress` es el estado correcto mientras espera revisión; corresponde al líder pasarla a `done` tras este veredicto.

## Revisión de código — detalle

### `src/api.rs`

- **Orden credencial-antes-que-DB (correcto):** el middleware `require_gateway_and_identity` (líneas 98-120) se registra vía `.route_layer(...)` (línea 82-85) envolviendo *ambas* rutas de `/users/me`. Dentro del middleware, primero se valida `X-Gateway-Secret` (líneas 103-108, `secrets_match` en tiempo constante vía `subtle::ConstantTimeEq`, con corte temprano por longitud documentado como aceptable porque no hay nada sensible que comparar byte a byte en ese caso) y solo si es válido se evalúa `X-Forwarded-User` (líneas 110-119). Ningún handler (`put_profile`/`get_profile`) ni el middleware llaman a `state.repository` antes de que ambas validaciones pasen — el primer acceso a `Repository` ocurre dentro de los handlers, que `axum` solo invoca después de que `next.run(request)` se alcance en el `Ok` path del middleware. Confirmado también por el test de integración `missing_gateway_secret_returns_401_before_touching_the_database`.
- **Único origen de verdad del `user_id`:** `UpsertProfileRequest` (líneas 147-151) solo tiene `email`/`display_name`, ningún campo `user_id`/`id`. `put_profile` y `get_profile` toman el `user_id` exclusivamente de `Extension<CallerIdentity>` (inyectado por el middleware desde el header), nunca del body/query. No hay ningún parámetro de ruta `{id}` en `/users/me` que permita apuntar a otro usuario — confirmado también por el test `a_user_cannot_read_another_users_profile_via_get`.
- **400/401 explícitos, sin panic:** `read_header` (líneas 122-126) devuelve `Option`, nunca panic, documentado explícitamente. La rama de identidad ausente/vacía cae en `ApiError::MissingIdentity` → 400 (líneas 113-119, 233). Secreto ausente/incorrecto → `ApiError::Unauthorized` → 401 (líneas 103-108, 232). No hay `unwrap()`/`expect()`/`panic!()` en código de producción de este módulo.
- **No fuga de datos personales:** `ApiError` (líneas 204-218) y su `Display`/`ApiErrorBody` (líneas 241-253) son mensajes genéricos fijos, sin interpolar `user_id`, email ni nombre. `From<RepoError> for ApiError` (líneas 220-227) descarta explícitamente el detalle del error de `repository` y lo colapsa a `ApiError::Internal` — un fallo interno de DB nunca serializa un `RepoError` ni un `UserProfile` parcial hacia el cliente. La única vía por la que un `UserProfile` completo sale al cliente es la respuesta de éxito (200) de `PUT`/`GET /users/me`, que es exactamente el propio perfil del llamante autenticado — comportamiento esperado, no una fuga.
- **Row-level authorization:** no hay rutas `/users/{id}` en este router; el único identificador de perfil es el header de identidad ya verificado. Correcto por diseño según lo señalado en `feature_list.json` (acceptance de la feature 5) y `docs/security-scope.md`.
- **Rustdoc:** cada ítem público documentado, incluye explícitamente el contrato de seguridad (headers exigidos, orden, no confiar en `user_id` del body) en el doc-comment del módulo (líneas 1-29) y de cada función pública/const relevante.

### `tests/api.rs`

- Ejercita el router real por HTTP vía `tower::ServiceExt::oneshot` (línea 27, uso en cada test), no llama a los handlers como funciones sueltas — cumple `docs/verification.md` Nivel 3.
- Los 7 tests cubren exactamente el acceptance de la feature 5: PUT crea perfil + GET lo refleja (`put_then_get_reflects_the_stored_profile`), upsert actualiza en una segunda llamada (`put_updates_email_and_display_name_on_a_second_call`), falta credencial de servicio → 401 antes de tocar DB (`missing_gateway_secret_returns_401_before_touching_the_database`), credencial incorrecta → 401 (`wrong_gateway_secret_returns_401`), falta header de identidad → 400 (`missing_identity_header_returns_400`), perfil inexistente → 404 (`get_profile_returns_404_when_the_caller_has_no_profile_yet`), y un test extra de autorización cruzada entre dos identidades (`a_user_cannot_read_another_users_profile_via_get`), más allá de lo mínimo pedido.
- Verifica **contenido** del cuerpo de la respuesta (`body_json`, `assert_eq!(put_payload["email"], ...)`, etc.), no solo el status code — cumple el anti-patrón explícito de `docs/verification.md`.
- Usa identidades/emails sintéticos (`test-user-1@example.test`, etc.), consistente con `docs/security-scope.md` ("nunca una identidad de Google real").
- Secreto de servicio sintético (`TEST_GATEWAY_SECRET`), nunca una credencial real.

### `Cargo.toml`

- Cambios mínimos y justificados: `subtle` (runtime, comparación en tiempo constante), `tower`/`http` (dev, para ejercer el router vía HTTP real en tests). Nada hardcodeado, nada fuera del alcance de la feature.

## Ejecución de `./init.sh`

Ejecutado completo con Docker disponible (confirmado con `docker ps` antes de correr):

- `cargo fmt --check`: sin diferencias.
- `cargo clippy --all-targets -- -D warnings`: sin warnings.
- `cargo test`: verde (incluye los 17 tests unitarios de otros módulos + 1 de scaffolding).
- `cargo test -- --ignored` (contra Docker real): **7/7** en `tests/api.rs` + **9/9** en `tests/repository.rs`, sin regresión.
- `cargo doc --no-deps`: sin warnings.
- Exit code final: `0`.

## Cambios requeridos (si aplica)

Ninguno. No se encontró ninguna vía por la que un email/nombre/`user_id` de otro usuario, o detalle interno de `RepoError`, llegue a un log o a un cuerpo de error; el orden credencial→identidad→DB se respeta en el único punto de entrada (`require_gateway_and_identity`); y no existe ruta ni parámetro que permita a un llamante operar sobre el perfil de otro usuario.
