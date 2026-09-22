# Review — feature 6 (scan_history_api)

**Re-revisión** tras `CHANGES_REQUESTED` de la ronda anterior (este archivo
sobrescribe esa versión). Foco: verificar que `PATCH /scans/{scan_id}` ahora
comprueba ownership del `scan_id` contra `X-Forwarded-User` antes de mutar,
como pedían los "Cambios requeridos" #1 y #2 del veredicto previo.

**Veredicto:** APPROVED

## Qué se pidió y qué se verificó del fix

1. **`src/repository.rs:141-149` — `find_scan_owner(scan_id) -> Result<Option<String>, RepoError>`**:
   consulta de solo lectura (`SELECT user_id FROM scan_history WHERE
   scan_id = $1`), no expone más columnas que el dueño, devuelve `Ok(None)`
   para `scan_id` inexistente (nunca error), y `RepoError` en caso de fallo
   de infraestructura — consistente con el resto del módulo (nunca
   `panic!`).

2. **`src/api.rs:280-306` — `patch_scan_status`**: ahora usa
   `Extension(identity)` (ya no `_identity`, el valor se usa de verdad).
   Flujo verificado línea por línea:
   - `find_scan_owner` falla por infra → `ApiError::from` → `Internal`
     (500), nunca detalle crudo.
   - `scan_id` inexistente (`Ok(None)`) → `.ok_or(ApiError::NotFound)?` →
     **404**, exactamente como antes del fix (sin regresión).
   - `scan_id` existe pero `owner != identity.0` → **403**
     (`ApiError::Forbidden`, nueva variante, `StatusCode::FORBIDDEN`,
     mensaje genérico `"el recurso solicitado no pertenece al llamante"` —
     no incluye el `user_id` real del dueño ni el del intruso, no hay fuga).
   - `owner == identity.0` → procede a `update_scan_status` igual que
     antes: `RepoError::NotFound` (race entre el `SELECT` de
     `find_scan_owner` y el `UPDATE`, caso de borde teórico ya que no existe
     ningún `DELETE` expuesto sobre `scan_history`) sigue mapeando a `404`;
     éxito → `204 No Content`, sin cambios de comportamiento respecto a la
     versión ya aprobada.

   Es exactamente la opción (a) que pedía el veredicto anterior: 403 cuando
   el id existe pero no coincide, 404 solo cuando no existe en absoluto, sin
   inventar un mecanismo nuevo de autenticación de servicio no documentado.

3. **Test nuevo `a_user_cannot_patch_another_users_scan_status`
   (`tests/api.rs:510-569`)**: usa dos identidades reales
   (`patch-owner`/`patch-intruder`), `patch-owner` crea el escaneo vía
   `POST /users/me/scans`, `patch-intruder` intenta `PATCH` sobre ese mismo
   `scan_id` y se confirma `403 Forbidden` (línea 545-549). Además —esto es
   lo que cierra el punto 2 de "Cambios requeridos"— confirma explícitamente
   que el intento rechazado **no mutó nada**: `GET /users/me/scans` como
   `patch-owner` devuelve el único escaneo con `status == "PENDIENTE"`
   (línea 564-568), es decir que el `COMPLETADO` del payload del intruso
   nunca se aplicó.

   Los tests preexistentes que dependían del comportamiento correcto ya
   aprobado siguen sin regresión:
   - `patch_scan_status_returns_404_for_unknown_scan_id`
     (`tests/api.rs:490-507`) usa un `scan_id` que no existe y sigue
     recibiendo `404` (nunca `403`, correcto: `find_scan_owner` devuelve
     `None` antes de llegar a comparar identidades).
   - `patch_scan_status_update_is_reflected_in_get_history`
     (`tests/api.rs:441-486`, nombre real del test que antes se llamaba
     distinto) usa la **misma** identidad (`scan-patch-owner`) para el
     `POST` y el `PATCH`, recibe `204` y el `GET` posterior refleja
     `COMPLETADO` — confirma que el ownership check no rompe el caso feliz.

## `./init.sh` completo — verde real

Ejecutado end-to-end, con `docker ps` confirmando Docker disponible antes de
`cargo test -- --ignored`:

- `cargo fmt --check`: sin diferencias.
- `cargo clippy --all-targets -- -D warnings`: sin advertencias.
- `cargo test` (unitarios, sin Docker): verde.
- `cargo test -- --ignored` contra Postgres real vía `testcontainers`:
  **13/13 en `tests/api.rs`** (incluye el nuevo test de ownership del
  `PATCH` y los 12 preexistentes, todos `ok`) y **13/13 en
  `tests/repository.rs`** (incluye
  `update_and_delete_against_audit_log_fail_by_permissions_for_the_app_role`
  y `record_scan_request_rolls_back_history_when_audit_insert_fails`, ambos
  heredados de features 4 y 6 anteriores, sin regresión).
- `cargo doc --no-deps`: genera sin errores, incluida la rustdoc nueva de
  `find_scan_owner` y de `patch_scan_status` que documenta explícitamente
  la regla 403 vs 404.

Sin regresión en ningún test de las features 4, 5, ni el resto de la 6 ya
aprobado en la ronda anterior.

## Revisión de efectos colaterales del fix

- No se toca `audit_log` en este fix: sigue sin `UPDATE`/`DELETE` a nivel de
  código y de permisos de base de datos (test heredado sigue en verde).
- `ApiError::Forbidden` no lleva ningún campo con datos (es una variante
  unitaria), y su `Display`/cuerpo JSON son un mensaje fijo genérico — no
  hay forma de que filtre el `user_id`, email o nombre de ningún usuario
  (ni del dueño real ni del intruso) en el error 403.
- `find_scan_owner` no introduce ningún `unwrap()`/`panic!()`/`println!`/
  `dbg!` fuera de test; usa `?`/`Result` de punta a punta igual que el resto
  de `repository.rs`.
- No hay ningún otro archivo tocado más allá de lo ya declarado en
  `progress/current.md` (`git status`/`git diff --stat` confirman
  exactamente `src/api.rs`, `src/repository.rs`, `tests/api.rs`,
  `tests/repository.rs`, `progress/current.md`, `feature_list.json`,
  `Cargo.toml`/`Cargo.lock` sin dependencias nuevas para este fix concreto).

## Checkpoints

- C1: [x] — 4 archivos base + 4 docs existen; `./init.sh` termina en 0.
- C2: [x] — 1 sola feature `in_progress` (id 6, correcto: el implementer no
  la marca `done`, corresponde al reviewer/leader); features `done` (1-5)
  siguen con sus tests en verde sin regresión; `progress/current.md`
  describe la sesión activa (incluye la bitácora del fix de esta ronda) sin
  basura de sesiones previas.
- C3: [x] — El problema que bloqueaba C3 en la ronda anterior
  (`patch_scan_status` ignoraba la identidad del llamante) está resuelto:
  ahora respeta la autorización a nivel de fila de
  `docs/security-scope.md` §"Autorización a nivel de fila" para
  `/scans/{scan_id}` igual que ya lo hacía para `/users/{id}/...`. Resto de
  la capa (repository, módulos, dependencias, ausencia de
  `unwrap`/`panic!`/`println!` fuera de test, rustdoc) sigue cumpliendo.
- C4: [x] — Tests de integración reales contra Postgres vía
  `testcontainers` para `repository` y `api`, incluido el nuevo test de
  ownership de `PATCH` con dos identidades; test de rechazo de
  `UPDATE`/`DELETE` sobre `audit_log` a nivel de base de datos sigue
  pasando; `cargo test` > 0 y todo verde; `cargo clippy --all-targets -- -D
  warnings` sin advertencias.
- C5: [x] — Sin archivos sin trackear sospechosos (aparte de este propio
  `progress/review_6.md`); los archivos modificados coinciden con lo
  declarado por el implementer en `progress/current.md`.
  `progress/history.md` se actualizará al cerrar la sesión, junto con el
  cambio de estado a `done` en `feature_list.json` — no corresponde a este
  reviewer hacerlo directamente.

## Cambios requeridos (si aplica)

Ninguno. El fix de ownership queda correctamente resuelto: `PATCH
/scans/{scan_id}` ahora exige `owner == identity.0` (403 si no coincide, 404
si el `scan_id` no existe, 204 si coincide y se aplica), está cubierto por
un test de integración real con dos identidades distintas que además
verifica que el intento rechazado no mutó el estado, y `./init.sh` completo
(incluido Docker real) termina en verde sin regresión en ninguna feature
previamente aprobada.
