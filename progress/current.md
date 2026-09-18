# Sesión actual

> Este archivo se vacía al cerrar cada sesión y se mueve a `history.md`.
> Mientras trabajas, **mantenlo actualizado en tiempo real**, no al final.

- **Feature en curso:** _ninguna — elegir la siguiente `pending` de `feature_list.json`_
- **Inicio:** _pendiente_
- **Agente:** _pendiente_

## Plan

_Bullets breves del plan de la próxima sesión._

## Bitácora

_Se registra en tiempo real mientras se trabaja._

## Próximo paso

_Si la sesión se interrumpe, lo primero que debe hacer la siguiente sesión._

## Nota heredada para `service_wiring` (feature id 7)

`progress/explore_audit_log_permissions.md` (pregunta abierta 3) y la
migración `migrations/20260918120100_lock_audit_log_permissions.sql` dejan
sin resolver con qué rol se aplican las migraciones en producción: el rol
de aplicación `ms_usuarios_app` no es dueño de las tablas (por diseño, para
que el `REVOKE` sobre `audit_log` tenga efecto real) y por tanto no puede
migrar el esquema por sí mismo. Cuando se implemente `service_wiring`, hay
que decidir explícitamente si las migraciones de producción corren con un
rol migrador separado y un paso de despliegue distinto del arranque del
binario, o alguna otra estrategia — no asumirlo implícitamente.

`api::router(repository: Repository, gateway_shared_secret: SecretString) -> axum::Router`
(feature 5, extendido por la feature 6 con las rutas de `/users/me/scans`,
`/scans/{scan_id}` y `/users/me/audit` bajo el mismo middleware) queda listo
para que `service_wiring` lo ensamble con el `Config`/pool reales — no hace
falta ensamblar nada extra por separado.

Precedente de diseño para futuras rutas con un identificador en la URL:
`PATCH /scans/{scan_id}` (feature 6) tuvo que corregirse porque exigía la
identidad del Gateway sin usarla para autorizar — cualquier handler nuevo
que reciba un identificador en la URL (no solo `/users/me/...`) debe
verificar ownership contra la identidad del header y responder `403` si no
coincide, `docs/security-scope.md` §"Autorización a nivel de fila" no se
limita al ejemplo `/users/{id}`.
