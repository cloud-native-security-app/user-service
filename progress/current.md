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
