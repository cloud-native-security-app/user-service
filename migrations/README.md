# migrations/

Migraciones versionadas de `sqlx migrate` para `db-usuarios` (feature
`postgres_persistence`, id 4):

- `20260918120000_create_core_schema.sql`: tablas `users`, `scan_history`,
  `audit_log` con sus claves foráneas (`scan_history.user_id ->
  users.user_id`, `audit_log.user_id -> users.user_id`). Se aplica con el
  rol "dueño" (nunca con `ms_usuarios_app`).
- `20260918120100_lock_audit_log_permissions.sql`: crea (idempotentemente)
  el rol de aplicación `ms_usuarios_app` en `NOLOGIN` y aplica
  `REVOKE`/`GRANT` para que `audit_log` admita únicamente
  `INSERT`/`SELECT` — nunca `UPDATE`/`DELETE` (RF-15). Contiene una nota
  para la feature `service_wiring` (id 7) sobre qué rol aplica estas
  migraciones en producción.

Recordatorio de convención (ver `docs/conventions.md`): una vez aplicada una
migración en algún entorno, nunca se edita — un cambio de esquema es una
migración nueva.
