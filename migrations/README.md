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
- `20260920120000_create_network_credentials.sql`: tabla
  `network_credentials` (feature `network_credentials_api`, id 10) con
  unicidad `(user_id, target_pattern)`, cifrado en reposo de
  `ssh_credentials_ref` (columnas `_ciphertext`/`_nonce`, AES-256-GCM) y
  grants `SELECT/INSERT/UPDATE/DELETE` para `ms_usuarios_app` — esta tabla
  SÍ es mutable por diseño (CRUD de credenciales propias), a diferencia de
  `audit_log`.

Recordatorio de convención (ver `docs/conventions.md`): una vez aplicada una
migración en algún entorno, nunca se edita — un cambio de esquema es una
migración nueva.
