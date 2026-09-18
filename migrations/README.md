# migrations/

Esta carpeta contendrá las migraciones versionadas de `sqlx migrate` para
`db-usuarios` (tablas `users`, `scan_history` y `audit_log`, con sus claves
foráneas y el endurecimiento de permisos de `audit_log` a solo
`INSERT`/`SELECT`).

Se implementan en la feature `postgres_persistence` de `feature_list.json`.
Por ahora está vacía a propósito: es scaffolding de la feature
`scaffolding` (id 1).

Recordatorio de convención (ver `docs/conventions.md`): una vez aplicada una
migración en algún entorno, nunca se edita — un cambio de esquema es una
migración nueva.
