-- Feature `user-role` (KAP-04): cada usuario tiene un rol, `user` o `admin`.
-- El Gateway lo lee del perfil al iniciar sesión y lo incluye en su JWT.
--
-- Cambio aditivo y retrocompatible: las filas existentes quedan con el rol
-- por defecto `user`. `role` es TEXT con una restricción CHECK (no un tipo
-- enum de Postgres), igual que `scan_history.status`.
--
-- Permisos: `users` ya tiene `GRANT SELECT, INSERT, UPDATE` a nivel de tabla
-- para `ms_usuarios_app` (migración de permisos), que cubre la columna
-- nueva; no se concede nada adicional y no se concede `DELETE`. El rol de
-- aplicación necesita `UPDATE` sobre `role` porque la reconciliación con
-- `ADMIN_BOOTSTRAP_EMAILS` (al arrancar y al aprovisionar el perfil) corre
-- con ese rol. La garantía de que ninguna petición HTTP puede escribir el
-- rol vive en la aplicación: `upsert_user` nunca toca `role` y ningún
-- cuerpo de petición lo acepta.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user'
    CONSTRAINT users_role_check CHECK (role IN ('user', 'admin'));
