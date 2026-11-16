-- Feature `network_scan_permission` (NS-07): permiso para lanzar escaneos en
-- modo red (sin credenciales). Solo las cuentas de una lista autorizada
-- (`NETWORK_SCAN_EMAILS`) lo tienen. El Gateway lo lee del perfil al iniciar
-- sesion y lo revalida contra `GET /users/me` en cada escaneo de red.
--
-- Cambio aditivo y retrocompatible: las filas existentes quedan en `false`.
--
-- Permisos: `users` ya tiene `GRANT SELECT, INSERT, UPDATE` a nivel de tabla
-- para `ms_usuarios_app`, que cubre la columna nueva; no se concede nada
-- adicional. La garantia de que ninguna peticion HTTP puede escribir el
-- permiso vive en la aplicacion: `upsert_user` nunca toca la columna y
-- ningun cuerpo de peticion la acepta; solo la reconciliacion con
-- `NETWORK_SCAN_EMAILS` la cambia.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS can_network_scan BOOLEAN NOT NULL DEFAULT false;
