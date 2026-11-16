-- Feature `scan_history_mode` (NS-08): el histórico guarda el modo del
-- escaneo (`ssh` con credenciales, `network` solo por IP) para que el
-- Gateway lo recupere tras un reinicio.
--
-- Cambio aditivo y retrocompatible: las filas existentes quedan como `ssh`
-- (el único modo que existía) y los llamantes que no envían `scan_mode`
-- siguen funcionando. `scan_history` ya tiene `GRANT SELECT, INSERT, UPDATE`
-- a nivel de tabla para `ms_usuarios_app`, que cubre la columna nueva.

ALTER TABLE scan_history
    ADD COLUMN IF NOT EXISTS scan_mode TEXT NOT NULL DEFAULT 'ssh'
    CHECK (scan_mode IN ('ssh', 'network'));
