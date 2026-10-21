-- Feature `scan-report` (opción A): el histórico de escaneos guarda el
-- resultado completo del escaneo (JSONB) y el motivo de un fallo o una
-- cancelación, y admite el estado CANCELADO.
--
-- Cambio aditivo y retrocompatible: las columnas nuevas son NULL, así que
-- las filas y los llamantes existentes siguen funcionando. `scan_history`
-- ya tiene `GRANT SELECT, INSERT, UPDATE` a nivel de tabla para
-- `ms_usuarios_app` (migración de permisos), que cubre las columnas nuevas.

ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS result JSONB NULL;
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS failure_reason TEXT NULL;

-- `status` es TEXT con una restricción CHECK (no un tipo enum de Postgres):
-- se reemplaza por una que incluye CANCELADO.
ALTER TABLE scan_history DROP CONSTRAINT IF EXISTS scan_history_status_check;
ALTER TABLE scan_history ADD CONSTRAINT scan_history_status_check CHECK (
    status IN ('PENDIENTE', 'EN_PROGRESO', 'COMPLETADO', 'FALLIDO', 'CANCELADO')
);
