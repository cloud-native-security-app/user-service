-- Tablas base de ms-usuarios (RF-13, RF-15). Se aplica con el rol "dueño"
-- (el superusuario del contenedor en test, o el rol migrador en
-- producción) — nunca con el rol de aplicación `ms_usuarios_app`, para que
-- el endurecimiento de permisos de la siguiente migración tenga efecto
-- real (el dueño de una tabla se salta cualquier REVOKE en PostgreSQL, ver
-- la migración de permisos más abajo).

CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_history (
    scan_id      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (user_id),
    target       TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (
        status IN ('PENDIENTE', 'EN_PROGRESO', 'COMPLETADO', 'FALLIDO')
    ),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_history_user_id_idx ON scan_history (user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users (user_id),
    target      TEXT NOT NULL,
    action      TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_user_id_idx ON audit_log (user_id);
