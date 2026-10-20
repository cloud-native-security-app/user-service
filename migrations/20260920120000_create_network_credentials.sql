-- Tabla de credenciales de red por usuario/objetivo (feature
-- network_credentials_api, id 10): qué network_user, referencia a la
-- credencial SSH y has_sudo usar para escanear un objetivo (IP exacta o
-- CIDR, v4 o v6) a nombre de un usuario. Se aplica con el rol "dueño"
-- (nunca con ms_usuarios_app), igual que el resto de migraciones.

CREATE TABLE IF NOT EXISTS network_credentials (
    id                              UUID PRIMARY KEY,
    user_id                         TEXT NOT NULL REFERENCES users (user_id),
    target_pattern                  TEXT NOT NULL,
    network_user                    TEXT NOT NULL,
    ssh_credentials_ref_ciphertext  BYTEA NOT NULL,
    ssh_credentials_ref_nonce       BYTEA NOT NULL,
    has_sudo                        BOOLEAN NOT NULL,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Un mismo usuario configura a lo sumo una entrada por objetivo: el
    -- upsert del endpoint crea o actualiza esta fila.
    UNIQUE (user_id, target_pattern)
);

CREATE INDEX IF NOT EXISTS network_credentials_user_id_idx
    ON network_credentials (user_id);

-- La unicidad (user_id, target_pattern) exige un índice sobre target_pattern
-- para ser eficiente además del compuesto; el look-up de resolución por
-- usuario suficiente con el índice de user_id.
CREATE INDEX IF NOT EXISTS network_credentials_user_pattern_idx
    ON network_credentials (user_id, target_pattern);

-- Sin grants implícitos vía PUBLIC.
REVOKE ALL ON network_credentials FROM PUBLIC;

-- A diferencia de audit_log (append-only, RF-15), esta tabla SÍ es mutable
-- por diseño: los endpoints CRUD de la feature network_credentials_api
-- permiten al usuario crear/actualizar/borrar sus propias credenciales, así
-- que el rol de aplicación ms_usuarios_app necesita SELECT/INSERT/UPDATE y
-- DELETE sobre ella. Lo que sí está prohibido es que el valor en claro de
-- ssh_credentials_ref exista aquí: solo se persiste su cifrado
-- (AES-256-GCM) + nonce, y la clave de cifrado vive en la configuración del
-- servicio (src/config.rs), nunca en el repo.
GRANT SELECT, INSERT, UPDATE, DELETE ON network_credentials TO ms_usuarios_app;