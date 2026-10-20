-- Crea (idempotentemente) el rol de aplicación de ms-usuarios SIN
-- contraseña ni LOGIN embebidos, y aplica el endurecimiento de permisos de
-- docs/security-scope.md ("Log de auditoría (RF-15): inmutabilidad"):
--   - users, scan_history: SELECT/INSERT/UPDATE para el rol de aplicación
--     (el repositorio nunca hace DELETE sobre estas tablas tampoco, pero
--     eso no se refuerza aquí porque no es un requisito de seguridad de
--     RF-15 — solo audit_log lo es).
--   - audit_log: SOLO SELECT/INSERT. Nunca UPDATE/DELETE, ni siquiera para
--     el propio código de la aplicación (ver docs/architecture.md
--     "Qué NO hacer").
--
-- Por qué el rol se crea sin contraseña: una contraseña embebida aquí
-- quedaría fija en el historial de `sqlx` (misma migración en todos los
-- entornos que la apliquen, sin poder editarla después) y se aplicaría
-- igual en producción que en un contenedor de test efímero — violaría
-- docs/security-scope.md ("ningún valor de configuración/credencial queda
-- hardcodeado en el repo"). Este rol se deja en NOLOGIN; quien active el
-- login (con una contraseña gestionada aparte, vía secretos/DBA/Terraform
-- en producción, o generada en runtime por el arnés de test en
-- testcontainers) es responsabilidad de cada entorno, no de esta
-- migración. Ver progress/explore_audit_log_permissions.md secciones 2-3
-- para el detalle completo de este diseño.
--
-- NOTA para la feature `service_wiring` (id 7, pendiente): esta migración
-- asume que se aplica con un rol "dueño" de las tablas (el superusuario en
-- test, un rol migrador dedicado en producción) — nunca con
-- `ms_usuarios_app` en sí, porque el dueño de una tabla se salta cualquier
-- REVOKE. Queda pendiente de decidir en `service_wiring` con qué rol/paso
-- de despliegue se aplican estas migraciones en producción si el proceso
-- de `ms-usuarios` solo tiene la credencial de `ms_usuarios_app`.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ms_usuarios_app') THEN
        CREATE ROLE ms_usuarios_app NOLOGIN;
    END IF;
END
$$;

-- El rol necesita poder conectarse a la base de datos y usar el esquema
-- público — ninguno de los dos está garantizado por defecto (Postgres 15+
-- ya no concede USAGE sobre "public" a PUBLIC). current_database() hace la
-- migración portable entre el nombre de BD de producción y el nombre
-- arbitrario que testcontainers asigna al contenedor de test.
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO ms_usuarios_app', current_database());
END
$$;

GRANT USAGE ON SCHEMA public TO ms_usuarios_app;

-- Sin grants implícitos vía PUBLIC sobre ninguna de las 3 tablas.
REVOKE ALL ON users, scan_history, audit_log FROM PUBLIC;

-- users / scan_history: grants normales que necesita el repositorio
-- (upsert_user, find_user, insert_scan_history, update_scan_status,
-- list_scan_history).
GRANT SELECT, INSERT, UPDATE ON users TO ms_usuarios_app;
GRANT SELECT, INSERT, UPDATE ON scan_history TO ms_usuarios_app;

-- audit_log: append-only reforzado a nivel de base de datos (RF-15).
-- REVOKE explícito primero por si alguna vez alguien concede algo más
-- amplio por error en una migración futura mal escrita: esta migración es
-- la fuente de verdad de "audit_log es solo INSERT/SELECT" y se puede
-- volver a aplicar su intención re-ejecutándola a mano en un incidente.
REVOKE ALL ON audit_log FROM ms_usuarios_app;
GRANT SELECT, INSERT ON audit_log TO ms_usuarios_app;
-- Deliberadamente NUNCA: GRANT UPDATE ON audit_log ...
-- Deliberadamente NUNCA: GRANT DELETE ON audit_log ...
