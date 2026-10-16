# Decisiones y historial de features

Registro breve de las decisiones de diseño del servicio, destilado del antiguo
lista de features del arnés anterior. Cada entrada: contexto, decisión.

## ADR-001 Scaffolding: lib + binario delgado

`src/lib.rs` declara los módulos (`config`, `domain`, `repository`, `audit`,
`api`) como `pub` para que `tests/` (crate externo) pueda importarlos;
`src/main.rs` solo inicializa tokio y `tracing` y llama a la lib. La lib activa
`#![deny(missing_docs)]`.

## ADR-002 Configuración solo por variables de entorno

`src/config.rs` carga todo desde el entorno y devuelve un error tipado si falta
una variable requerida (sin panics). Los secretos usan `secrecy` para que no se
filtren por `Debug`/`Display`. Nada de valores hardcodeados.

## ADR-003 Dominio puro

`UserProfile`, `ScanHistoryEntry` y la entrada de auditoría son tipos puros sin
dependencias de IO.

## ADR-004 Persistencia PostgreSQL con auditoría append-only

Migraciones versionadas de `sqlx` y repositorio en `src/repository.rs`.
`audit_log` solo admite `INSERT`/`SELECT` a nivel de base de datos (RF-15). Como
el dueño de una tabla se salta cualquier `REVOKE`, el rol que migra
(`MIGRATIONS_DATABASE_URL`) debe ser distinto del rol de aplicación
`ms_usuarios_app` (`DATABASE_URL`). Los tests usan dos pools por contenedor: uno
de superusuario para migrar y activar el login del rol de aplicación, y otro
con ese rol para ejercer el repositorio. Ver la migración
`20260918120100_lock_audit_log_permissions.sql`.

## ADR-005 API de perfil

`PUT/GET /users/me`, autorizados a nivel de fila contra la identidad reenviada
por el Gateway.

## ADR-006 API de histórico y auditoría

Registro de solicitudes de escaneo con su auditoría en la misma transacción,
actualización de estado de solicitudes propias y consulta de histórico (RF-13)
y auditoría (RF-15).

## ADR-007 Composition root y health check

`config -> repository -> api` se conecta en `run()` (`src/wiring.rs`), invocada
desde `main`. Se expone un endpoint de salud (RNF-09).

## ADR-008 Imagen Docker multi-stage

Builder `rust:1.98-bookworm`, runtime `distroless/cc-debian12:nonroot`. Las
migraciones se embeben en el binario en compilación.

## ADR-009 Contrato real de `X-Forwarded-User`

El Gateway envía JSON `{"sub": "...", "email": "..."}`. El middleware parsea el
JSON y usa el `sub` como único `user_id`; antes guardaba el JSON completo como
identificador. Se trató como regresión de las APIs de perfil e histórico.

## ADR-010 Credenciales de red por usuario/objetivo

Implementa `GET /users/me/scan-targets?target=<ip|cidr>` (consumido por
`gateway::usuarios_client::resolve_scan_target`) más un CRUD mínimo. Matching:
un `target_pattern` aplica si `target` es una IP contenida en él o es el mismo
CIDR; con varias coincidencias gana el prefijo más largo. `ssh_credentials_ref`
es una credencial SSH real de terceros: se cifra en reposo (AES-256-GCM,
`CREDENTIALS_ENCRYPTION_KEY`) y solo la devuelve el endpoint de resolución.

## ADR-011 Loguear el `RepoError` real

`From<RepoError> for ApiError` descartaba el error sin registrarlo, lo que
ocultó un 500 en AWS. Ahora se loguea el error real en el servidor y el cliente
sigue recibiendo un `ApiError::Internal` genérico.
