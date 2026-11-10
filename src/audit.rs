//! Helper de escritura del log de auditoría (append-only, RF-15).
//!
//! Stub del scaffolding inicial: la lógica real, invocada desde `api` en
//! cada operación que deba dejar rastro de auditoría, se implementa junto a
//! las features `postgres_persistence` y `scan_history_api`. Este módulo
//! nunca expondrá una forma de mutar o borrar una entrada ya escrita (ver
//! `docs/architecture.md`).

/// Acción de auditoría al conceder el rol `admin` a un usuario. El `target`
/// de la entrada es el rol resultante (`"admin"`); no se registra el correo.
pub const ROLE_GRANTED_ACTION: &str = "role.granted";

/// Acción de auditoría al revocar el rol `admin` de un usuario. El `target`
/// de la entrada es el rol resultante (`"user"`); no se registra el correo.
pub const ROLE_REVOKED_ACTION: &str = "role.revoked";
