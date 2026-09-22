//! Helper de escritura del log de auditoría (append-only, RF-15).
//!
//! Stub del scaffolding inicial: la lógica real, invocada desde `api` en
//! cada operación que deba dejar rastro de auditoría, se implementa junto a
//! las features `postgres_persistence` y `scan_history_api`. Este módulo
//! nunca expondrá una forma de mutar o borrar una entrada ya escrita (ver
//! `docs/architecture.md`).
