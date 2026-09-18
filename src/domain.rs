//! Tipos de dominio puros: perfil de usuario, histórico de escaneos y
//! entradas de auditoría.
//!
//! Estos tipos no hacen IO: solo modelan los datos que las capas
//! `repository`/`api` persisten y exponen. Los identificadores de Google
//! (`user_id`, `email`, `display_name`) son datos personales — ver
//! `docs/security-scope.md` — por lo que ningún tipo de este módulo deriva
//! `Display` ni participa en un mensaje de log o de error; su único uso es
//! como estructura de datos serializable para la API HTTP.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Perfil de un usuario autenticado.
///
/// `user_id` es la identidad ya verificada por el Gateway/IDaaS (p. ej. el
/// `sub` de Google, RF-01) — `ms-usuarios` no la valida, solo la persiste y
/// la usa como clave primaria del perfil. `email` y `display_name` son datos
/// personales reenviados junto con esa identidad: nunca deben aparecer en
/// logs, mensajes de error o mensajes de panic (ver
/// `docs/security-scope.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    /// Identidad ya verificada por el Gateway (p. ej. el `sub` de Google).
    pub user_id: String,
    /// Correo electrónico asociado a la identidad de Google. Dato personal.
    pub email: String,
    /// Nombre visible del usuario. Dato personal.
    pub display_name: String,
    /// Marca de tiempo en la que se creó el perfil en `ms-usuarios`.
    pub created_at: DateTime<Utc>,
}

/// Estado de una solicitud de escaneo, según los 4 estados definidos por
/// RF-07.
///
/// Es un enum cerrado: no existe una variante "desconocida" ni un valor por
/// defecto silencioso — un valor fuera de estas 4 variantes no compila, y un
/// string que no coincida con ninguna de ellas falla la deserialización en
/// vez de mapear a un estado arbitrario. El encoding JSON usa
/// `SCREAMING_SNAKE_CASE` para coincidir exactamente con los nombres de
/// estado documentados en `docs/architecture.md`
/// (`PENDIENTE`/`EN_PROGRESO`/`COMPLETADO`/`FALLIDO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStatus {
    /// El escaneo fue solicitado pero aún no ha comenzado a ejecutarse.
    Pendiente,
    /// El escaneo está siendo ejecutado actualmente.
    EnProgreso,
    /// El escaneo terminó exitosamente.
    Completado,
    /// El escaneo terminó con un error y no produjo un resultado utilizable.
    Fallido,
}

/// Entrada del histórico de escaneos solicitados por un usuario (RF-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    /// Identificador único de la solicitud de escaneo.
    pub scan_id: String,
    /// Identidad del usuario que solicitó el escaneo (ver [`UserProfile`]).
    pub user_id: String,
    /// Objetivo del escaneo (p. ej. una IP o rango de red).
    pub target: String,
    /// Estado actual de la solicitud.
    pub status: ScanStatus,
    /// Marca de tiempo en la que se solicitó el escaneo.
    pub requested_at: DateTime<Utc>,
    /// Marca de tiempo de la última actualización de estado.
    pub updated_at: DateTime<Utc>,
}

/// Entrada inmutable del log de auditoría (RF-15): registra qué usuario
/// solicitó un escaneo sobre qué objetivo y en qué momento.
///
/// Es append-only por diseño a nivel de tipo: sus campos son privados y no
/// existe ningún método público que reciba `&mut self` ni un setter — la
/// única forma de obtener una instancia es [`AuditEntry::new`], y una vez
/// construida no puede modificarse. La corrección de un dato erróneo se
/// modela como una entrada nueva, nunca como la mutación de una existente
/// (ver `docs/security-scope.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    id: String,
    user_id: String,
    target: String,
    action: String,
    recorded_at: DateTime<Utc>,
}

impl AuditEntry {
    /// Construye una nueva entrada de auditoría.
    ///
    /// No existe forma pública de modificarla tras construirla: todos sus
    /// accesores son de solo lectura.
    pub fn new(
        id: impl Into<String>,
        user_id: impl Into<String>,
        target: impl Into<String>,
        action: impl Into<String>,
        recorded_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: id.into(),
            user_id: user_id.into(),
            target: target.into(),
            action: action.into(),
            recorded_at,
        }
    }

    /// Identificador único de la entrada de auditoría.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Identidad del usuario que originó la acción auditada.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Objetivo (p. ej. IP o rango de red) sobre el que se solicitó la
    /// acción auditada.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Descripción de la acción auditada (p. ej. `"scan_requested"`).
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Marca de tiempo en la que se registró la entrada.
    pub fn recorded_at(&self) -> DateTime<Utc> {
        self.recorded_at
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn sample_timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 18, 12, 0, 0).unwrap()
    }

    #[test]
    fn user_profile_round_trips_through_json() {
        let profile = UserProfile {
            user_id: "google-oauth2|123456".to_string(),
            email: "test-user-1@example.test".to_string(),
            display_name: "Test User".to_string(),
            created_at: sample_timestamp(),
        };

        let json = serde_json::to_string(&profile).expect("serializa");
        let round_tripped: UserProfile = serde_json::from_str(&json).expect("deserializa");

        assert_eq!(profile, round_tripped);
    }

    #[test]
    fn scan_history_entry_round_trips_through_json() {
        let entry = ScanHistoryEntry {
            scan_id: "scan-1".to_string(),
            user_id: "google-oauth2|123456".to_string(),
            target: "192.0.2.10".to_string(),
            status: ScanStatus::EnProgreso,
            requested_at: sample_timestamp(),
            updated_at: sample_timestamp(),
        };

        let json = serde_json::to_string(&entry).expect("serializa");
        let round_tripped: ScanHistoryEntry = serde_json::from_str(&json).expect("deserializa");

        assert_eq!(entry, round_tripped);
    }

    #[test]
    fn audit_entry_round_trips_through_json() {
        let entry = AuditEntry::new(
            "audit-1",
            "google-oauth2|123456",
            "192.0.2.10",
            "scan_requested",
            sample_timestamp(),
        );

        let json = serde_json::to_string(&entry).expect("serializa");
        let round_tripped: AuditEntry = serde_json::from_str(&json).expect("deserializa");

        assert_eq!(entry, round_tripped);
        assert_eq!(round_tripped.id(), "audit-1");
        assert_eq!(round_tripped.user_id(), "google-oauth2|123456");
        assert_eq!(round_tripped.target(), "192.0.2.10");
        assert_eq!(round_tripped.action(), "scan_requested");
        assert_eq!(round_tripped.recorded_at(), sample_timestamp());
    }

    #[test]
    fn scan_status_json_encoding_is_stable() {
        assert_eq!(
            serde_json::to_string(&ScanStatus::Pendiente).unwrap(),
            "\"PENDIENTE\""
        );
        assert_eq!(
            serde_json::to_string(&ScanStatus::EnProgreso).unwrap(),
            "\"EN_PROGRESO\""
        );
        assert_eq!(
            serde_json::to_string(&ScanStatus::Completado).unwrap(),
            "\"COMPLETADO\""
        );
        assert_eq!(
            serde_json::to_string(&ScanStatus::Fallido).unwrap(),
            "\"FALLIDO\""
        );
    }

    #[test]
    fn scan_status_deserializes_from_its_stable_encoding() {
        assert_eq!(
            serde_json::from_str::<ScanStatus>("\"PENDIENTE\"").unwrap(),
            ScanStatus::Pendiente
        );
        assert_eq!(
            serde_json::from_str::<ScanStatus>("\"EN_PROGRESO\"").unwrap(),
            ScanStatus::EnProgreso
        );
        assert_eq!(
            serde_json::from_str::<ScanStatus>("\"COMPLETADO\"").unwrap(),
            ScanStatus::Completado
        );
        assert_eq!(
            serde_json::from_str::<ScanStatus>("\"FALLIDO\"").unwrap(),
            ScanStatus::Fallido
        );
    }

    #[test]
    fn scan_status_rejects_unknown_string_instead_of_defaulting() {
        let result = serde_json::from_str::<ScanStatus>("\"NO_EXISTE\"");

        assert!(
            result.is_err(),
            "un string desconocido debe fallar la deserialización, no caer en un default"
        );
    }
}
