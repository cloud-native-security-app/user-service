//! Tipos de dominio puros: perfil de usuario, histórico de escaneos y
//! entradas de auditoría.
//!
//! Estos tipos no hacen IO: solo modelan los datos que las capas
//! `repository`/`api` persisten y exponen. Los identificadores de Google
//! (`user_id`, `email`, `display_name`) son datos personales — ver
//! `docs/security-scope.md` — por lo que ningún tipo de este módulo deriva
//! `Display` ni participa en un mensaje de log o de error; su único uso es
//! como estructura de datos serializable para la API HTTP.

use std::fmt;

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

/// Credenciales de red configuradas por un usuario para un objetivo (IP
/// exacta o CIDR): qué `network_user` usar al conectarse, si tiene `sudo`, y
/// — guardada cifrada en reposo, ver `docs/security-scope.md` §"Credenciales
/// de red" — la referencia a la credencial SSH real.
///
/// Deliberadamente **no** incluye la credencial SSH (`ssh_credentials_ref`):
/// ese valor nunca sale del repositorio — ni en claro ni cifrado — salvo en
/// la respuesta puntual de `GET /users/me/scan-targets` (feature
/// `network_credentials_api`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkCredential {
    /// Identificador único de la entrada, asignado por este servicio.
    pub id: String,
    /// Identidad del usuario que configuró la entrada (el `sub` reenviado
    /// por el Gateway; ver [`UserProfile`]).
    pub user_id: String,
    /// IP exacta o CIDR (v4 o v6) al que aplica esta entrada, tal como el
    /// usuario lo configuró. Validado en el borde (ver
    /// `repository::parse_target`).
    pub target_pattern: String,
    /// Usuario de red a usar para autenticarse en el objetivo.
    pub network_user: String,
    /// Si `network_user` tiene privilegios `sudo` en el objetivo.
    pub has_sudo: bool,
    /// Marca de tiempo en la que se creó la entrada.
    pub created_at: DateTime<Utc>,
    /// Marca de tiempo de la última actualización de la entrada.
    pub updated_at: DateTime<Utc>,
}

/// Credenciales de red resueltas para un objetivo concreto, devueltas por
/// `GET /users/me/scan-targets` en el shape EXACTO que espera
/// `gateway::usuarios_client::ScanTargetCredentials` (confirmado por lectura
/// directa de ese repo hermano): `network_user`, `ssh_credentials_ref` y
/// `has_sudo`, y solo esos 3 campos.
///
/// `ssh_credentials_ref` es una credencial SSH **real**: este tipo
/// implementa `Debug` a mano para redactarla, igual que
/// `gateway::usuarios_client::ScanTargetCredentials`, de modo que nunca
/// pueda colarse en un log vía `tracing::*!` ni en un `panic` message (ver
/// `docs/security-scope.md` §"Credenciales de red").
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedScanTarget {
    /// Usuario de red a usar para autenticarse en el objetivo.
    pub network_user: String,
    /// Credencial SSH real para autenticarse en el objetivo. Nunca se
    /// loggea (redactada en `Debug`, ver [`ResolvedScanTarget`]).
    pub ssh_credentials_ref: String,
    /// Si `network_user` tiene privilegios `sudo` en el objetivo.
    pub has_sudo: bool,
}

impl fmt::Debug for ResolvedScanTarget {
    /// Implementación manual para que el credencial SSH real
    /// (`ssh_credentials_ref`) nunca se imprima en texto plano al
    /// formatear con `{:?}` — requisito de `docs/security-scope.md`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedScanTarget")
            .field("network_user", &self.network_user)
            .field("ssh_credentials_ref", &"[REDACTED]")
            .field("has_sudo", &self.has_sudo)
            .finish()
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

    #[test]
    fn network_credential_serializes_without_any_credential_material() {
        let credential = NetworkCredential {
            id: "cred-1".to_string(),
            user_id: "google-oauth2|123456".to_string(),
            target_pattern: "203.0.113.0/24".to_string(),
            network_user: "netadmin".to_string(),
            has_sudo: true,
            created_at: sample_timestamp(),
            updated_at: sample_timestamp(),
        };

        let json = serde_json::to_value(&credential).expect("serializa");

        assert_eq!(json["id"], "cred-1");
        assert_eq!(json["user_id"], "google-oauth2|123456");
        assert_eq!(json["target_pattern"], "203.0.113.0/24");
        assert_eq!(json["network_user"], "netadmin");
        assert_eq!(json["has_sudo"], true);
        assert_eq!(
            json["created_at"],
            serde_json::to_value(sample_timestamp()).expect("ts")
        );
        assert!(
            json.get("ssh_credentials_ref").is_none(),
            "NetworkCredential nunca debe serializar la credencial SSH"
        );
    }

    #[test]
    fn resolved_scan_target_serializes_exactly_the_three_contract_fields() {
        let resolved = ResolvedScanTarget {
            network_user: "netadmin".to_string(),
            ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
            has_sudo: true,
        };

        let json = serde_json::to_value(&resolved).expect("serializa");

        let object = json.as_object().expect("debe ser un objeto");
        assert_eq!(
            object.len(),
            3,
            "el shape de scan-targets debe ser EXACTO: \
             {{network_user, ssh_credentials_ref, has_sudo}}"
        );
        assert_eq!(json["network_user"], "netadmin");
        assert_eq!(json["ssh_credentials_ref"], "lab-only-not-a-real-secret");
        assert_eq!(json["has_sudo"], true);
    }

    #[test]
    fn resolved_scan_target_debug_redacts_the_ssh_credential() {
        let resolved = ResolvedScanTarget {
            network_user: "netadmin".to_string(),
            ssh_credentials_ref: "lab-only-not-a-real-secret".to_string(),
            has_sudo: true,
        };

        let debug_output = format!("{resolved:?}");

        assert!(!debug_output.contains("lab-only-not-a-real-secret"));
        assert!(debug_output.contains("REDACTED"));
    }
}
