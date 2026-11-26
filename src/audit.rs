//! Helper de escritura del log de auditoría (append-only, RF-15).
//!
//! Stub del scaffolding inicial: la lógica real, invocada desde `api` en
//! cada operación que deba dejar rastro de auditoría, se implementa junto a
//! las features `postgres_persistence` y `scan_history_api`. Este módulo
//! nunca expondrá una forma de mutar o borrar una entrada ya escrita (ver
//! `docs/architecture.md`).
//!
//! También traduce cada entrada escrita al evento `audit.recorded` del
//! contrato de eventos de seguridad ([`recorded_event`], KAP-08).

use crate::domain::AuditEntry;
use crate::security_events::{InvalidSecurityEvent, SecurityEvent};

/// Acción de auditoría al registrar una solicitud de escaneo
/// (`POST /users/me/scans`). El `target` de la entrada es el objetivo del
/// escaneo (IP o CIDR).
pub const SCAN_REQUESTED_ACTION: &str = "scan_requested";

/// Acción de auditoría al conceder el rol `admin` a un usuario. El `target`
/// de la entrada es el rol resultante (`"admin"`); no se registra el correo.
pub const ROLE_GRANTED_ACTION: &str = "role.granted";

/// Acción de auditoría al revocar el rol `admin` de un usuario. El `target`
/// de la entrada es el rol resultante (`"user"`); no se registra el correo.
pub const ROLE_REVOKED_ACTION: &str = "role.revoked";

/// Audit action when the scan report email was sent. The entry `target` is the
/// scan id; neither the recipient nor the body is recorded.
pub const REPORT_EMAILED_ACTION: &str = "report.emailed";

/// Audit action when the scan report email failed after every retry. The entry
/// `target` is the scan id.
pub const REPORT_EMAIL_FAILED_ACTION: &str = "report.email_failed";

/// Traduce una entrada de `audit_log` ya confirmada al evento `audit.recorded`.
///
/// Mapeo de acciones y tipos de recurso a slugs del contrato (cualquier otra
/// acción se rechaza con [`InvalidSecurityEvent`], porque su texto no es un
/// código conocido y el evento nunca lleva texto libre):
///
/// | `AuditEntry::action` | `payload.action` | `payload.resource_type` |
/// |---|---|---|
/// | [`SCAN_REQUESTED_ACTION`] (`scan_requested`) | `scan.requested` | `scan` |
/// | [`ROLE_GRANTED_ACTION`] (`role.granted`) | `role.granted` | `user` |
/// | [`ROLE_REVOKED_ACTION`] (`role.revoked`) | `role.revoked` | `user` |
/// | [`REPORT_EMAILED_ACTION`] (`report.emailed`) | `report.emailed` | `scan` |
/// | [`REPORT_EMAIL_FAILED_ACTION`] (`report.email_failed`) | `report.email_failed` | `scan` |
///
/// `actor_sub` es el `user_id` de la entrada: en `scan_requested`, el usuario
/// que pidió el escaneo (quien actúa); en `role.granted`/`role.revoked`, el
/// usuario cuyo rol cambió (el sujeto; el cambio lo hace la lista
/// `ADMIN_BOOTSTRAP_EMAILS`, no una persona); en `report.emailed`/
/// `report.email_failed`, el dueño del escaneo (el destinatario; el envío lo
/// hace el servicio, no una persona). El `target` (IP del escaneo, rol
/// resultante o id del escaneo) y el identificador de la entrada no se
/// publican.
///
/// # Errores
///
/// [`InvalidSecurityEvent`] si la acción no tiene mapeo o el `user_id` no es un
/// `actor_sub` válido para el schema.
pub fn recorded_event(entry: &AuditEntry) -> Result<SecurityEvent, InvalidSecurityEvent> {
    let (action, resource_type) = match entry.action() {
        SCAN_REQUESTED_ACTION => ("scan.requested", "scan"),
        ROLE_GRANTED_ACTION => (ROLE_GRANTED_ACTION, "user"),
        ROLE_REVOKED_ACTION => (ROLE_REVOKED_ACTION, "user"),
        REPORT_EMAILED_ACTION => (REPORT_EMAILED_ACTION, "scan"),
        REPORT_EMAIL_FAILED_ACTION => (REPORT_EMAIL_FAILED_ACTION, "scan"),
        _ => {
            return Err(InvalidSecurityEvent {
                event_type: "audit.recorded",
                field: "action",
            })
        }
    };
    SecurityEvent::audit_recorded(entry.user_id(), action, resource_type)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn entry(user_id: &str, action: &str) -> AuditEntry {
        AuditEntry::new(
            "audit-1",
            user_id,
            "target-never-published",
            action,
            Utc::now(),
        )
    }

    #[test]
    fn scan_requested_maps_to_scan_requested_on_a_scan_with_the_requester_as_actor() {
        let event = recorded_event(&entry("user-sub-1", SCAN_REQUESTED_ACTION)).unwrap();
        assert_eq!(event.actor_sub(), Some("user-sub-1"));
        assert_eq!(
            event.payload(),
            &serde_json::json!({"action": "scan.requested", "resource_type": "scan"})
        );
    }

    #[test]
    fn role_changes_map_to_their_own_action_on_a_user_with_the_subject_as_actor() {
        for action in [ROLE_GRANTED_ACTION, ROLE_REVOKED_ACTION] {
            let event = recorded_event(&entry("user-sub-2", action)).unwrap();
            assert_eq!(event.actor_sub(), Some("user-sub-2"));
            assert_eq!(
                event.payload(),
                &serde_json::json!({"action": action, "resource_type": "user"})
            );
        }
    }

    #[test]
    fn report_email_outcomes_map_to_their_own_action_on_a_scan_with_the_owner_as_actor() {
        for action in [REPORT_EMAILED_ACTION, REPORT_EMAIL_FAILED_ACTION] {
            let event = recorded_event(&entry("user-sub-3", action)).unwrap();
            assert_eq!(event.actor_sub(), Some("user-sub-3"));
            assert_eq!(
                event.payload(),
                &serde_json::json!({"action": action, "resource_type": "scan"})
            );
        }
    }

    #[test]
    fn the_event_never_carries_the_audit_target() {
        let event = recorded_event(&entry("user-sub-1", ROLE_GRANTED_ACTION)).unwrap();
        let text = serde_json::to_string(&event).unwrap();
        assert!(!text.contains("target-never-published"));
    }

    #[test]
    fn unmapped_actions_are_refused_naming_the_field_only() {
        let err = recorded_event(&entry("user-sub-1", "free text, with secrets"))
            .expect_err("una acción sin mapeo no se publica");
        assert_eq!(err.field, "action");
        assert!(!err.to_string().contains("secrets"));
    }
}
