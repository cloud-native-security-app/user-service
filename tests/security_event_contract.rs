//! Paridad de contrato de `SecurityEvent` (tarea KAP-08): cada evento que
//! construye `user-service` valida contra
//! `../broker/contracts/security-event.schema.json`, y los ejemplos de
//! `../broker/contracts/examples/security-event/` se deserializan en el tipo de
//! este servicio. Así un cambio del schema rompe este build en vez de divergir
//! en silencio (ningún servicio depende del crate `broker`).
//!
//! Los tests leen el checkout hermano `../broker` en tiempo de ejecución; si no
//! existe (este repo clonado solo) imprimen un aviso y pasan: sin el otro repo
//! no pueden gatear nada.

use std::path::PathBuf;

use chrono::Utc;
use jsonschema::Validator;
use serde_json::Value;
use user_service::audit::{
    recorded_event, ROLE_GRANTED_ACTION, ROLE_REVOKED_ACTION, SCAN_REQUESTED_ACTION,
};
use user_service::domain::AuditEntry;
use user_service::security_events::{EventSource, SecurityEvent};

fn broker_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts")
        .join(relative)
}

/// Schema compilado del contrato, o `None` (con aviso) si `../broker` falta.
fn schema_validator() -> Option<Validator> {
    let path = broker_path("security-event.schema.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            path.display()
        );
        return None;
    };
    let schema: Value = serde_json::from_str(&text).expect("el schema debe ser JSON válido");
    Some(jsonschema::validator_for(&schema).expect("el schema debe compilar"))
}

fn assert_valid(validator: &Validator, event: &SecurityEvent) {
    let value = serde_json::to_value(event).expect("el evento debe serializar");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| format!("{e} en {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "el evento {} no valida contra el schema: {errors:?}\n{value}",
        event.event_type_str()
    );
}

#[test]
fn every_audit_action_maps_to_an_event_that_validates_against_the_broker_schema() {
    let Some(validator) = schema_validator() else {
        return;
    };
    for action in [
        SCAN_REQUESTED_ACTION,
        ROLE_GRANTED_ACTION,
        ROLE_REVOKED_ACTION,
    ] {
        let entry = AuditEntry::new("audit-1", "user-sub-123", "192.0.2.10", action, Utc::now());
        let event = recorded_event(&entry).expect("la acción debe tener mapeo");
        assert_eq!(event.source(), EventSource::UserService);
        assert_valid(&validator, &event);
    }
}

#[test]
fn constructor_accepts_the_schema_boundaries() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let long_sub = "s".repeat(128);
    let long_slug = format!("a{}", "b_.9".repeat(15) + "b");
    assert_eq!(long_slug.len(), 62);
    let event = SecurityEvent::audit_recorded(&long_sub, &long_slug, "user.v2").unwrap();
    assert_valid(&validator, &event);
}

#[test]
fn schema_rejects_what_the_constructor_refuses_to_build() {
    // Salvaguarda de las pruebas anteriores: el validador no es permisivo.
    let Some(validator) = schema_validator() else {
        return;
    };
    let base = serde_json::json!({
        "event_id": "3f2b8c1e-5d4a-4e7b-9a10-2c6d8e0f1a0b",
        "event_type": "audit.recorded",
        "occurred_at": "2026-11-09T12:30:00Z",
        "source": "user-service",
        "actor_sub": "user-sub-123",
        "payload": {"action": "role.granted", "resource_type": "user"}
    });
    assert!(validator.is_valid(&base));
    let mut bad_slug = base.clone();
    bad_slug["payload"]["action"] = "Role Granted".into();
    assert!(!validator.is_valid(&bad_slug));
    let mut no_actor = base.clone();
    no_actor.as_object_mut().unwrap().remove("actor_sub");
    assert!(!validator.is_valid(&no_actor));
}

#[test]
fn broker_examples_deserialize_into_security_event_and_round_trip() {
    let dir = broker_path("examples/security-event");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            dir.display()
        );
        return;
    };
    let mut checked = 0;
    for entry in entries {
        let path = entry.expect("entrada legible").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("ejemplo legible");
        let original: Value = serde_json::from_str(&text).expect("ejemplo JSON");
        let event: SecurityEvent = serde_json::from_value(original.clone())
            .unwrap_or_else(|e| panic!("{} no deserializa: {e}", path.display()));
        let again = serde_json::to_value(&event).expect("serializa");
        assert_eq!(
            again,
            original,
            "{} no hace round trip exacto",
            path.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 11,
        "se esperaban al menos los 11 ejemplos del contrato"
    );
}

#[test]
fn audit_recorded_example_has_the_same_shape_as_the_constructor_output() {
    let path = broker_path("examples/security-event/audit-recorded.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("SKIP: {} not found", path.display());
        return;
    };
    let strip = |mut value: Value| -> Value {
        let object = value.as_object_mut().expect("objeto");
        object.remove("event_id");
        object.remove("occurred_at");
        value
    };
    let example: Value = serde_json::from_str(&text).expect("ejemplo JSON");
    let event = SecurityEvent::audit_recorded("user-sub-123", "user.updated", "user").unwrap();
    assert_eq!(
        strip(serde_json::to_value(&event).unwrap()),
        strip(example),
        "audit-recorded.json difiere de la salida del constructor"
    );
}
