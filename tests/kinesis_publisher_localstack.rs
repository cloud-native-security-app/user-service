//! Test de integración de `KinesisSecurityEventPublisher` (tarea KAP-08)
//! contra un LocalStack real levantado con `testcontainers` (sin mocks, sin
//! cuenta AWS): se crea el stream, se publica con el adaptador, se lee con
//! `GetRecords` y el cuerpo se valida contra el schema del contrato
//! (`../broker/contracts/security-event.schema.json`; si el repo hermano no
//! está, solo se omite la validación del schema).
//!
//! Requiere Docker: `#[ignore = "requiere Docker"]`, se ejecuta con
//! `cargo test -- --ignored`.

mod common;

use std::path::PathBuf;

use serde_json::Value;
use user_service::messaging::kinesis::KinesisSecurityEventPublisher;
use user_service::security_events::{SecurityEvent, SecurityEventError, SecurityEventPublisher};

const STREAM: &str = "security-events";

fn schema() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts/security-event.schema.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(serde_json::from_str(&text).expect("schema JSON")),
        Err(_) => {
            eprintln!(
                "SKIP schema: {} not found (sibling broker checkout absent)",
                path.display()
            );
            None
        }
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishes_audit_events_that_read_back_valid_with_actor_sub_as_partition_key() {
    let localstack = common::LocalStack::start().await;
    localstack.create_stream(STREAM).await;
    let publisher =
        KinesisSecurityEventPublisher::from_client(localstack.kinesis.clone(), STREAM.to_string());

    let events = [
        SecurityEvent::audit_recorded("test-user-1", "scan.requested", "scan").unwrap(),
        SecurityEvent::audit_recorded("test-user-2", "role.granted", "user").unwrap(),
        SecurityEvent::audit_recorded("test-user-2", "role.revoked", "user").unwrap(),
    ];
    for event in &events {
        publisher.publish(event).await.expect("publicar el evento");
    }

    let records = localstack.read_stream(STREAM, events.len()).await;
    assert_eq!(
        records.len(),
        events.len(),
        "deben llegar todos los eventos"
    );
    let validator = schema().map(|s| jsonschema::validator_for(&s).expect("schema compila"));
    for (record, event) in records.iter().zip(&events) {
        let body: Value = serde_json::from_slice(record.data().as_ref()).expect("cuerpo JSON");
        assert_eq!(body, serde_json::to_value(event).unwrap());
        assert_eq!(record.partition_key(), event.actor_sub());
        if let Some(validator) = &validator {
            assert!(
                validator.is_valid(&body),
                "no valida contra el schema: {body}"
            );
        }
        let parsed: SecurityEvent = serde_json::from_value(body).expect("deserializa");
        assert_eq!(&parsed, event);
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn publishing_to_a_missing_stream_yields_publish_failed_without_the_body() {
    let localstack = common::LocalStack::start().await;
    let publisher =
        KinesisSecurityEventPublisher::from_client(localstack.kinesis.clone(), "no-existe".into());

    let err = publisher
        .publish(&SecurityEvent::audit_recorded("sub-secret-42", "role.granted", "user").unwrap())
        .await
        .expect_err("un stream inexistente debe fallar");

    assert!(matches!(err, SecurityEventError::PublishFailed(_)));
    assert!(!err.to_string().contains("sub-secret-42"));
}
