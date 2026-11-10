//! Integración extremo a extremo de la emisión de `audit.recorded` (tarea
//! KAP-08): un `Repository` real sobre PostgreSQL (`testcontainers`) con el
//! adaptador Kinesis real contra LocalStack. Se escribe auditoría, se lee el
//! stream con `GetRecords` y cada cuerpo se valida contra el schema del
//! contrato (si `../broker` no está, se omite solo esa validación).
//!
//! Requiere Docker: `#[ignore = "requiere Docker"]`, se ejecuta con
//! `cargo test -- --ignored`.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretSlice;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres as PostgresImage;

use user_service::domain::{
    AdminEmails, AuditEntry, Role, ScanHistoryEntry, ScanStatus, UserProfile,
};
use user_service::messaging::kinesis::KinesisSecurityEventPublisher;
use user_service::repository::Repository;

const STREAM: &str = "security-events";

#[tokio::test]
#[ignore = "requiere Docker"]
async fn audit_writes_reach_the_kinesis_stream_with_valid_bodies_and_actor_sub_partition_key() {
    let localstack = common::LocalStack::start().await;
    localstack.create_stream(STREAM).await;

    let container = PostgresImage::default()
        .start()
        .await
        .expect("el contenedor Postgres debe arrancar");
    let host = container.get_host().await.expect("host");
    let port = container.get_host_port_ipv4(5432).await.expect("puerto");
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("pool");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migraciones");

    let repo = Repository::new(pool, SecretSlice::from(vec![0x07u8; 32]))
        .with_admin_emails(AdminEmails::parse("e2e-admin@example.test").expect("lista"))
        .with_security_events(Arc::new(KinesisSecurityEventPublisher::from_client(
            localstack.kinesis.clone(),
            STREAM.to_string(),
        )));
    let now = chrono::Utc::now();
    for user in ["e2e-admin", "e2e-user"] {
        repo.upsert_user(&UserProfile {
            user_id: user.to_string(),
            email: format!("{user}@example.test"),
            display_name: "Test User".to_string(),
            role: Role::User,
            created_at: now,
        })
        .await
        .expect("upsert");
    }

    repo.sync_admin_roles().await.expect("sync");
    let scan = ScanHistoryEntry {
        scan_id: "e2e-scan".to_string(),
        user_id: "e2e-user".to_string(),
        target: "192.0.2.77".to_string(),
        status: ScanStatus::Pendiente,
        requested_at: now,
        updated_at: now,
        failure_reason: None,
    };
    let audit = AuditEntry::new("e2e-audit", "e2e-user", "192.0.2.77", "scan_requested", now);
    repo.record_scan_request(&scan, &audit)
        .await
        .expect("record_scan_request");

    let records = localstack.read_stream(STREAM, 2).await;
    assert_eq!(records.len(), 2, "un evento por entrada de auditoría");
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts/security-event.schema.json");
    let validator = std::fs::read_to_string(&schema_path)
        .ok()
        .map(|text| serde_json::from_str::<Value>(&text).expect("schema JSON"))
        .map(|schema| jsonschema::validator_for(&schema).expect("schema compila"));
    if validator.is_none() {
        eprintln!("SKIP schema: {} not found", schema_path.display());
    }
    let mut seen = Vec::new();
    for record in &records {
        let body: Value = serde_json::from_slice(record.data().as_ref()).expect("cuerpo JSON");
        if let Some(validator) = &validator {
            assert!(
                validator.is_valid(&body),
                "no valida contra el schema: {body}"
            );
        }
        assert_eq!(body["event_type"], "audit.recorded");
        assert_eq!(body["source"], "user-service");
        assert_eq!(record.partition_key(), body["actor_sub"].as_str());
        let text = body.to_string();
        assert!(!text.contains("example.test") && !text.contains("192.0.2.77"));
        seen.push((
            body["actor_sub"].as_str().unwrap().to_string(),
            body["payload"]["action"].as_str().unwrap().to_string(),
        ));
    }
    seen.sort();
    assert_eq!(
        seen,
        [
            ("e2e-admin".to_string(), "role.granted".to_string()),
            ("e2e-user".to_string(), "scan.requested".to_string()),
        ]
    );
}
