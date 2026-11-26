//! Integration tests of the report email (EM-02) against a real Postgres and a
//! real Mailpit SMTP sink (`axllent/mailpit`), both started with
//! `testcontainers`. Marked `#[ignore = "requiere Docker"]`: run them with
//! `cargo test -- --ignored` (`make test-integration`).

mod common;

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use secrecy::SecretSlice;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};
use testcontainers_modules::postgres::Postgres as PostgresImage;

use tokio_util::sync::CancellationToken;
use user_service::domain::{
    ReportEmailStatus, Role, ScanHistoryEntry, ScanMode, ScanStatus, UserProfile,
};
use user_service::messaging::sqs::{
    load_queue_settings, SqsReportEmailConsumer, SqsReportEmailPublisher,
};
use user_service::report_email::mailer::{InMemoryMailer, Mailer, MailerError, OutgoingEmail};
use user_service::report_email::queue::{RecordingPublisher, ReportEmailRequestPublisher};
use user_service::report_email::service::{
    QueueOutcome, ReaperPolicy, ReportEmailService, ReportEmailStore, RetryPolicy,
};
use user_service::report_email::smtp::{SmtpMailer, SmtpSettings, SmtpTls};
use user_service::report_email::ReportAttachment;
use user_service::repository::Repository;

const MAILPIT_TAG: &str = "v1.21";

struct TestDb {
    _container: ContainerAsync<PostgresImage>,
    pool: PgPool,
}

async fn start_db() -> TestDb {
    let container = PostgresImage::default()
        .start()
        .await
        .expect("Postgres must start");
    let host = container.get_host().await.expect("host");
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&format!(
            "postgres://postgres:postgres@{host}:{port}/postgres"
        ))
        .await
        .expect("connect");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply");
    TestDb {
        _container: container,
        pool,
    }
}

fn repository(pool: &PgPool) -> Repository {
    Repository::new(pool.clone(), SecretSlice::from(vec![0x07u8; 32]))
}

/// Inserts the owner and a scan, then stores `status` with a result.
async fn seed_scan(repo: &Repository, scan_id: &str, status: ScanStatus) {
    let now = Utc::now();
    repo.upsert_user(&UserProfile {
        user_id: "owner-sub".into(),
        email: "owner@example.test".into(),
        display_name: "Owner".into(),
        role: Role::User,
        can_network_scan: false,
        created_at: now,
    })
    .await
    .expect("user");
    repo.insert_scan_history(&ScanHistoryEntry {
        scan_id: scan_id.into(),
        user_id: "owner-sub".into(),
        target: "192.0.2.10".into(),
        status: ScanStatus::Pendiente,
        requested_at: now,
        updated_at: now,
        failure_reason: None,
        scan_mode: ScanMode::Ssh,
        report_email_status: None,
        report_emailed_at: None,
    })
    .await
    .expect("scan");
    let result = json!({
        "host": "192.0.2.10",
        "ports": [],
        "vulnerabilities": [{
            "id": "CVE-2024-0001", "severity": "high", "description": "d",
            "nse_script": "vulners", "source": "nmap_nse", "references": []
        }],
        "scanned_at": "2026-11-20T15:30:00Z",
    });
    let reason = (status == ScanStatus::Fallido).then_some("boom");
    let result_ref = (status == ScanStatus::Completado).then_some(&result);
    repo.update_scan_outcome(scan_id, status, result_ref, reason)
        .await
        .expect("outcome");
}

async fn history_entry(repo: &Repository) -> ScanHistoryEntry {
    repo.list_scan_history("owner-sub")
        .await
        .expect("history")
        .remove(0)
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_is_atomic_and_the_status_reaches_the_history() {
    let db = start_db().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert_eq!(history_entry(&repo).await.report_email_status, None);

    let (a, b) = tokio::join!(repo.claim("scan-1"), repo.claim("scan-1"));
    let claims: Vec<_> = [a.expect("claim a"), b.expect("claim b")]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(claims.len(), 1, "exactly one concurrent claim wins");
    assert_eq!(claims[0].recipient, "owner@example.test");
    assert_eq!(
        history_entry(&repo).await.report_email_status,
        Some(ReportEmailStatus::Pending)
    );
    assert!(repo.claim("scan-1").await.expect("claim").is_none());

    repo.finish("scan-1", ReportEmailStatus::Sent, Utc::now())
        .await
        .expect("finish");
    let entry = history_entry(&repo).await;
    assert_eq!(entry.report_email_status, Some(ReportEmailStatus::Sent));
    assert!(entry.report_emailed_at.is_some());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_failed_scan_cannot_be_claimed() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Fallido).await;

    assert!(repo.claim("scan-1").await.expect("claim").is_none());
    assert_eq!(history_entry(&repo).await.report_email_status, None);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn the_database_refuses_an_unknown_report_email_status() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;

    let result = sqlx::query("UPDATE scan_history SET report_email_status = 'bogus'")
        .execute(&db.pool)
        .await;
    assert!(result.is_err());
}

struct Mailpit {
    _container: ContainerAsync<GenericImage>,
    smtp_port: u16,
    api: String,
}

async fn start_mailpit() -> Mailpit {
    let container = GenericImage::new("axllent/mailpit", MAILPIT_TAG)
        .with_exposed_port(1025.tcp())
        .with_exposed_port(8025.tcp())
        .start()
        .await
        .expect("Mailpit must start");
    let host = container.get_host().await.expect("host");
    let smtp_port = container.get_host_port_ipv4(1025).await.expect("smtp port");
    let http_port = container.get_host_port_ipv4(8025).await.expect("http port");
    let mailpit = Mailpit {
        _container: container,
        smtp_port,
        api: format!("http://{host}:{http_port}/api/v1"),
    };
    for _ in 0..100 {
        if reqwest::get(format!("{}/messages", mailpit.api))
            .await
            .is_ok()
        {
            return mailpit;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Mailpit API did not come up");
}

impl Mailpit {
    fn settings(&self, tls: SmtpTls) -> SmtpSettings {
        SmtpSettings {
            host: "127.0.0.1".into(),
            port: self.smtp_port,
            username: None,
            password: None,
            from: "reports@example.test".into(),
            tls,
        }
    }

    async fn messages(&self) -> Vec<Value> {
        let list: Value = reqwest::get(format!("{}/messages", self.api))
            .await
            .expect("list")
            .json()
            .await
            .expect("json");
        list["messages"].as_array().cloned().unwrap_or_default()
    }

    async fn message(&self, id: &str) -> Value {
        reqwest::get(format!("{}/message/{id}", self.api))
            .await
            .expect("message")
            .json()
            .await
            .expect("json")
    }
}

fn sample_email() -> OutgoingEmail {
    OutgoingEmail {
        to: "owner@example.test".into(),
        subject: "Informe".into(),
        html: "<html><body><p>hola html</p></body></html>".into(),
        text: "hola texto".into(),
        attachment: ReportAttachment {
            filename: "reporte-escaneo-x.json".into(),
            content_type: "application/json",
            bytes: b"{\n  \"a\": 1\n}".to_vec(),
        },
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn the_smtp_adapter_delivers_html_text_and_json_attachment_to_the_recipient() {
    let mailpit = start_mailpit().await;
    let mailer = SmtpMailer::new(&mailpit.settings(SmtpTls::None)).expect("mailer");

    mailer.send(&sample_email()).await.expect("send");

    let messages = mailpit.messages().await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["To"][0]["Address"], "owner@example.test");
    let message = mailpit.message(messages[0]["ID"].as_str().unwrap()).await;
    assert!(message["HTML"].as_str().unwrap().contains("hola html"));
    assert!(message["Text"].as_str().unwrap().contains("hola texto"));
    assert_eq!(
        message["Attachments"][0]["FileName"],
        "reporte-escaneo-x.json"
    );
    assert_eq!(message["Attachments"][0]["ContentType"], "application/json");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn required_starttls_refuses_a_server_that_does_not_offer_it() {
    let mailpit = start_mailpit().await;
    let mailer = SmtpMailer::new(&mailpit.settings(SmtpTls::StartTls)).expect("mailer");

    let result = mailer.send(&sample_email()).await;

    assert_eq!(result, Err(MailerError::Transport));
    assert!(mailpit.messages().await.is_empty(), "nothing in plain text");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn completing_a_scan_emails_the_owner_once_even_if_the_outcome_is_redelivered() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    let mailer: Arc<dyn Mailer> =
        Arc::new(SmtpMailer::new(&mailpit.settings(SmtpTls::None)).expect("mailer"));
    let service = ReportEmailService::new(repo.clone(), Some(mailer), RetryPolicy::default());

    service.process_completed("scan-1").await;
    service.process_completed("scan-1").await;

    let messages = mailpit.messages().await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["To"][0]["Address"], "owner@example.test");
    let entry = history_entry(&repo).await;
    assert_eq!(entry.report_email_status, Some(ReportEmailStatus::Sent));
    assert!(entry.report_emailed_at.is_some());
    let audit = repo.list_audit_entries("owner-sub").await.expect("audit");
    let emailed: Vec<_> = audit
        .iter()
        .filter(|e| e.action() == "report.emailed")
        .collect();
    assert_eq!(emailed.len(), 1);
    assert_eq!(emailed[0].target(), "scan-1");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn patching_a_scan_to_completed_returns_at_once_and_emails_in_the_background() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use user_service::api::{self, FORWARDED_USER_HEADER, GATEWAY_SECRET_HEADER};

    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::EnProgreso).await;
    let mailer: Arc<dyn Mailer> =
        Arc::new(SmtpMailer::new(&mailpit.settings(SmtpTls::None)).expect("mailer"));
    let app = api::router_with_report_email(
        repo,
        "gateway-secret".to_string().into(),
        Some((Some(mailer), RetryPolicy::default())),
    );
    let identity = json!({"sub": "owner-sub", "email": "owner@example.test"}).to_string();
    let result = json!({
        "host": "192.0.2.10", "ports": [], "vulnerabilities": [],
        "scanned_at": "2026-11-20T15:30:00Z"
    });
    let patch = |status: &str| {
        Request::builder()
            .method("PATCH")
            .uri("/scans/scan-1")
            .header(GATEWAY_SECRET_HEADER, "gateway-secret")
            .header(FORWARDED_USER_HEADER, &identity)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"status": status, "result": result}).to_string(),
            ))
            .unwrap()
    };

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(patch("COMPLETADO"))
            .await
            .expect("patch");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    let mut messages = Vec::new();
    for _ in 0..100 {
        messages = mailpit.messages().await;
        if !messages.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Let a (wrong) second send show up before asserting there is only one.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(mailpit.messages().await.len(), 1);
    assert_eq!(messages[0]["To"][0]["Address"], "owner@example.test");

    let list = Request::builder()
        .uri("/users/me/scans")
        .header(GATEWAY_SECRET_HEADER, "gateway-secret")
        .header(FORWARDED_USER_HEADER, &identity)
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(list).await.expect("list");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let history: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(history[0]["report_email_status"], "sent");
    assert!(history[0]["report_emailed_at"].is_string());
}

/// Leaves the scan `pending` since `age`, as if the process died mid-send.
async fn strand_pending(pool: &PgPool, scan_id: &str, age: &str) {
    sqlx::query(
        "UPDATE scan_history SET report_email_status = 'pending', \
         report_email_claimed_at = now() - $2::interval WHERE scan_id = $1",
    )
    .bind(scan_id)
    .bind(age)
    .execute(pool)
    .await
    .expect("strand");
}

async fn mailpit_service(repo: &Arc<Repository>, mailpit: &Mailpit) -> Arc<ReportEmailService> {
    let mailer: Arc<dyn Mailer> =
        Arc::new(SmtpMailer::new(&mailpit.settings(SmtpTls::None)).expect("mailer"));
    Arc::new(ReportEmailService::new(
        repo.clone(),
        Some(mailer),
        RetryPolicy::default(),
    ))
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn the_reaper_sends_a_pending_report_older_than_the_threshold_and_marks_it_sent() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());
    strand_pending(&db.pool, "scan-1", "1 hour").await;

    let processed = mailpit_service(&repo, &mailpit)
        .await
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(processed, 1);
    let messages = mailpit.messages().await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["To"][0]["Address"], "owner@example.test");
    let entry = history_entry(&repo).await;
    assert_eq!(entry.report_email_status, Some(ReportEmailStatus::Sent));
    assert!(entry.report_emailed_at.is_some());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn the_reaper_also_takes_a_legacy_pending_row_without_a_claim_time() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    sqlx::query(
        "UPDATE scan_history SET report_email_status = 'pending', \
         report_email_claimed_at = NULL, updated_at = now() - interval '1 hour'",
    )
    .execute(&db.pool)
    .await
    .expect("legacy row");

    mailpit_service(&repo, &mailpit)
        .await
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(mailpit.messages().await.len(), 1);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn the_reaper_leaves_a_fresh_pending_report_alone() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());

    let processed = mailpit_service(&repo, &mailpit)
        .await
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(processed, 0);
    assert!(mailpit.messages().await.is_empty());
    assert_eq!(
        history_entry(&repo).await.report_email_status,
        Some(ReportEmailStatus::Pending)
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn two_concurrent_reaper_ticks_send_the_report_once() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());
    strand_pending(&db.pool, "scan-1", "1 hour").await;
    let service = mailpit_service(&repo, &mailpit).await;
    let policy = ReaperPolicy::default();

    let (a, b) = tokio::join!(service.reap_once(&policy), service.reap_once(&policy));

    assert_eq!(a + b, 1, "exactly one tick takes the row");
    assert_eq!(mailpit.messages().await.len(), 1);
    assert_eq!(
        history_entry(&repo).await.report_email_status,
        Some(ReportEmailStatus::Sent)
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn the_reaper_marks_failed_a_stale_report_whose_send_fails() {
    let db = start_db().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());
    strand_pending(&db.pool, "scan-1", "1 hour").await;
    // Nothing listens on this port: every attempt is a transport failure.
    let settings = SmtpSettings {
        host: "127.0.0.1".into(),
        port: 1,
        username: None,
        password: None,
        from: "reports@example.test".into(),
        tls: SmtpTls::None,
    };
    let mailer: Arc<dyn Mailer> = Arc::new(SmtpMailer::new(&settings).expect("mailer"));
    let service = ReportEmailService::new(
        repo.clone(),
        Some(mailer),
        RetryPolicy {
            attempts: 1,
            backoff: Duration::ZERO,
            ..RetryPolicy::default()
        },
    );

    service.reap_once(&ReaperPolicy::default()).await;

    assert_eq!(
        history_entry(&repo).await.report_email_status,
        Some(ReportEmailStatus::Failed)
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn touch_refreshes_the_claim_time_of_a_pending_report_only() {
    let db = start_db().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());
    strand_pending(&db.pool, "scan-1", "1 hour").await;

    repo.touch(&["scan-1".to_string()]).await.expect("touch");
    let age: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM now() - report_email_claimed_at)::float8 FROM scan_history",
    )
    .fetch_one(&db.pool)
    .await
    .expect("age");
    assert!(age < 60.0, "touched, so no longer stale: {age}s");

    repo.finish("scan-1", ReportEmailStatus::Sent, Utc::now())
        .await
        .expect("finish");
    strand_pending(&db.pool, "scan-1", "1 hour").await;
    sqlx::query("UPDATE scan_history SET report_email_status = 'sent'")
        .execute(&db.pool)
        .await
        .expect("sent");
    repo.touch(&["scan-1".to_string()]).await.expect("touch");
    let age: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM now() - report_email_claimed_at)::float8 FROM scan_history",
    )
    .fetch_one(&db.pool)
    .await
    .expect("age");
    assert!(age > 3000.0, "a finished report is left alone: {age}s");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn the_reaper_marks_failed_and_audits_a_row_whose_stored_data_cannot_be_read() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());
    // Corrupt stored data: the CHECK constraint is dropped to simulate it.
    sqlx::query("ALTER TABLE scan_history DROP CONSTRAINT scan_history_scan_mode_check")
        .execute(&db.pool)
        .await
        .expect("drop check");
    sqlx::query("UPDATE scan_history SET scan_mode = 'bogus'")
        .execute(&db.pool)
        .await
        .expect("corrupt");
    strand_pending(&db.pool, "scan-1", "1 hour").await;

    let processed = mailpit_service(&repo, &mailpit)
        .await
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(processed, 0);
    assert!(mailpit.messages().await.is_empty());
    let status: Option<String> = sqlx::query_scalar("SELECT report_email_status FROM scan_history")
        .fetch_one(&db.pool)
        .await
        .expect("status");
    assert_eq!(status.as_deref(), Some("failed"));
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'report.email_failed'")
            .fetch_one(&db.pool)
            .await
            .expect("audits");
    assert_eq!(audits, 1);
}

/// Makes the stored `scan_mode` unreadable, as corrupt data would.
async fn corrupt_scan_mode(pool: &PgPool) {
    sqlx::query("ALTER TABLE scan_history DROP CONSTRAINT scan_history_scan_mode_check")
        .execute(pool)
        .await
        .expect("drop check");
    sqlx::query("UPDATE scan_history SET scan_mode = 'bogus'")
        .execute(pool)
        .await
        .expect("corrupt");
}

async fn report_email_status(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT report_email_status FROM scan_history")
        .fetch_one(pool)
        .await
        .expect("status")
}

async fn failed_audits(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'report.email_failed'")
        .fetch_one(pool)
        .await
        .expect("audits")
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_failed_audit_insert_leaves_an_unreadable_row_pending_without_marking_it_failed() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());
    corrupt_scan_mode(&db.pool).await;
    strand_pending(&db.pool, "scan-1", "1 hour").await;
    // The audit insert fails: `failed` must not be stored without its audit.
    sqlx::query(
        "ALTER TABLE audit_log ADD CONSTRAINT refuse_email_failed \
         CHECK (action <> 'report.email_failed')",
    )
    .execute(&db.pool)
    .await
    .expect("add check");

    let processed = mailpit_service(&repo, &mailpit)
        .await
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(processed, 0);
    assert!(mailpit.messages().await.is_empty());
    assert_eq!(
        report_email_status(&db.pool).await.as_deref(),
        Some("pending")
    );
    assert_eq!(failed_audits(&db.pool).await, 0);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_transient_owner_lookup_error_leaves_the_row_pending_without_an_audit() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    assert!(repo.claim("scan-1").await.expect("claim").is_some());
    strand_pending(&db.pool, "scan-1", "1 hour").await;
    // `find_user` fails with a database error, not "no such user".
    sqlx::query("ALTER TABLE users RENAME TO users_unavailable")
        .execute(&db.pool)
        .await
        .expect("rename");

    let processed = mailpit_service(&repo, &mailpit)
        .await
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(processed, 0);
    assert!(mailpit.messages().await.is_empty());
    assert_eq!(
        report_email_status(&db.pool).await.as_deref(),
        Some("pending")
    );
    assert_eq!(failed_audits(&db.pool).await, 0);
}

/// Forces the report email state of the scan, `age` ago when it has a claim.
async fn set_report_state(pool: &PgPool, status: Option<&str>, age: Option<&str>) {
    sqlx::query(
        "UPDATE scan_history SET report_email_status = $1, \
         report_email_claimed_at = now() - $2::interval",
    )
    .bind(status)
    .bind(age)
    .execute(pool)
    .await
    .expect("set state");
}

const LEASE: Duration = Duration::from_secs(120);

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_for_queue_claims_a_scan_with_no_email_state_and_sets_the_lease() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;

    let claim = repo.claim_for_queue("scan-1", LEASE).await.expect("claim");

    assert_eq!(claim.expect("claimed").recipient, "owner@example.test");
    assert_eq!(
        report_email_status(&db.pool).await.as_deref(),
        Some("pending")
    );
    let age: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM now() - report_email_claimed_at)::float8 FROM scan_history",
    )
    .fetch_one(&db.pool)
    .await
    .expect("age");
    assert!(age < 60.0, "claim time is now: {age}s");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_for_queue_refuses_a_live_lease_and_takes_over_an_expired_one() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;

    set_report_state(&db.pool, Some("pending"), Some("10 seconds")).await;
    assert!(repo
        .claim_for_queue("scan-1", LEASE)
        .await
        .expect("claim")
        .is_none());

    set_report_state(&db.pool, Some("pending"), Some("10 minutes")).await;
    assert!(repo
        .claim_for_queue("scan-1", LEASE)
        .await
        .expect("claim")
        .is_some());
    // The takeover refreshed the lease: a second consumer is refused.
    assert!(repo
        .claim_for_queue("scan-1", LEASE)
        .await
        .expect("claim")
        .is_none());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_for_queue_takes_a_pending_row_without_a_claim_time() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    set_report_state(&db.pool, Some("pending"), None).await;

    assert!(repo
        .claim_for_queue("scan-1", LEASE)
        .await
        .expect("claim")
        .is_some());
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_for_queue_claims_a_failed_row_again() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    set_report_state(&db.pool, Some("failed"), Some("10 minutes")).await;

    assert!(repo
        .claim_for_queue("scan-1", LEASE)
        .await
        .expect("claim")
        .is_some());
    assert_eq!(
        report_email_status(&db.pool).await.as_deref(),
        Some("pending")
    );
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_for_queue_never_claims_a_final_row() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;

    for status in ["sent", "disabled"] {
        set_report_state(&db.pool, Some(status), Some("10 hours")).await;
        assert!(
            repo.claim_for_queue("scan-1", LEASE)
                .await
                .expect("claim")
                .is_none(),
            "{status} is final"
        );
        assert_eq!(report_email_status(&db.pool).await.as_deref(), Some(status));
    }
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_for_queue_ignores_a_scan_that_is_not_completed_or_unknown() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Fallido).await;

    assert!(repo
        .claim_for_queue("scan-1", LEASE)
        .await
        .expect("claim")
        .is_none());
    assert!(repo
        .claim_for_queue("missing", LEASE)
        .await
        .expect("claim")
        .is_none());
    assert_eq!(report_email_status(&db.pool).await, None);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn two_concurrent_queue_claims_have_exactly_one_winner() {
    let db = start_db().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;

    let (a, b) = tokio::join!(
        repo.claim_for_queue("scan-1", LEASE),
        repo.claim_for_queue("scan-1", LEASE)
    );

    let wins = [a.expect("claim a"), b.expect("claim b")]
        .into_iter()
        .flatten()
        .count();
    assert_eq!(wins, 1);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn claim_for_queue_stores_failed_and_audits_a_row_whose_data_cannot_be_read() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    corrupt_scan_mode(&db.pool).await;

    let claim = repo.claim_for_queue("scan-1", LEASE).await.expect("claim");

    assert!(claim.is_none());
    assert_eq!(
        report_email_status(&db.pool).await.as_deref(),
        Some("failed")
    );
    assert_eq!(failed_audits(&db.pool).await, 1);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_queue_request_sends_the_email_once_and_a_duplicate_is_done_without_sending() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    let service = mailpit_service(&repo, &mailpit).await;

    let first = service.handle_request("scan-1", 1, 3, LEASE).await;
    let second = service.handle_request("scan-1", 2, 3, LEASE).await;

    assert_eq!(first, QueueOutcome::Done);
    assert_eq!(second, QueueOutcome::Done);
    assert_eq!(mailpit.messages().await.len(), 1);
    assert_eq!(report_email_status(&db.pool).await.as_deref(), Some("sent"));
}

// --- Report email queue (RF-20): LocalStack SQS + Postgres + Mailpit ---

/// Visibility timeout of the test queue: small, so redeliveries are quick.
const TEST_VISIBILITY_SECS: u32 = 2;
const TEST_MAX_RECEIVES: u32 = 3;

struct QueueRig {
    localstack: common::LocalStack,
    urls: common::QueueUrls,
    publisher: SqsReportEmailPublisher,
}

async fn start_queue() -> QueueRig {
    let localstack = common::LocalStack::start().await;
    let urls = localstack
        .create_queue_with_dlq(
            "user-service-report-emails",
            TEST_VISIBILITY_SECS,
            TEST_MAX_RECEIVES,
        )
        .await;
    let publisher =
        SqsReportEmailPublisher::from_client(localstack.sqs.clone(), urls.queue_url.clone());
    QueueRig {
        localstack,
        urls,
        publisher,
    }
}

struct RunningConsumer {
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl RunningConsumer {
    async fn stop(self) {
        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("the consumer stops promptly on cancellation")
            .expect("the consumer task does not panic");
    }
}

async fn spawn_consumer(rig: &QueueRig, service: Arc<ReportEmailService>) -> RunningConsumer {
    let client = rig.localstack.sqs.clone();
    let settings = load_queue_settings(&client, &rig.urls.queue_url)
        .await
        .expect("queue attributes");
    assert_eq!(
        settings.visibility_timeout,
        Duration::from_secs(TEST_VISIBILITY_SECS.into())
    );
    assert_eq!(settings.max_receives, TEST_MAX_RECEIVES);
    let consumer = SqsReportEmailConsumer::from_client(
        client,
        rig.urls.queue_url.clone(),
        rig.urls.dlq_url.clone(),
        settings,
    );
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(consumer.run(service, shutdown.clone()));
    RunningConsumer { shutdown, task }
}

/// Bodies that reach the DLQ within `secs` seconds; panics if none does.
async fn dlq_bodies(rig: &QueueRig, secs: u32) -> Vec<String> {
    for _ in 0..secs {
        let bodies = rig.localstack.receive_bodies(&rig.urls.dlq_url, 1).await;
        if !bodies.is_empty() {
            return bodies;
        }
    }
    panic!("nothing reached the DLQ in {secs}s");
}

/// Polls `condition` every 200 ms for up to `secs` seconds.
async fn eventually<F, Fut>(secs: u64, what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..(secs * 5) {
        if condition().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_published_request_emails_the_owner_once_and_the_message_is_deleted() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let rig = start_queue().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    let consumer = spawn_consumer(&rig, mailpit_service(&repo, &mailpit).await).await;

    rig.publisher.publish("scan-1").await.expect("publish");

    eventually(30, "the email in Mailpit", || async {
        mailpit.messages().await.len() == 1
    })
    .await;
    eventually(15, "the message deleted", || async {
        rig.localstack.queue_depth(&rig.urls.queue_url).await == 0
    })
    .await;
    assert_eq!(
        mailpit.messages().await[0]["To"][0]["Address"],
        "owner@example.test"
    );
    assert_eq!(
        history_entry(&repo).await.report_email_status,
        Some(ReportEmailStatus::Sent)
    );
    assert_eq!(rig.localstack.queue_depth(&rig.urls.dlq_url).await, 0);
    consumer.stop().await;
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_duplicate_request_sends_one_email() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let rig = start_queue().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    let consumer = spawn_consumer(&rig, mailpit_service(&repo, &mailpit).await).await;

    rig.publisher.publish("scan-1").await.expect("publish");
    rig.publisher
        .publish("scan-1")
        .await
        .expect("publish again");

    eventually(30, "both messages consumed", || async {
        rig.localstack.queue_depth(&rig.urls.queue_url).await == 0
    })
    .await;
    // Let a (wrong) second send show up before asserting there is only one.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(mailpit.messages().await.len(), 1);
    let audit = repo.list_audit_entries("owner-sub").await.expect("audit");
    assert_eq!(
        audit
            .iter()
            .filter(|e| e.action() == "report.emailed")
            .count(),
        1
    );
    consumer.stop().await;
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_malformed_message_goes_to_the_dlq_and_leaves_the_queue() {
    let db = start_db().await;
    let mailpit = start_mailpit().await;
    let rig = start_queue().await;
    let repo = Arc::new(repository(&db.pool));
    let consumer = spawn_consumer(&rig, mailpit_service(&repo, &mailpit).await).await;
    let body = r#"{"scan_id":"scan-1","unexpected":true}"#;

    rig.localstack
        .sqs
        .send_message()
        .queue_url(&rig.urls.queue_url)
        .message_body(body)
        .send()
        .await
        .expect("send");

    let dlq = dlq_bodies(&rig, 30).await;
    assert_eq!(dlq, [body]);
    eventually(15, "the queue empty", || async {
        rig.localstack.queue_depth(&rig.urls.queue_url).await == 0
    })
    .await;
    assert!(mailpit.messages().await.is_empty());
    consumer.stop().await;
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn a_failing_mailer_is_retried_by_the_queue_then_fails_the_row_and_redrives_to_the_dlq() {
    let db = start_db().await;
    let rig = start_queue().await;
    let repo = Arc::new(repository(&db.pool));
    seed_scan(&repo, "scan-1", ScanStatus::Completado).await;
    let mailer = Arc::new(InMemoryMailer::failing_first(usize::MAX));
    let service = Arc::new(ReportEmailService::new(
        repo.clone(),
        Some(mailer.clone() as Arc<dyn Mailer>),
        RetryPolicy::default(),
    ));
    let consumer = spawn_consumer(&rig, service).await;

    rig.publisher.publish("scan-1").await.expect("publish");

    // One attempt per receive: three receives, three attempts, then `failed`.
    eventually(60, "the row marked failed", || async {
        history_entry(&repo).await.report_email_status == Some(ReportEmailStatus::Failed)
    })
    .await;
    assert_eq!(mailer.attempts(), TEST_MAX_RECEIVES as usize);
    let dlq = dlq_bodies(&rig, 30).await;
    assert!(dlq[0].contains("scan-1"));
    let audit = repo.list_audit_entries("owner-sub").await.expect("audit");
    assert_eq!(
        audit
            .iter()
            .filter(|e| e.action() == "report.email_failed")
            .count(),
        1
    );
    consumer.stop().await;
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn cancelling_the_token_stops_the_consumer_during_a_long_poll() {
    let db = start_db().await;
    let rig = start_queue().await;
    let repo = Arc::new(repository(&db.pool));
    let service = Arc::new(ReportEmailService::new(repo, None, RetryPolicy::default()));
    let consumer = spawn_consumer(&rig, service).await;
    // Let it enter the 20 s long poll on the empty queue.
    tokio::time::sleep(Duration::from_secs(1)).await;

    consumer.stop().await;
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn patching_to_completed_publishes_a_request_without_sending_in_process() {
    let db = start_db().await;
    let rig = start_queue().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::EnProgreso).await;
    let mailer = Arc::new(InMemoryMailer::default());

    let publisher: Arc<dyn ReportEmailRequestPublisher> = Arc::new(rig.publisher.clone());
    patch_completed(repo, mailer.clone(), Some(publisher)).await;

    let bodies = rig.localstack.receive_bodies(&rig.urls.queue_url, 5).await;
    assert_eq!(bodies.len(), 1);
    let request: Value = serde_json::from_str(&bodies[0]).expect("json");
    assert_eq!(request["scan_id"], "scan-1");
    assert!(request["requested_at"].is_string());
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(mailer.attempts(), 0);
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn patching_to_completed_falls_back_to_the_in_process_send_when_the_publish_fails() {
    let db = start_db().await;
    let repo = repository(&db.pool);
    seed_scan(&repo, "scan-1", ScanStatus::EnProgreso).await;
    let mailer = Arc::new(InMemoryMailer::default());

    let publisher: Arc<dyn ReportEmailRequestPublisher> = Arc::new(RecordingPublisher::failing());
    patch_completed(repo, mailer.clone(), Some(publisher)).await;

    eventually(15, "the in-process email", || async {
        mailer.sent().len() == 1
    })
    .await;
}

/// `PATCH /scans/scan-1` with `COMPLETADO` through a router with `publisher`.
async fn patch_completed(
    repo: Repository,
    mailer: Arc<InMemoryMailer>,
    publisher: Option<Arc<dyn ReportEmailRequestPublisher>>,
) {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use user_service::api::{self, FORWARDED_USER_HEADER, GATEWAY_SECRET_HEADER};

    let app = api::router_with_report_queue(
        Arc::new(repo),
        "gateway-secret".to_string().into(),
        Some((Some(mailer as Arc<dyn Mailer>), RetryPolicy::default())),
        publisher,
    );
    let identity = json!({"sub": "owner-sub", "email": "owner@example.test"}).to_string();
    let result = json!({
        "host": "192.0.2.10", "ports": [], "vulnerabilities": [],
        "scanned_at": "2026-11-20T15:30:00Z"
    });
    let request = Request::builder()
        .method("PATCH")
        .uri("/scans/scan-1")
        .header(GATEWAY_SECRET_HEADER, "gateway-secret")
        .header(FORWARDED_USER_HEADER, &identity)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"status": "COMPLETADO", "result": result}).to_string(),
        ))
        .unwrap();
    let response = app.oneshot(request).await.expect("patch");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
