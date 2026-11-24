//! Integration tests of the report email (EM-02) against a real Postgres and a
//! real Mailpit SMTP sink (`axllent/mailpit`), both started with
//! `testcontainers`. Marked `#[ignore = "requiere Docker"]`: run them with
//! `cargo test -- --ignored` (`make test-integration`).

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

use user_service::domain::{
    ReportEmailStatus, Role, ScanHistoryEntry, ScanMode, ScanStatus, UserProfile,
};
use user_service::report_email::mailer::{Mailer, MailerError, OutgoingEmail};
use user_service::report_email::service::{
    ReaperPolicy, ReportEmailService, ReportEmailStore, RetryPolicy,
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
