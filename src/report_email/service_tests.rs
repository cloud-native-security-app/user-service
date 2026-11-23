//! Unit tests of the send-on-completion flow with in-memory fakes (no Docker).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;

use super::mailer::{InMemoryMailer, Mailer};
use super::service::{
    ClaimedReport, ReaperPolicy, ReportEmailService, ReportEmailStore, RetryPolicy,
};
use crate::audit::{REPORT_EMAILED_ACTION, REPORT_EMAIL_FAILED_ACTION};
use crate::domain::{ReportEmailStatus, ScanMode};
use crate::repository::RepoError;

const OWNER_EMAIL: &str = "owner@example.test";

fn claimed(scan_id: &str) -> ClaimedReport {
    ClaimedReport {
        scan_id: scan_id.to_string(),
        user_id: "owner-sub".to_string(),
        recipient: OWNER_EMAIL.to_string(),
        target: "10.0.0.5".to_string(),
        mode: ScanMode::Ssh,
        finished_at: Utc.with_ymd_and_hms(2026, 11, 20, 15, 30, 0).unwrap(),
        result: Some(json!({"vulnerabilities": [], "host": "10.0.0.5", "ports": []})),
    }
}

#[derive(Default)]
struct StoreState {
    /// Scan ids whose report email was already claimed.
    claimed: Vec<String>,
    /// Scan ids left `pending` long enough for the reaper to take them.
    stale: Vec<String>,
    statuses: Vec<(String, ReportEmailStatus)>,
    audits: Vec<(String, String, String)>,
}

/// In-memory store: `completed` scans can be claimed once, like the SQL claim.
struct FakeStore {
    completed: Vec<String>,
    state: Mutex<StoreState>,
}

impl FakeStore {
    fn with_completed(scan_id: &str) -> Arc<Self> {
        Arc::new(Self {
            completed: vec![scan_id.to_string()],
            state: Mutex::default(),
        })
    }

    fn with_stale(scan_ids: &[&str]) -> Arc<Self> {
        let store = Self::with_completed("unused");
        store.state.lock().unwrap().stale = scan_ids.iter().map(|s| s.to_string()).collect();
        store
    }

    fn statuses(&self) -> Vec<(String, ReportEmailStatus)> {
        self.state.lock().unwrap().statuses.clone()
    }

    fn last_status(&self) -> Option<ReportEmailStatus> {
        self.state.lock().unwrap().statuses.last().map(|s| s.1)
    }

    fn audit_actions(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state.audits.iter().map(|a| a.1.clone()).collect()
    }
}

#[async_trait]
impl ReportEmailStore for FakeStore {
    async fn claim(&self, scan_id: &str) -> Result<Option<ClaimedReport>, RepoError> {
        let mut state = self.state.lock().unwrap();
        if !self.completed.iter().any(|s| s == scan_id)
            || state.claimed.iter().any(|s| s == scan_id)
        {
            return Ok(None);
        }
        state.claimed.push(scan_id.to_string());
        Ok(Some(claimed(scan_id)))
    }

    async fn reclaim_stale(
        &self,
        _older_than: Duration,
        limit: u32,
    ) -> Result<Vec<ClaimedReport>, RepoError> {
        let mut state = self.state.lock().unwrap();
        let take = state.stale.len().min(limit as usize);
        let ids: Vec<String> = state.stale.drain(..take).collect();
        Ok(ids.into_iter().map(|id| claimed(&id)).collect())
    }

    async fn finish(
        &self,
        scan_id: &str,
        status: ReportEmailStatus,
        _at: DateTime<Utc>,
    ) -> Result<(), RepoError> {
        self.state
            .lock()
            .unwrap()
            .statuses
            .push((scan_id.to_string(), status));
        Ok(())
    }

    async fn audit(&self, user_id: &str, action: &str, scan_id: &str) -> Result<(), RepoError> {
        self.state.lock().unwrap().audits.push((
            user_id.to_string(),
            action.to_string(),
            scan_id.to_string(),
        ));
        Ok(())
    }
}

fn service(
    store: &Arc<FakeStore>,
    mailer: Option<&Arc<InMemoryMailer>>,
) -> Arc<ReportEmailService> {
    let store: Arc<dyn ReportEmailStore> = store.clone();
    let mailer: Option<Arc<dyn Mailer>> = mailer.map(|m| m.clone() as Arc<dyn Mailer>);
    Arc::new(ReportEmailService::new(
        store,
        mailer,
        RetryPolicy {
            attempts: 3,
            backoff: Duration::ZERO,
        },
    ))
}

#[tokio::test]
async fn completed_scan_sends_one_email_to_the_owner_account_with_the_attachment() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::default());

    service(&store, Some(&mailer))
        .process_completed("scan-1")
        .await;

    let sent = mailer.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, OWNER_EMAIL);
    assert!(sent[0].html.contains("<html"));
    assert!(!sent[0].text.is_empty());
    assert_eq!(sent[0].attachment.filename, "reporte-escaneo-scan-1.json");
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Sent));
    assert_eq!(store.audit_actions(), [REPORT_EMAILED_ACTION]);
}

#[tokio::test]
async fn redelivery_of_the_same_completed_outcome_still_sends_one_email() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::default());
    let service = service(&store, Some(&mailer));

    service.process_completed("scan-1").await;
    service.process_completed("scan-1").await;

    assert_eq!(mailer.sent().len(), 1);
}

#[tokio::test]
async fn a_scan_that_is_not_completed_sends_nothing() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::default());

    service(&store, Some(&mailer))
        .process_completed("failed-scan")
        .await;

    assert!(mailer.sent().is_empty());
    assert_eq!(store.last_status(), None);
}

#[tokio::test]
async fn smtp_not_configured_marks_disabled_and_sends_nothing() {
    let store = FakeStore::with_completed("scan-1");

    service(&store, None).process_completed("scan-1").await;

    assert_eq!(store.last_status(), Some(ReportEmailStatus::Disabled));
    assert!(store.audit_actions().is_empty());
}

#[tokio::test]
async fn a_mailer_failing_every_attempt_marks_failed_and_audits_the_failure() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::failing_first(usize::MAX));

    service(&store, Some(&mailer))
        .process_completed("scan-1")
        .await;

    assert_eq!(mailer.attempts(), 3);
    assert!(mailer.sent().is_empty());
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Failed));
    assert_eq!(store.audit_actions(), [REPORT_EMAIL_FAILED_ACTION]);
}

#[tokio::test]
async fn a_transient_failure_then_success_marks_sent() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::failing_first(2));

    service(&store, Some(&mailer))
        .process_completed("scan-1")
        .await;

    assert_eq!(mailer.attempts(), 3);
    assert_eq!(mailer.sent().len(), 1);
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Sent));
    assert_eq!(store.audit_actions(), [REPORT_EMAILED_ACTION]);
}

#[tokio::test]
async fn the_audit_entry_names_the_scan_and_never_carries_the_email_body() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::default());

    service(&store, Some(&mailer))
        .process_completed("scan-1")
        .await;

    let state = store.state.lock().unwrap();
    assert_eq!(
        state.audits,
        [(
            "owner-sub".to_string(),
            REPORT_EMAILED_ACTION.to_string(),
            "scan-1".to_string()
        )]
    );
}

#[tokio::test]
async fn the_reaper_sends_a_stale_pending_report_and_marks_it_sent() {
    let store = FakeStore::with_stale(&["scan-1"]);
    let mailer = Arc::new(InMemoryMailer::default());

    let processed = service(&store, Some(&mailer))
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(processed, 1);
    assert_eq!(mailer.sent().len(), 1);
    assert_eq!(mailer.sent()[0].to, OWNER_EMAIL);
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Sent));
    assert_eq!(store.audit_actions(), [REPORT_EMAILED_ACTION]);
}

#[tokio::test]
async fn the_reaper_marks_failed_and_audits_when_the_send_keeps_failing() {
    let store = FakeStore::with_stale(&["scan-1"]);
    let mailer = Arc::new(InMemoryMailer::failing_first(usize::MAX));

    service(&store, Some(&mailer))
        .reap_once(&ReaperPolicy::default())
        .await;

    assert!(mailer.sent().is_empty());
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Failed));
    assert_eq!(store.audit_actions(), [REPORT_EMAIL_FAILED_ACTION]);
}

#[tokio::test]
async fn the_reaper_takes_at_most_one_batch_per_tick() {
    let store = FakeStore::with_stale(&["a", "b", "c"]);
    let mailer = Arc::new(InMemoryMailer::default());
    let policy = ReaperPolicy {
        batch: 2,
        ..ReaperPolicy::default()
    };
    let service = service(&store, Some(&mailer));

    assert_eq!(service.reap_once(&policy).await, 2);
    assert_eq!(store.statuses().len(), 2);
    assert_eq!(service.reap_once(&policy).await, 1);
    assert_eq!(mailer.sent().len(), 3);
}

#[tokio::test]
async fn the_reaper_has_nothing_to_do_when_no_report_is_stale() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::default());

    let processed = service(&store, Some(&mailer))
        .reap_once(&ReaperPolicy::default())
        .await;

    assert_eq!(processed, 0);
    assert!(mailer.sent().is_empty());
}

#[test]
fn the_reaper_defaults_are_ten_minutes_every_minute() {
    let policy = ReaperPolicy::default();
    assert_eq!(policy.after, Duration::from_secs(600));
    assert_eq!(policy.interval, Duration::from_secs(60));
    assert!(policy.batch >= 1);
}
