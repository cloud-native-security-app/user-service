//! Unit tests of the send-on-completion flow with in-memory fakes (no Docker).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;
use tokio::time::Instant;

use super::mailer::{InMemoryMailer, Mailer, MailerError, OutgoingEmail};
use super::service::{
    ClaimedReport, QueueOutcome, ReaperPolicy, ReportEmailService, ReportEmailStore, RetryPolicy,
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
    /// When each claimed scan was last claimed, re-claimed or touched.
    claim_times: HashMap<String, Instant>,
    /// How many times the reaper asked for stale reports.
    reclaim_calls: usize,
    /// Rows as the queue claim sees them: status and last claim time.
    rows: HashMap<String, (Option<ReportEmailStatus>, Option<Instant>)>,
    /// Makes `claim_for_queue` fail with a store error.
    fail_queue_claim: bool,
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

    /// A completed scan already in `status`, claimed just now when `claimed`.
    fn with_row(scan_id: &str, status: Option<ReportEmailStatus>, claimed: bool) -> Arc<Self> {
        let store = Self::with_completed(scan_id);
        let at = claimed.then(Instant::now);
        store
            .state
            .lock()
            .unwrap()
            .rows
            .insert(scan_id.to_string(), (status, at));
        store
    }

    fn row_status(&self, scan_id: &str) -> Option<ReportEmailStatus> {
        let state = self.state.lock().unwrap();
        state.rows.get(scan_id).and_then(|row| row.0)
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
        state
            .claim_times
            .insert(scan_id.to_string(), Instant::now());
        Ok(Some(claimed(scan_id)))
    }

    async fn claim_for_queue(
        &self,
        scan_id: &str,
        lease: Duration,
    ) -> Result<Option<ClaimedReport>, RepoError> {
        let mut state = self.state.lock().unwrap();
        if state.fail_queue_claim {
            return Err(RepoError::ConnectionFailed);
        }
        if !self.completed.iter().any(|s| s == scan_id) {
            return Ok(None);
        }
        let now = Instant::now();
        let (status, claimed_at) = state.rows.get(scan_id).copied().unwrap_or((None, None));
        let leased = claimed_at.is_some_and(|at| now.duration_since(at) < lease);
        let claimable = match status {
            None => !leased,
            Some(ReportEmailStatus::Pending | ReportEmailStatus::Failed) => !leased,
            Some(ReportEmailStatus::Sent | ReportEmailStatus::Disabled) => false,
        };
        if !claimable {
            return Ok(None);
        }
        state.rows.insert(
            scan_id.to_string(),
            (Some(ReportEmailStatus::Pending), Some(now)),
        );
        Ok(Some(claimed(scan_id)))
    }

    async fn reclaim_stale(
        &self,
        older_than: Duration,
        limit: u32,
    ) -> Result<Vec<ClaimedReport>, RepoError> {
        let mut state = self.state.lock().unwrap();
        state.reclaim_calls += 1;
        let take = state.stale.len().min(limit as usize);
        let mut ids: Vec<String> = state.stale.drain(..take).collect();
        let now = Instant::now();
        let mut aged: Vec<String> = state
            .claim_times
            .iter()
            .filter(|(id, at)| {
                now.duration_since(**at) >= older_than
                    && !state.statuses.iter().any(|(done, _)| done == *id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        aged.sort();
        aged.truncate((limit as usize).saturating_sub(ids.len()));
        ids.extend(aged);
        for id in &ids {
            state.claim_times.insert(id.clone(), now);
        }
        Ok(ids.into_iter().map(|id| claimed(&id)).collect())
    }

    async fn touch(&self, scan_ids: &[String]) -> Result<(), RepoError> {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        for id in scan_ids {
            let pending = !state.statuses.iter().any(|(done, _)| done == id);
            if pending {
                if let Some(at) = state.claim_times.get_mut(id) {
                    *at = now;
                }
            }
        }
        Ok(())
    }

    async fn finish(
        &self,
        scan_id: &str,
        status: ReportEmailStatus,
        _at: DateTime<Utc>,
    ) -> Result<(), RepoError> {
        let mut state = self.state.lock().unwrap();
        state.statuses.push((scan_id.to_string(), status));
        if let Some(row) = state.rows.get_mut(scan_id) {
            row.0 = Some(status);
        }
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
            ..RetryPolicy::default()
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

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Mailer that takes `delay` per attempt and fails the first `fail_first`.
struct SlowMailer {
    delay: Duration,
    fail_first: usize,
    hang_first: usize,
    attempts: Mutex<usize>,
    sent: Mutex<usize>,
}

impl SlowMailer {
    fn new(delay: Duration, fail_first: usize) -> Arc<Self> {
        Arc::new(Self {
            delay,
            fail_first,
            hang_first: 0,
            attempts: Mutex::new(0),
            sent: Mutex::new(0),
        })
    }

    fn sent(&self) -> usize {
        *self.sent.lock().unwrap()
    }

    fn attempts(&self) -> usize {
        *self.attempts.lock().unwrap()
    }

    /// Mailer whose first `hang` attempts never answer; later ones take `delay`.
    fn hanging_first(hang: usize, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            delay,
            fail_first: 0,
            hang_first: hang,
            attempts: Mutex::new(0),
            sent: Mutex::new(0),
        })
    }
}

#[async_trait]
impl Mailer for SlowMailer {
    async fn send(&self, _email: &OutgoingEmail) -> Result<(), MailerError> {
        let attempt = {
            let mut attempts = self.attempts.lock().unwrap();
            *attempts += 1;
            *attempts
        };
        if attempt <= self.hang_first {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(self.delay).await;
        if attempt <= self.fail_first {
            return Err(MailerError::Transport);
        }
        *self.sent.lock().unwrap() += 1;
        Ok(())
    }
}

fn slow_service(
    store: &Arc<FakeStore>,
    mailer: &Arc<SlowMailer>,
    backoff: Duration,
) -> Arc<ReportEmailService> {
    let store: Arc<dyn ReportEmailStore> = store.clone();
    let mailer: Arc<dyn Mailer> = mailer.clone();
    Arc::new(ReportEmailService::new(
        store,
        Some(mailer),
        RetryPolicy {
            attempts: 3,
            backoff,
            ..RetryPolicy::default()
        },
    ))
}

/// Runs `reap_once` every `every` seconds `ticks` times, returning how many
/// reports the ticks took in total.
async fn reap_repeatedly(
    service: &ReportEmailService,
    policy: &ReaperPolicy,
    every: u64,
    ticks: u64,
) -> usize {
    let mut taken = 0;
    for _ in 0..ticks {
        tokio::time::sleep(secs(every)).await;
        taken += service.reap_once(policy).await;
    }
    taken
}

#[tokio::test(start_paused = true)]
async fn a_send_that_outlasts_the_threshold_is_not_taken_by_the_reaper() {
    // First attempt 0-20s fails, 5s backoff, second attempt 25-45s succeeds:
    // the send lasts 45s, longer than the 30s threshold.
    let store = FakeStore::with_completed("scan-1");
    let mailer = SlowMailer::new(secs(20), 1);
    let service = slow_service(&store, &mailer, secs(5));
    let policy = ReaperPolicy {
        after: secs(30),
        ..ReaperPolicy::default()
    };

    let (_, taken) = tokio::join!(
        service.process_completed("scan-1"),
        reap_repeatedly(&service, &policy, 10, 6)
    );

    assert_eq!(taken, 0, "a live sender is never stale");
    assert_eq!(mailer.sent(), 1);
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Sent));
}

#[tokio::test(start_paused = true)]
async fn the_rows_queued_behind_a_slow_batch_are_not_taken_by_another_reaper() {
    // Three reports re-claimed at t=0, 20s each, one after another: the third
    // starts at 40s, past the 30s threshold of its original claim.
    let store = FakeStore::with_stale(&["a", "b", "c"]);
    let mailer = SlowMailer::new(secs(20), 0);
    let service = slow_service(&store, &mailer, Duration::ZERO);
    let policy = ReaperPolicy {
        after: secs(30),
        ..ReaperPolicy::default()
    };

    let (first, second) = tokio::join!(service.reap_once(&policy), async {
        tokio::time::sleep(secs(35)).await;
        service.reap_once(&policy).await
    });

    assert_eq!((first, second), (3, 0));
    assert_eq!(mailer.sent(), 3);
}

#[tokio::test(start_paused = true)]
async fn the_reaper_ticks_at_the_configured_interval_and_reaps() {
    let store = FakeStore::with_stale(&["scan-1"]);
    let mailer = Arc::new(InMemoryMailer::default());
    let policy = ReaperPolicy {
        interval: secs(10),
        ..ReaperPolicy::default()
    };

    service(&store, Some(&mailer)).spawn_reaper(policy);
    tokio::time::sleep(secs(25)).await;

    // Ticks at 0s, 10s and 20s.
    assert_eq!(store.state.lock().unwrap().reclaim_calls, 3);
    assert_eq!(mailer.sent().len(), 1);
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Sent));
}

#[tokio::test(start_paused = true)]
async fn the_reaper_does_not_start_without_a_mailer() {
    let store = FakeStore::with_stale(&["scan-1"]);

    service(&store, None).spawn_reaper(ReaperPolicy::default());
    tokio::time::sleep(secs(300)).await;

    assert_eq!(store.state.lock().unwrap().reclaim_calls, 0);
    assert!(store.statuses().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_zero_interval_does_not_panic_the_reaper_and_ticks_every_second() {
    let store = FakeStore::with_stale(&[]);
    let mailer = Arc::new(InMemoryMailer::default());
    let policy = ReaperPolicy {
        interval: Duration::ZERO,
        ..ReaperPolicy::default()
    };

    service(&store, Some(&mailer)).spawn_reaper(policy);
    tokio::time::sleep(Duration::from_millis(3500)).await;

    // Clamped to one second: ticks at 0s, 1s, 2s and 3s.
    assert_eq!(store.state.lock().unwrap().reclaim_calls, 4);
}

fn retry(attempts: u32, backoff: u64, attempt_timeout: u64) -> RetryPolicy {
    RetryPolicy {
        attempts,
        backoff: secs(backoff),
        attempt_timeout: secs(attempt_timeout),
    }
}

fn service_with(
    store: &Arc<FakeStore>,
    mailer: &Arc<SlowMailer>,
    retry: RetryPolicy,
) -> Arc<ReportEmailService> {
    let store: Arc<dyn ReportEmailStore> = store.clone();
    let mailer: Arc<dyn Mailer> = mailer.clone();
    Arc::new(ReportEmailService::new(store, Some(mailer), retry))
}

#[test]
fn the_default_attempt_deadline_is_sixty_seconds() {
    assert_eq!(RetryPolicy::default().attempt_timeout, secs(60));
}

#[test]
fn the_reaper_minimum_is_the_deadline_plus_the_largest_backoff_wait() {
    // Waits between attempts: 2s, 4s. The largest is 4s.
    assert_eq!(RetryPolicy::default().max_refresh_gap(), secs(64));
    // Waits: 2s, 4s, 8s.
    assert_eq!(retry(4, 2, 60).max_refresh_gap(), secs(68));
    // One attempt never waits.
    assert_eq!(retry(1, 30, 60).max_refresh_gap(), secs(60));
    // Zero attempts still run once.
    assert_eq!(retry(0, 30, 60).max_refresh_gap(), secs(60));
}

#[test]
fn the_largest_backoff_wait_does_not_overflow() {
    let policy = RetryPolicy {
        attempts: u32::MAX,
        backoff: Duration::MAX,
        attempt_timeout: secs(60),
    };
    assert!(policy.max_refresh_gap() >= secs(60));
}

#[tokio::test(start_paused = true)]
async fn a_hung_attempt_is_cut_at_the_deadline_and_counted_as_failed() {
    // Every attempt hangs: cut at 10s, wait 5s, cut at 10s again.
    let store = FakeStore::with_completed("scan-1");
    let mailer = SlowMailer::new(secs(3600), 0);
    let service = service_with(&store, &mailer, retry(2, 5, 10));
    let started = Instant::now();

    service.process_completed("scan-1").await;

    assert_eq!(started.elapsed(), secs(25));
    assert_eq!(mailer.attempts(), 2);
    assert_eq!(mailer.sent(), 0);
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Failed));
    assert_eq!(store.audit_actions(), vec![REPORT_EMAIL_FAILED_ACTION]);
}

#[tokio::test(start_paused = true)]
async fn a_hung_attempt_is_retried_and_a_later_one_can_succeed() {
    // The first attempt hangs, the second answers in 1s.
    let store = FakeStore::with_completed("scan-1");
    let mailer = SlowMailer::hanging_first(1, secs(1));
    let service = service_with(&store, &mailer, retry(3, 5, 10));

    service.process_completed("scan-1").await;

    assert_eq!(mailer.attempts(), 2);
    assert_eq!(mailer.sent(), 1);
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Sent));
}

#[tokio::test(start_paused = true)]
async fn a_slow_but_live_sender_is_never_taken_by_the_reaper_at_the_minimum() {
    // Default policy: 60s deadline, waits 2s and 4s. Attempts take 50s and
    // fail, so the claim is refreshed at 0s, 52s and 106s: gaps of 52s and
    // 54s, under the 65s minimum threshold.
    let store = FakeStore::with_completed("scan-1");
    let mailer = SlowMailer::new(secs(50), 2);
    let retry = RetryPolicy::default();
    let service = service_with(&store, &mailer, retry);
    let policy = ReaperPolicy {
        after: retry.max_refresh_gap() + secs(1),
        ..ReaperPolicy::default()
    };

    let (_, taken) = tokio::join!(
        service.process_completed("scan-1"),
        reap_repeatedly(&service, &policy, 5, 40)
    );

    assert_eq!(taken, 0, "the heartbeat gap stays under `after`");
    assert_eq!(mailer.sent(), 1);
    assert_eq!(store.last_status(), Some(ReportEmailStatus::Sent));
}

// --- Queue consumer: one attempt per receive (RF-20) ---

const LEASE: Duration = Duration::from_secs(120);

async fn handle(
    service: &ReportEmailService,
    receive_count: u32,
    max_receives: u32,
) -> QueueOutcome {
    service
        .handle_request("scan-1", receive_count, max_receives, LEASE)
        .await
}

#[tokio::test(start_paused = true)]
async fn a_queue_request_sends_one_email_marks_sent_and_audits() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::default());

    let outcome = handle(&service(&store, Some(&mailer)), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Done);
    assert_eq!(mailer.sent().len(), 1);
    assert_eq!(store.row_status("scan-1"), Some(ReportEmailStatus::Sent));
    assert_eq!(store.audit_actions(), [REPORT_EMAILED_ACTION]);
}

#[tokio::test(start_paused = true)]
async fn a_transient_failure_before_the_last_receive_stays_pending_and_retries() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::failing_first(usize::MAX));

    let outcome = handle(&service(&store, Some(&mailer)), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Retry);
    assert_eq!(mailer.attempts(), 1, "exactly one attempt per receive");
    assert_eq!(store.row_status("scan-1"), Some(ReportEmailStatus::Pending));
    assert!(store.statuses().is_empty());
    assert!(store.audit_actions().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_failure_on_the_last_receive_marks_failed_audits_and_still_retries() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = Arc::new(InMemoryMailer::failing_first(usize::MAX));

    let outcome = handle(&service(&store, Some(&mailer)), 3, 3).await;

    // Retry keeps the message, so the redrive policy moves it to the DLQ.
    assert_eq!(outcome, QueueOutcome::Retry);
    assert_eq!(store.row_status("scan-1"), Some(ReportEmailStatus::Failed));
    assert_eq!(store.audit_actions(), [REPORT_EMAIL_FAILED_ACTION]);
}

#[tokio::test(start_paused = true)]
async fn a_hung_attempt_counts_as_a_failure_cut_at_the_deadline() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = SlowMailer::new(secs(3600), 0);
    let service = service_with(&store, &mailer, retry(3, 5, 10));
    let started = Instant::now();

    let outcome = handle(&service, 2, 3).await;

    assert_eq!(outcome, QueueOutcome::Retry);
    assert_eq!(started.elapsed(), secs(10));
    assert_eq!(mailer.attempts(), 1);
    assert_eq!(store.row_status("scan-1"), Some(ReportEmailStatus::Pending));
}

#[tokio::test(start_paused = true)]
async fn a_hung_attempt_on_the_last_receive_marks_failed() {
    let store = FakeStore::with_completed("scan-1");
    let mailer = SlowMailer::new(secs(3600), 0);
    let service = service_with(&store, &mailer, retry(3, 5, 10));

    let outcome = handle(&service, 3, 3).await;

    assert_eq!(outcome, QueueOutcome::Retry);
    assert_eq!(store.row_status("scan-1"), Some(ReportEmailStatus::Failed));
    assert_eq!(store.audit_actions(), [REPORT_EMAIL_FAILED_ACTION]);
}

#[tokio::test(start_paused = true)]
async fn an_already_sent_report_is_done_without_sending() {
    let store = FakeStore::with_row("scan-1", Some(ReportEmailStatus::Sent), false);
    let mailer = Arc::new(InMemoryMailer::default());

    let outcome = handle(&service(&store, Some(&mailer)), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Done);
    assert_eq!(mailer.attempts(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_report_leased_by_another_consumer_is_done_without_sending() {
    let store = FakeStore::with_row("scan-1", Some(ReportEmailStatus::Pending), true);
    let mailer = Arc::new(InMemoryMailer::default());

    let outcome = handle(&service(&store, Some(&mailer)), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Done);
    assert_eq!(mailer.attempts(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_pending_report_with_an_expired_lease_is_claimed_and_sent() {
    let store = FakeStore::with_row("scan-1", Some(ReportEmailStatus::Pending), true);
    let mailer = Arc::new(InMemoryMailer::default());
    tokio::time::advance(LEASE + secs(1)).await;

    let outcome = handle(&service(&store, Some(&mailer)), 2, 3).await;

    assert_eq!(outcome, QueueOutcome::Done);
    assert_eq!(mailer.sent().len(), 1);
    assert_eq!(store.row_status("scan-1"), Some(ReportEmailStatus::Sent));
}

#[tokio::test(start_paused = true)]
async fn a_failed_report_redriven_from_the_dlq_is_claimed_and_sent() {
    let store = FakeStore::with_row("scan-1", Some(ReportEmailStatus::Failed), false);
    let mailer = Arc::new(InMemoryMailer::default());

    let outcome = handle(&service(&store, Some(&mailer)), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Done);
    assert_eq!(store.row_status("scan-1"), Some(ReportEmailStatus::Sent));
}

#[tokio::test(start_paused = true)]
async fn without_a_mailer_the_queue_request_marks_disabled_and_is_done() {
    let store = FakeStore::with_completed("scan-1");

    let outcome = handle(&service(&store, None), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Done);
    assert_eq!(
        store.row_status("scan-1"),
        Some(ReportEmailStatus::Disabled)
    );
}

#[tokio::test(start_paused = true)]
async fn an_unknown_scan_is_done_without_sending() {
    let store = FakeStore::with_completed("other");
    let mailer = Arc::new(InMemoryMailer::default());

    let outcome = handle(&service(&store, Some(&mailer)), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Done);
    assert_eq!(mailer.attempts(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_store_error_on_the_claim_is_retried() {
    let store = FakeStore::with_completed("scan-1");
    store.state.lock().unwrap().fail_queue_claim = true;
    let mailer = Arc::new(InMemoryMailer::default());

    let outcome = handle(&service(&store, Some(&mailer)), 1, 3).await;

    assert_eq!(outcome, QueueOutcome::Retry);
    assert_eq!(mailer.attempts(), 0);
}
