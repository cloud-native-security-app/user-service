//! Sends the report email when a scan completes (task EM-02).
//!
//! The flow runs in a background task so the outcome update never waits for
//! SMTP and never fails because of it. Once per scan: the store `claim` is an
//! atomic compare-and-set, so a redelivered completed outcome finds nothing to
//! claim. The only recipient is the account email the store returns for the
//! scan owner.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::mailer::{Mailer, MailerError, OutgoingEmail};
use super::{render_report_email, ReportEmailInput};
use crate::audit::{REPORT_EMAILED_ACTION, REPORT_EMAIL_FAILED_ACTION};
use crate::domain::{ReportEmailStatus, ScanMode};
use crate::repository::RepoError;

/// A completed scan whose report email this process just claimed.
#[derive(Debug, Clone)]
pub struct ClaimedReport {
    /// Scan identifier.
    pub scan_id: String,
    /// Owner of the scan (audit actor).
    pub user_id: String,
    /// Account email of the owner: the only recipient.
    pub recipient: String,
    /// Scan target.
    pub target: String,
    /// Scan mode.
    pub mode: ScanMode,
    /// When the scan finished.
    pub finished_at: DateTime<Utc>,
    /// Stored result, `None` if the scan completed without one.
    pub result: Option<serde_json::Value>,
}

/// Persistence the flow needs; implemented by `Repository` and by test fakes.
#[async_trait]
pub trait ReportEmailStore: Send + Sync {
    /// Atomically claims the report email of `scan_id` (status `pending`).
    /// `None` when the scan is not `COMPLETADO` or the email was already claimed.
    async fn claim(&self, scan_id: &str) -> Result<Option<ClaimedReport>, RepoError>;

    /// Atomically re-claims up to `limit` reports left `pending` for longer than
    /// `older_than` (a send lost to a shutdown or crash), refreshing their claim
    /// time so no other caller gets them.
    async fn reclaim_stale(
        &self,
        older_than: Duration,
        limit: u32,
    ) -> Result<Vec<ClaimedReport>, RepoError>;

    /// Heartbeat: refreshes the claim time of those of `scan_ids` still `pending`,
    /// so a report this process is still sending is never judged stale.
    async fn touch(&self, scan_ids: &[String]) -> Result<(), RepoError>;

    /// Stores the final status; `at` becomes `report_emailed_at` for `sent`.
    async fn finish(
        &self,
        scan_id: &str,
        status: ReportEmailStatus,
        at: DateTime<Utc>,
    ) -> Result<(), RepoError>;

    /// Records an audit entry: actor `user_id`, target `scan_id`.
    async fn audit(&self, user_id: &str, action: &str, scan_id: &str) -> Result<(), RepoError>;
}

/// Bounded retry: `attempts` tries, waiting `backoff`, `2 * backoff`, ... between them.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total number of send attempts (at least 1).
    pub attempts: u32,
    /// Wait before the second attempt; doubles after each failure.
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            backoff: Duration::from_secs(2),
        }
    }
}

/// Smallest accepted `ReaperPolicy::after`. The heartbeat refreshes the claim
/// before every send attempt, so a live sender is stale only if one attempt
/// outlasts `after`. One SMTP attempt is bounded by a 20 s timeout per network
/// operation; 120 s leaves a wide margin over it.
pub const MIN_REAPER_AFTER: Duration = Duration::from_secs(120);

/// Shortest period the reaper ticks at: a zero interval would panic the timer.
const MIN_REAPER_INTERVAL: Duration = Duration::from_secs(1);

/// When the reaper looks for reports stuck in `pending`, and how many it takes.
#[derive(Debug, Clone, Copy)]
pub struct ReaperPolicy {
    /// A `pending` report is stuck once its claim (refreshed before every send
    /// attempt) is older than this. At least [`MIN_REAPER_AFTER`].
    pub after: Duration,
    /// Time between reaper ticks (clamped to at least one second).
    pub interval: Duration,
    /// Maximum reports re-claimed per tick.
    pub batch: u32,
}

impl Default for ReaperPolicy {
    fn default() -> Self {
        Self {
            after: Duration::from_secs(600),
            interval: Duration::from_secs(60),
            batch: 20,
        }
    }
}

/// Orchestrates claim, render, send with retry, status and audit.
pub struct ReportEmailService {
    store: Arc<dyn ReportEmailStore>,
    /// `None` = SMTP not configured: scans are marked `disabled`.
    mailer: Option<Arc<dyn Mailer>>,
    retry: RetryPolicy,
}

impl ReportEmailService {
    /// Builds the service; pass `mailer: None` when SMTP is not configured.
    pub fn new(
        store: Arc<dyn ReportEmailStore>,
        mailer: Option<Arc<dyn Mailer>>,
        retry: RetryPolicy,
    ) -> Self {
        Self {
            store,
            mailer,
            retry,
        }
    }

    /// Starts [`Self::process_completed`] in the background and returns at once.
    pub fn spawn_for_completed(self: &Arc<Self>, scan_id: String) {
        let service = Arc::clone(self);
        tokio::spawn(async move { service.process_completed(&scan_id).await });
    }

    /// Sends the report of `scan_id` if it is completed and not emailed yet.
    /// Never returns an error: failures are logged and stored as status.
    pub async fn process_completed(&self, scan_id: &str) {
        let job = match self.store.claim(scan_id).await {
            Ok(Some(job)) => job,
            Ok(None) => return,
            Err(error) => {
                tracing::error!(%error, scan_id, "report email: could not claim the send");
                return;
            }
        };
        self.send_claimed(job, &[]).await;
    }

    /// Starts the periodic reaper in the background (see [`Self::reap_once`]).
    /// Does nothing when SMTP is not configured: there is nothing to retry.
    pub fn spawn_reaper(self: &Arc<Self>, policy: ReaperPolicy) {
        if self.mailer.is_none() {
            return;
        }
        let service = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(policy.interval.max(MIN_REAPER_INTERVAL));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                service.reap_once(&policy).await;
            }
        });
    }

    /// One reaper tick: re-claims up to `policy.batch` reports stuck in
    /// `pending` for longer than `policy.after` and sends them through the same
    /// path as the first attempt. Returns how many it took. Never fails:
    /// errors are logged.
    pub async fn reap_once(&self, policy: &ReaperPolicy) -> usize {
        let jobs = match self.store.reclaim_stale(policy.after, policy.batch).await {
            Ok(jobs) => jobs,
            Err(error) => {
                tracing::error!(%error, "report email reaper: could not re-claim stuck reports");
                return 0;
            }
        };
        let count = jobs.len();
        let ids: Vec<String> = jobs.iter().map(|job| job.scan_id.clone()).collect();
        for (index, job) in jobs.into_iter().enumerate() {
            tracing::warn!(scan_id = %job.scan_id, "report email reaper: retrying a stuck send");
            // The reports queued behind this one are held too: they were claimed
            // together and must not look stale while waiting their turn.
            self.send_claimed(job, &ids[index + 1..]).await;
        }
        count
    }

    /// Renders and sends a report this process holds the claim of, then stores
    /// `sent`, `failed` or `disabled` and audits it. `queued` are the scan ids
    /// this process also holds and has not started yet.
    async fn send_claimed(&self, job: ClaimedReport, queued: &[String]) {
        let scan_id = job.scan_id.as_str();
        let Some(mailer) = &self.mailer else {
            tracing::info!(scan_id, "report email disabled: SMTP is not configured");
            self.finish(&job, ReportEmailStatus::Disabled).await;
            return;
        };

        let outcome = match self.build_email(&job) {
            Ok(email) => {
                let mut held = vec![job.scan_id.clone()];
                held.extend_from_slice(queued);
                self.send_with_retry(mailer.as_ref(), &email, scan_id, &held)
                    .await
            }
            Err(error) => Err(error),
        };
        match outcome {
            Ok(()) => {
                self.finish(&job, ReportEmailStatus::Sent).await;
                self.audit(&job, REPORT_EMAILED_ACTION).await;
            }
            Err(error) => {
                tracing::warn!(%error, scan_id, "report email failed");
                self.finish(&job, ReportEmailStatus::Failed).await;
                self.audit(&job, REPORT_EMAIL_FAILED_ACTION).await;
            }
        }
    }

    fn build_email(&self, job: &ClaimedReport) -> Result<OutgoingEmail, MailerError> {
        let result = job.result.as_ref().ok_or(MailerError::Invalid)?;
        let rendered = render_report_email(&ReportEmailInput {
            scan_id: &job.scan_id,
            target: &job.target,
            mode: job.mode,
            finished_at: job.finished_at,
            result,
        })
        .map_err(|_| MailerError::Invalid)?;
        Ok(OutgoingEmail {
            to: job.recipient.clone(),
            subject: rendered.subject,
            html: rendered.html,
            text: rendered.text,
            attachment: rendered.attachment,
        })
    }

    async fn send_with_retry(
        &self,
        mailer: &dyn Mailer,
        email: &OutgoingEmail,
        scan_id: &str,
        held: &[String],
    ) -> Result<(), MailerError> {
        let attempts = self.retry.attempts.max(1);
        let mut wait = self.retry.backoff;
        let mut last = MailerError::Transport;
        for attempt in 1..=attempts {
            self.heartbeat(held).await;
            match mailer.send(email).await {
                Ok(()) => return Ok(()),
                Err(MailerError::Invalid) => return Err(MailerError::Invalid),
                Err(error) => {
                    last = error;
                    tracing::warn!(scan_id, attempt, attempts, "report email attempt failed");
                }
            }
            if attempt < attempts {
                tokio::time::sleep(wait).await;
                wait = wait.saturating_mul(2);
            }
        }
        Err(last)
    }

    /// Refreshes the claim time of every report this process holds. A failure
    /// is logged and the send goes on: the claim only goes stale if the store
    /// stays unreachable for the whole threshold.
    async fn heartbeat(&self, held: &[String]) {
        if let Err(error) = self.store.touch(held).await {
            tracing::error!(%error, "report email: could not refresh the claim time");
        }
    }

    async fn finish(&self, job: &ClaimedReport, status: ReportEmailStatus) {
        if let Err(error) = self.store.finish(&job.scan_id, status, Utc::now()).await {
            tracing::error!(%error, scan_id = %job.scan_id, "report email: could not store the status");
        }
    }

    async fn audit(&self, job: &ClaimedReport, action: &str) {
        if let Err(error) = self.store.audit(&job.user_id, action, &job.scan_id).await {
            tracing::error!(%error, scan_id = %job.scan_id, "report email: could not record the audit entry");
        }
    }
}
