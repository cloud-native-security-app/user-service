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

        let Some(mailer) = &self.mailer else {
            tracing::info!(scan_id, "report email disabled: SMTP is not configured");
            self.finish(&job, ReportEmailStatus::Disabled).await;
            return;
        };

        let outcome = match self.build_email(&job) {
            Ok(email) => self.send_with_retry(mailer.as_ref(), &email, scan_id).await,
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
    ) -> Result<(), MailerError> {
        let attempts = self.retry.attempts.max(1);
        let mut wait = self.retry.backoff;
        let mut last = MailerError::Transport;
        for attempt in 1..=attempts {
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
