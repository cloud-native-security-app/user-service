//! The report email queue contract and the producer side (RF-20).
//!
//! `PATCH /scans/{id}` with `COMPLETADO` publishes a [`ReportEmailRequest`] (the
//! body of `broker/contracts/report-email-request.schema.json`) through the
//! [`ReportEmailRequestPublisher`] port; the consumer in
//! `crate::messaging::sqs` turns each message into
//! `ReportEmailService::handle_request`. Everything here is pure or in memory:
//! the SQS adapter lives in `crate::messaging::sqs`.
//!
//! A message body is never logged and never put in an error: only its length
//! and the SQS message id are safe to show.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::service::ReportEmailService;

/// Longest the producer waits for the queue before falling back to the
/// in-process path, so a slow SQS never delays the `PATCH` response much.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// The message: which scan to email and when it was requested. Matches the
/// broker contract, which forbids any other field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportEmailRequest {
    /// Scan whose report is emailed to its owner.
    pub scan_id: String,
    /// When the request was published (RFC 3339).
    pub requested_at: DateTime<Utc>,
}

impl ReportEmailRequest {
    /// A request for `scan_id`, stamped now.
    pub fn new(scan_id: impl Into<String>) -> Self {
        Self {
            scan_id: scan_id.into(),
            requested_at: Utc::now(),
        }
    }
}

/// Why a message body is not a usable [`ReportEmailRequest`]. Never carries
/// the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// Not JSON, a missing or unknown field, or a wrong type or timestamp.
    #[error("the message body does not match the report email request contract")]
    Malformed,
    /// `scan_id` is empty (the contract requires at least one character).
    #[error("the report email request has an empty scan_id")]
    EmptyScanId,
}

/// Parses a queue message body.
///
/// # Errors
///
/// [`RequestError`] when the body does not match the contract. The error never
/// contains the body.
pub fn parse_request_body(body: &str) -> Result<ReportEmailRequest, RequestError> {
    let request: ReportEmailRequest =
        serde_json::from_str(body).map_err(|_| RequestError::Malformed)?;
    if request.scan_id.is_empty() {
        return Err(RequestError::EmptyScanId);
    }
    Ok(request)
}

/// `ApproximateReceiveCount` of a message; 1 when SQS did not send a usable
/// value (it always does for a received message).
pub fn parse_receive_count(raw: Option<&str>) -> u32 {
    raw.and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|count| *count >= 1)
        .unwrap_or(1)
}

/// What the consumer reads from the queue at startup: the claim lease and the
/// last-receive threshold derive from it, so Terraform stays the only place
/// where they are set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueSettings {
    /// The queue's `VisibilityTimeout`: how long a received message stays
    /// hidden. It is also the claim lease.
    pub visibility_timeout: Duration,
    /// The redrive policy's `maxReceiveCount`: the receive that is the last one.
    pub max_receives: u32,
}

impl QueueSettings {
    /// How long a claim by a consumer holds: 90% of the visibility timeout. The
    /// claim is made a moment after the receive, so a redelivery exactly one
    /// visibility timeout after it must already find the lease expired;
    /// otherwise the retry would be treated as a duplicate and deleted. It stays
    /// far above one SMTP attempt (the visibility timeout must exceed it anyway).
    pub fn lease(&self) -> Duration {
        self.visibility_timeout.mul_f64(0.9)
    }
}

/// The queue attributes cannot be turned into [`QueueSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QueueSettingsError {
    /// `VisibilityTimeout` is missing or not a number of seconds >= 1.
    #[error("the queue has no usable VisibilityTimeout")]
    VisibilityTimeout,
    /// `RedrivePolicy` is missing or has no usable `maxReceiveCount` (the queue
    /// has no dead-letter queue configured).
    #[error("the queue has no usable RedrivePolicy maxReceiveCount")]
    RedrivePolicy,
}

/// Builds [`QueueSettings`] from the raw `VisibilityTimeout` and `RedrivePolicy`
/// attribute values of `GetQueueAttributes`.
///
/// # Errors
///
/// [`QueueSettingsError`] naming which attribute is unusable.
pub fn parse_queue_settings(
    visibility_timeout: Option<&str>,
    redrive_policy: Option<&str>,
) -> Result<QueueSettings, QueueSettingsError> {
    let seconds = visibility_timeout
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs >= 1)
        .ok_or(QueueSettingsError::VisibilityTimeout)?;
    let max_receives = redrive_policy
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|policy| match policy.get("maxReceiveCount")? {
            serde_json::Value::Number(n) => n.as_u64(),
            serde_json::Value::String(s) => s.trim().parse().ok(),
            _ => None,
        })
        .and_then(|count| u32::try_from(count).ok())
        .filter(|count| *count >= 1)
        .ok_or(QueueSettingsError::RedrivePolicy)?;
    Ok(QueueSettings {
        visibility_timeout: Duration::from_secs(seconds),
        max_receives,
    })
}

/// The reaper threshold is not above the whole queue window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "REPORT_EMAIL_REAPER_AFTER_SECS must be greater than the whole queue window (visibility \
     timeout x maxReceiveCount + one SMTP attempt deadline): at least {minimum_secs} seconds"
)]
pub struct ReaperWindowError {
    /// Smallest accepted threshold, in whole seconds.
    pub minimum_secs: u64,
}

/// In queue mode every receive refreshes the claim, so a live message can keep
/// a row `pending` for `visibility x max_receives` plus one attempt. The reaper
/// (kept for the in-process fallback) must not take such a row.
///
/// # Errors
///
/// [`ReaperWindowError`] when `reaper_after` does not exceed that window.
pub fn check_reaper_window(
    settings: &QueueSettings,
    reaper_after: Duration,
    attempt_timeout: Duration,
) -> Result<(), ReaperWindowError> {
    let window = settings
        .visibility_timeout
        .saturating_mul(settings.max_receives)
        .saturating_add(attempt_timeout);
    if reaper_after > window {
        Ok(())
    } else {
        Err(ReaperWindowError {
            minimum_secs: window.as_secs().saturating_add(1),
        })
    }
}

/// Why a request could not be published. Never carries the message body.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The queue refused or could not be reached.
    #[error("could not publish the report email request")]
    Failed(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The queue did not answer in time.
    #[error("publishing the report email request timed out")]
    TimedOut,
}

/// Port: puts a [`ReportEmailRequest`] for a scan on the queue.
#[async_trait]
pub trait ReportEmailRequestPublisher: Send + Sync {
    /// Publishes a request for `scan_id`.
    ///
    /// # Errors
    ///
    /// [`PublishError`] when the request is not on the queue.
    async fn publish(&self, scan_id: &str) -> Result<(), PublishError>;
}

enum RecordingMode {
    Accept,
    Fail,
    Hang,
}

/// In-memory [`ReportEmailRequestPublisher`] for tests: records the scan ids,
/// and can fail or never answer.
pub struct RecordingPublisher {
    mode: RecordingMode,
    published: Mutex<Vec<String>>,
}

impl Default for RecordingPublisher {
    fn default() -> Self {
        Self::with_mode(RecordingMode::Accept)
    }
}

impl RecordingPublisher {
    fn with_mode(mode: RecordingMode) -> Self {
        Self {
            mode,
            published: Mutex::default(),
        }
    }

    /// A publisher whose every `publish` fails.
    pub fn failing() -> Self {
        Self::with_mode(RecordingMode::Fail)
    }

    /// A publisher whose `publish` never answers.
    pub fn hanging() -> Self {
        Self::with_mode(RecordingMode::Hang)
    }

    /// Scan ids published so far.
    pub fn published(&self) -> Vec<String> {
        self.published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[async_trait]
impl ReportEmailRequestPublisher for RecordingPublisher {
    async fn publish(&self, scan_id: &str) -> Result<(), PublishError> {
        match self.mode {
            RecordingMode::Accept => {
                self.published
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(scan_id.to_string());
                Ok(())
            }
            RecordingMode::Fail => Err(PublishError::Failed("recording publisher".into())),
            RecordingMode::Hang => std::future::pending().await,
        }
    }
}

/// Producer entry point for a completed scan: publishes the request (bounded by
/// `timeout`) and, if that is not possible or not configured, falls back to the
/// in-process send so the email is not lost. Never fails and never blocks the
/// caller for more than `timeout`.
pub async fn request_report_email(
    publisher: Option<&Arc<dyn ReportEmailRequestPublisher>>,
    fallback: Option<&Arc<ReportEmailService>>,
    scan_id: String,
    timeout: Duration,
) {
    if let Some(publisher) = publisher {
        match tokio::time::timeout(timeout, publisher.publish(&scan_id)).await {
            Ok(Ok(())) => return,
            Ok(Err(error)) => {
                tracing::warn!(%error, scan_id, "report email queue: publish failed, sending in process");
            }
            Err(_elapsed) => {
                tracing::warn!(
                    scan_id,
                    "report email queue: publish timed out, sending in process"
                );
            }
        }
    }
    if let Some(service) = fallback {
        service.spawn_for_completed(scan_id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_valid_body_parses_into_a_request() {
        let request =
            parse_request_body(r#"{"scan_id":"scan-42","requested_at":"2026-11-26T14:03:09Z"}"#)
                .unwrap();
        assert_eq!(request.scan_id, "scan-42");
        assert_eq!(
            request.requested_at.to_rfc3339(),
            "2026-11-26T14:03:09+00:00"
        );
    }

    #[test]
    fn an_offset_timestamp_is_accepted() {
        let request =
            parse_request_body(r#"{"scan_id":"s","requested_at":"2026-11-26T11:03:09.512-03:00"}"#)
                .unwrap();
        assert_eq!(request.requested_at.timestamp(), 1_795_701_789);
    }

    #[test]
    fn malformed_bodies_are_rejected_without_echoing_them() {
        let bodies = [
            "",
            "not json",
            "[]",
            r#"{"scan_id":"s"}"#,
            r#"{"requested_at":"2026-11-26T14:03:09Z"}"#,
            r#"{"scan_id":"s","requested_at":"yesterday"}"#,
            r#"{"scan_id":7,"requested_at":"2026-11-26T14:03:09Z"}"#,
            r#"{"scan_id":"s","requested_at":"2026-11-26T14:03:09Z","extra":1}"#,
        ];
        for body in bodies {
            let error = parse_request_body(body).unwrap_err().to_string();
            assert!(!error.contains(body) || body.is_empty(), "{error}");
        }
    }

    #[test]
    fn an_empty_scan_id_is_rejected() {
        let result = parse_request_body(r#"{"scan_id":"","requested_at":"2026-11-26T14:03:09Z"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn a_request_serializes_to_the_contract_fields() {
        let value = serde_json::to_value(ReportEmailRequest::new("scan-1")).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["requested_at", "scan_id"]);
        assert_eq!(value["scan_id"], "scan-1");
    }

    #[test]
    fn the_receive_count_is_read_and_defaults_to_one() {
        assert_eq!(parse_receive_count(Some("3")), 3);
        assert_eq!(parse_receive_count(Some(" 2 ")), 2);
        for bad in [None, Some(""), Some("x"), Some("-1"), Some("0")] {
            assert_eq!(parse_receive_count(bad), 1, "{bad:?}");
        }
    }

    #[test]
    fn queue_settings_come_from_the_visibility_timeout_and_the_redrive_policy() {
        let redrive = r#"{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:dlq","maxReceiveCount":3}"#;
        let settings = parse_queue_settings(Some("120"), Some(redrive)).unwrap();
        assert_eq!(settings.visibility_timeout, Duration::from_secs(120));
        assert_eq!(settings.max_receives, 3);
    }

    #[test]
    fn a_max_receive_count_sent_as_a_string_is_accepted() {
        let redrive = r#"{"deadLetterTargetArn":"a","maxReceiveCount":"5"}"#;
        let settings = parse_queue_settings(Some("30"), Some(redrive)).unwrap();
        assert_eq!(settings.max_receives, 5);
    }

    #[test]
    fn unusable_queue_attributes_are_refused() {
        let good = r#"{"deadLetterTargetArn":"a","maxReceiveCount":3}"#;
        let cases = [
            (None, Some(good)),
            (Some("soon"), Some(good)),
            (Some("0"), Some(good)),
            (Some("30"), None),
            (Some("30"), Some("not json")),
            (Some("30"), Some(r#"{"deadLetterTargetArn":"a"}"#)),
            (Some("30"), Some(r#"{"maxReceiveCount":0}"#)),
            (Some("30"), Some(r#"{"maxReceiveCount":"many"}"#)),
        ];
        for (visibility, redrive) in cases {
            assert!(
                parse_queue_settings(visibility, redrive).is_err(),
                "{visibility:?} {redrive:?}"
            );
        }
    }

    fn settings(visibility: u64, max_receives: u32) -> QueueSettings {
        QueueSettings {
            visibility_timeout: Duration::from_secs(visibility),
            max_receives,
        }
    }

    #[test]
    fn the_claim_lease_is_a_little_shorter_than_the_visibility_timeout() {
        // The claim is made a moment after the receive, so a redelivery exactly
        // one visibility timeout after it must already find the lease expired.
        assert_eq!(settings(120, 3).lease(), Duration::from_secs(108));
        assert_eq!(settings(2, 3).lease(), Duration::from_millis(1800));
        assert!(settings(1, 3).lease() < Duration::from_secs(1));
    }

    #[test]
    fn the_reaper_must_outlast_the_whole_queue_window() {
        // 120 s x 3 receives + 60 s attempt = 420 s; the threshold must exceed it.
        let attempt = Duration::from_secs(60);
        let queue = settings(120, 3);
        let error = check_reaper_window(&queue, Duration::from_secs(420), attempt).unwrap_err();
        assert_eq!(error.minimum_secs, 421);
        assert!(check_reaper_window(&queue, Duration::from_secs(421), attempt).is_ok());
        // The default threshold (600 s) is above it.
        assert!(check_reaper_window(&queue, Duration::from_secs(600), attempt).is_ok());
    }

    #[test]
    fn a_huge_queue_window_does_not_overflow_the_reaper_check() {
        let queue = settings(43_200, u32::MAX);
        assert!(
            check_reaper_window(&queue, Duration::from_secs(600), Duration::from_secs(60)).is_err()
        );
    }

    #[tokio::test]
    async fn the_recording_publisher_keeps_what_was_published() {
        let publisher = RecordingPublisher::default();
        publisher.publish("scan-1").await.unwrap();
        assert_eq!(publisher.published(), ["scan-1"]);
        let failing = RecordingPublisher::failing();
        assert!(failing.publish("scan-1").await.is_err());
        assert!(failing.published().is_empty());
        let _: Arc<dyn ReportEmailRequestPublisher> = Arc::new(publisher);
    }
}
