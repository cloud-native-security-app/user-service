//! SQS adapters of the report email queue (RF-20): the producer
//! ([`SqsReportEmailPublisher`]) and the consumer loop
//! ([`SqsReportEmailConsumer`]), modelled on `gateway/src/sqs.rs`.
//!
//! Design notes:
//!
//! - **Queue attributes at startup.** `GetQueueAttributes` provides the
//!   `VisibilityTimeout` (the claim lease derives from it) and the redrive `maxReceiveCount`
//!   (the last receive), so Terraform stays the only place that sets them.
//! - **One message per receive.** An SMTP attempt may take up to 60 s and the
//!   messages of a batch are handled one after another; with up to 10 per batch
//!   the last ones would outlive the visibility timeout, be redelivered with a
//!   higher receive count without having been handled, and risk a premature
//!   `failed`. Receiving one at a time keeps the receive count honest.
//! - **Delete after handling.** `Done` deletes the message. `Retry` leaves it
//!   untouched: SQS redelivers it after the visibility timeout and, once the
//!   last receive has failed, the redrive policy moves it to the DLQ.
//! - **Malformed bodies** are copied to the DLQ with an explicit `SendMessage`
//!   and then deleted from the queue. If the copy fails the message stays and
//!   the redrive resolves it. The body is never logged: only its length and the
//!   SQS message id.
//! - **Receive errors** are logged and retried with an exponential backoff
//!   (1 s up to 30 s). The loop only ends on shutdown.
//! - **Shutdown.** A [`CancellationToken`] races the long poll and the backoff,
//!   so `run` returns at once; a message already being handled finishes first
//!   and the unprocessed ones reappear after their visibility timeout.
//!
//! Credentials come from the default AWS provider chain (ECS task role);
//! `AWS_ENDPOINT_URL` is only used against LocalStack.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_sqs::error::DisplayErrorContext;
use aws_sdk_sqs::types::{Message, MessageSystemAttributeName, QueueAttributeName};
use aws_sdk_sqs::Client;
use tokio_util::sync::CancellationToken;

use crate::report_email::queue::{
    parse_queue_settings, parse_receive_count, parse_request_body, PublishError, QueueSettings,
    QueueSettingsError, ReportEmailRequest, ReportEmailRequestPublisher,
};
use crate::report_email::service::{QueueOutcome, ReportEmailService};

/// Longest wait of a `ReceiveMessage` long poll, in seconds.
const WAIT_TIME_SECONDS: i32 = 20;
/// Messages per `ReceiveMessage`: one, see the module notes.
const MAX_MESSAGES: i32 = 1;
/// First backoff after a receive error.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Cap of the exponential backoff.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Builds an SQS client with the default AWS credential chain, the `region`
/// (else the one the default chain resolves) and, for LocalStack only, an
/// `endpoint_url`. Opens no connection.
pub async fn build_client(region: Option<&str>, endpoint_url: Option<&str>) -> Client {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = region {
        loader = loader.region(aws_config::Region::new(region.to_string()));
    }
    if let Some(url) = endpoint_url {
        loader = loader.endpoint_url(url);
    }
    Client::new(&loader.load().await)
}

/// Producer: sends a [`ReportEmailRequest`] to the report email queue.
#[derive(Debug, Clone)]
pub struct SqsReportEmailPublisher {
    client: Client,
    queue_url: String,
}

impl SqsReportEmailPublisher {
    /// Builds the publisher on an already configured `client`.
    pub fn from_client(client: Client, queue_url: String) -> Self {
        Self { client, queue_url }
    }
}

#[async_trait]
impl ReportEmailRequestPublisher for SqsReportEmailPublisher {
    async fn publish(&self, scan_id: &str) -> Result<(), PublishError> {
        let body = serde_json::to_string(&ReportEmailRequest::new(scan_id))
            .map_err(|source| PublishError::Failed(Box::new(source)))?;
        self.client
            .send_message()
            .queue_url(&self.queue_url)
            .message_body(body)
            .send()
            .await
            .map_err(|source| PublishError::Failed(Box::new(source)))?;
        Ok(())
    }
}

/// Why the queue could not be set up at startup.
#[derive(Debug, thiserror::Error)]
pub enum QueueSetupError {
    /// `GetQueueAttributes` failed.
    #[error("could not read the attributes of the report email queue")]
    Attributes(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The attributes are not usable.
    #[error("the report email queue is not usable: {0}")]
    Settings(#[from] QueueSettingsError),
}

/// Reads the `VisibilityTimeout` and the redrive `maxReceiveCount` of the queue.
///
/// # Errors
///
/// [`QueueSetupError`] when the call fails or the queue has no usable values.
pub async fn load_queue_settings(
    client: &Client,
    queue_url: &str,
) -> Result<QueueSettings, QueueSetupError> {
    let output = client
        .get_queue_attributes()
        .queue_url(queue_url)
        .attribute_names(QueueAttributeName::VisibilityTimeout)
        .attribute_names(QueueAttributeName::RedrivePolicy)
        .send()
        .await
        .map_err(|source| QueueSetupError::Attributes(Box::new(source)))?;
    let attributes = output.attributes();
    let settings = parse_queue_settings(
        attributes
            .and_then(|a| a.get(&QueueAttributeName::VisibilityTimeout))
            .map(String::as_str),
        attributes
            .and_then(|a| a.get(&QueueAttributeName::RedrivePolicy))
            .map(String::as_str),
    )?;
    Ok(settings)
}

/// Consumer of the report email queue, with its DLQ for malformed messages.
#[derive(Clone)]
pub struct SqsReportEmailConsumer {
    client: Client,
    queue_url: String,
    dlq_url: String,
    settings: QueueSettings,
}

impl std::fmt::Debug for SqsReportEmailConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqsReportEmailConsumer")
            .field("queue_url", &self.queue_url)
            .field("dlq_url", &self.dlq_url)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl SqsReportEmailConsumer {
    /// Builds the consumer on an already configured `client` and the queue's
    /// `settings` (tests inject a client pointing at LocalStack).
    pub fn from_client(
        client: Client,
        queue_url: String,
        dlq_url: String,
        settings: QueueSettings,
    ) -> Self {
        Self {
            client,
            queue_url,
            dlq_url,
            settings,
        }
    }

    /// Builds the client and reads the queue attributes ([`load_queue_settings`]).
    ///
    /// # Errors
    ///
    /// [`QueueSetupError`] when the queue cannot be read or is not usable.
    pub async fn connect(
        region: Option<&str>,
        endpoint_url: Option<&str>,
        queue_url: String,
        dlq_url: String,
    ) -> Result<Self, QueueSetupError> {
        let client = build_client(region, endpoint_url).await;
        let settings = load_queue_settings(&client, &queue_url).await?;
        Ok(Self::from_client(client, queue_url, dlq_url, settings))
    }

    /// The SQS client, to share it with the producer.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The queue attributes read at startup.
    pub fn settings(&self) -> QueueSettings {
        self.settings
    }

    /// Consumes the queue until `shutdown` is cancelled (see the module notes).
    pub async fn run(self, service: Arc<ReportEmailService>, shutdown: CancellationToken) {
        let mut backoff = BACKOFF_INITIAL;
        while !shutdown.is_cancelled() {
            let receive = self
                .client
                .receive_message()
                .queue_url(&self.queue_url)
                .wait_time_seconds(WAIT_TIME_SECONDS)
                .max_number_of_messages(MAX_MESSAGES)
                .message_system_attribute_names(MessageSystemAttributeName::ApproximateReceiveCount)
                .send();
            let result = tokio::select! {
                _ = shutdown.cancelled() => break,
                result = receive => result,
            };
            match result {
                Ok(output) => {
                    backoff = BACKOFF_INITIAL;
                    for message in output.messages.unwrap_or_default() {
                        if shutdown.is_cancelled() {
                            break;
                        }
                        self.process(&service, message).await;
                    }
                }
                Err(err) => {
                    tracing::error!(
                        error = %DisplayErrorContext(&err),
                        retry_in_secs = backoff.as_secs(),
                        "report email queue: receive failed, retrying"
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = next_backoff(backoff);
                }
            }
        }
        tracing::info!("report email queue consumer stopped");
    }

    async fn process(&self, service: &ReportEmailService, message: Message) {
        let Some(receipt_handle) = message.receipt_handle() else {
            tracing::error!("report email queue: message without receipt handle skipped");
            return;
        };
        let body = message.body().unwrap_or_default();
        let request = match parse_request_body(body) {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(
                    %error,
                    message_id = message.message_id().unwrap_or("<none>"),
                    payload_len = body.len(),
                    "report email queue: malformed message sent to the DLQ"
                );
                self.dead_letter(receipt_handle, body).await;
                return;
            }
        };
        let receive_count = parse_receive_count(
            message
                .attributes()
                .and_then(|a| a.get(&MessageSystemAttributeName::ApproximateReceiveCount))
                .map(String::as_str),
        );
        let outcome = service
            .handle_request(
                &request.scan_id,
                receive_count,
                self.settings.max_receives,
                self.settings.lease(),
            )
            .await;
        if outcome == QueueOutcome::Done {
            self.delete(
                receipt_handle,
                "report email queue: could not delete a handled message, SQS will redeliver it",
            )
            .await;
        }
    }

    /// Copies a malformed body to the DLQ, then deletes it from the queue. If
    /// the copy fails the message is kept: the redrive resolves it.
    async fn dead_letter(&self, receipt_handle: &str, body: &str) {
        if let Err(err) = self
            .client
            .send_message()
            .queue_url(&self.dlq_url)
            .message_body(body)
            .send()
            .await
        {
            tracing::error!(
                error = %DisplayErrorContext(&err),
                "report email queue: could not copy a malformed message to the DLQ, keeping it"
            );
            return;
        }
        self.delete(
            receipt_handle,
            "report email queue: could not delete a malformed message already in the DLQ",
        )
        .await;
    }

    /// Deletes a message; a failure is only logged (`context`), SQS redelivers.
    async fn delete(&self, receipt_handle: &str, context: &str) {
        if let Err(err) = self
            .client
            .delete_message()
            .queue_url(&self.queue_url)
            .receipt_handle(receipt_handle)
            .send()
            .await
        {
            tracing::error!(error = %DisplayErrorContext(&err), "{context}");
        }
    }
}

/// Next backoff: double, capped at [`BACKOFF_MAX`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_from_one_second_and_caps_at_thirty() {
        let mut d = BACKOFF_INITIAL;
        let mut seen = vec![d.as_secs()];
        for _ in 0..6 {
            d = next_backoff(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, vec![1, 2, 4, 8, 16, 30, 30]);
    }
}
