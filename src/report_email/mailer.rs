//! The `Mailer` port: how the service sends an email, without knowing SMTP.
//!
//! Adapters: [`super::smtp::SmtpMailer`] (production) and [`InMemoryMailer`]
//! (tests). Without SMTP settings the service gets no mailer at all.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;

use super::ReportAttachment;

/// One email ready to send: HTML body, plain-text alternative and one attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingEmail {
    /// Recipient address (always the account email of the scan owner).
    pub to: String,
    /// Single-line subject.
    pub subject: String,
    /// HTML body.
    pub html: String,
    /// Plain-text alternative.
    pub text: String,
    /// JSON attachment.
    pub attachment: ReportAttachment,
}

/// Why a send failed. Never carries credentials or message content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailerError {
    /// The message could not be built (invalid address); retrying cannot help.
    #[error("the email could not be built")]
    Invalid,
    /// The SMTP exchange failed; a retry may succeed.
    #[error("the SMTP server did not accept the email")]
    Transport,
}

/// Sends one email.
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Sends `email`.
    ///
    /// # Errors
    ///
    /// [`MailerError::Invalid`] when the message cannot be built,
    /// [`MailerError::Transport`] when the SMTP exchange fails.
    async fn send(&self, email: &OutgoingEmail) -> Result<(), MailerError>;
}

/// In-memory [`Mailer`]: records what was sent and can fail the first N attempts.
#[derive(Default)]
pub struct InMemoryMailer {
    sent: Mutex<Vec<OutgoingEmail>>,
    attempts: AtomicUsize,
    failures_left: AtomicUsize,
}

impl InMemoryMailer {
    /// A mailer whose first `count` attempts fail with [`MailerError::Transport`].
    pub fn failing_first(count: usize) -> Self {
        Self {
            failures_left: AtomicUsize::new(count),
            ..Self::default()
        }
    }

    /// Emails accepted so far.
    pub fn sent(&self) -> Vec<OutgoingEmail> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Number of `send` calls, failed or not.
    pub fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Mailer for InMemoryMailer {
    async fn send(&self, email: &OutgoingEmail) -> Result<(), MailerError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let failing = self
            .failures_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if failing {
            return Err(MailerError::Transport);
        }
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(email.clone());
        Ok(())
    }
}
