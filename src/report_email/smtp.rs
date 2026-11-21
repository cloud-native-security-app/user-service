//! SMTP adapter of the `Mailer` port (`lettre`).
//!
//! STARTTLS is required by default (a server without it is refused, never
//! downgraded to plain text). [`SmtpTls::None`] exists only for the Mailpit
//! test sink and must be chosen explicitly (`SMTP_TLS=none`).

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};

use super::mailer::{Mailer, MailerError, OutgoingEmail};

/// Time allowed for each SMTP exchange.
const SMTP_TIMEOUT: Duration = Duration::from_secs(20);

/// Transport security of the SMTP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpTls {
    /// STARTTLS is mandatory (default, production).
    #[default]
    StartTls,
    /// No encryption and no authentication; only for a local test sink.
    None,
}

/// SMTP connection settings. The password is redacted in `Debug`.
#[derive(Clone)]
pub struct SmtpSettings {
    /// SMTP server host.
    pub host: String,
    /// SMTP server port (587 by default).
    pub port: u16,
    /// Login user, if the server requires authentication.
    pub username: Option<String>,
    /// Login password (an app password for Gmail).
    pub password: Option<SecretString>,
    /// Sender address.
    pub from: String,
    /// Transport security.
    pub tls: SmtpTls,
}

impl fmt::Debug for SmtpSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmtpSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("from", &self.from)
            .field("tls", &self.tls)
            .finish()
    }
}

/// [`Mailer`] over SMTP.
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl SmtpMailer {
    /// Builds the transport. Opens no connection until the first send.
    ///
    /// # Errors
    ///
    /// [`MailerError::Invalid`] if the sender address or host is invalid.
    pub fn new(settings: &SmtpSettings) -> Result<Self, MailerError> {
        let from = settings
            .from
            .parse::<Mailbox>()
            .map_err(|_| MailerError::Invalid)?;
        let builder = match settings.tls {
            SmtpTls::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)
                    .map_err(|_| MailerError::Invalid)?
            }
            SmtpTls::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
            }
        };
        let mut builder = builder.port(settings.port).timeout(Some(SMTP_TIMEOUT));
        if let (Some(user), Some(password)) = (&settings.username, &settings.password) {
            builder = builder.credentials(Credentials::new(
                user.clone(),
                password.expose_secret().to_owned(),
            ));
        }
        Ok(Self {
            transport: builder.build(),
            from,
        })
    }

    fn build_message(&self, email: &OutgoingEmail) -> Result<Message, MailerError> {
        let to = email
            .to
            .parse::<Mailbox>()
            .map_err(|_| MailerError::Invalid)?;
        let attachment_type =
            ContentType::parse(email.attachment.content_type).map_err(|_| MailerError::Invalid)?;
        let body = MultiPart::mixed()
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(email.text.clone()))
                    .singlepart(SinglePart::html(email.html.clone())),
            )
            .singlepart(
                Attachment::new(email.attachment.filename.clone())
                    .body(email.attachment.bytes.clone(), attachment_type),
            );
        Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject.clone())
            .multipart(body)
            .map_err(|_| MailerError::Invalid)
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, email: &OutgoingEmail) -> Result<(), MailerError> {
        let message = self.build_message(email)?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(|_| MailerError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_password() {
        let settings = SmtpSettings {
            host: "smtp.example.test".into(),
            port: 587,
            username: Some("reports@example.test".into()),
            password: Some(SecretString::from("s3cret-app-password")),
            from: "reports@example.test".into(),
            tls: SmtpTls::StartTls,
        };
        let debug = format!("{settings:?}");
        assert!(!debug.contains("s3cret-app-password"));
        assert!(debug.contains("[REDACTED]"));
    }
}
