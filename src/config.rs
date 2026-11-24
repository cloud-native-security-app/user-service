//! Carga de configuración del servicio desde variables de entorno.
//!
//! Toda la configuración de `ms-usuarios` (URL de conexión a Postgres,
//! host/puerto de bind del servidor HTTP y la credencial de servicio que
//! autentica al Gateway como llamante, ver `docs/security-scope.md`) se lee
//! exclusivamente de variables de entorno — ningún valor queda hardcodeado
//! en el código. [`Config::from_env`] nunca hace `panic!`: cualquier
//! variable ausente o inválida se traduce en un [`ConfigError`] tipado.

use std::ffi::OsString;
use std::fmt;
use std::time::Duration;

use secrecy::{SecretBox, SecretSlice, SecretString};

use crate::domain::{AdminEmails, NetworkScanEmails};
use crate::report_email::service::{ReaperPolicy, MIN_REAPER_AFTER};
use crate::report_email::smtp::{SmtpMailer, SmtpSettings, SmtpTls};

/// Nombre de la variable de entorno con la URL de conexión a PostgreSQL.
const DATABASE_URL_VAR: &str = "DATABASE_URL";

/// Nombre de la variable de entorno con el host de bind del servidor HTTP.
const HTTP_HOST_VAR: &str = "HTTP_HOST";

/// Nombre de la variable de entorno con el puerto de bind del servidor HTTP.
const HTTP_PORT_VAR: &str = "HTTP_PORT";

/// Nombre de la variable de entorno con la credencial compartida que
/// autentica la llamada Gateway→`ms-usuarios` (ver `docs/security-scope.md`).
const GATEWAY_SHARED_SECRET_VAR: &str = "GATEWAY_SHARED_SECRET";

/// Nombre de la variable de entorno, **opcional**, con la URL de conexión
/// usada exclusivamente para aplicar migraciones (ver
/// [`Config::migrations_database_url`]). Si está ausente, se usa el mismo
/// valor que `DATABASE_URL`.
const MIGRATIONS_DATABASE_URL_VAR: &str = "MIGRATIONS_DATABASE_URL";

/// Nombre de la variable de entorno con la clave de cifrado en reposo de las
/// credenciales SSH de red (`network_credentials.ssh_credentials_ref`, ver
/// `docs/security-scope.md` §"Credenciales de red"): 32 bytes codificados en
/// hex (64 caracteres). Se trata como configuración sensible del mismo
/// nivel que `GATEWAY_SHARED_SECRET` — nunca se hardcodea, nunca se loggea.
const CREDENTIALS_ENCRYPTION_KEY_VAR: &str = "CREDENTIALS_ENCRYPTION_KEY";

/// Nombre de la variable de entorno, **opcional**, con los correos de los
/// administradores separados por comas (ver [`Config::admin_bootstrap_emails`]).
const ADMIN_BOOTSTRAP_EMAILS_VAR: &str = "ADMIN_BOOTSTRAP_EMAILS";

/// Nombre de la variable de entorno, **opcional**, con los correos autorizados
/// a escanear en modo red, separados por comas (ver
/// [`Config::network_scan_emails`]).
const NETWORK_SCAN_EMAILS_VAR: &str = "NETWORK_SCAN_EMAILS";

/// Nombre de la variable de entorno, **opcional**, con el nombre del Kinesis
/// Data Stream de eventos de seguridad (`security-events`). Ausente o en
/// blanco desactiva la publicación (adaptador no-op).
pub const SECURITY_EVENTS_STREAM_NAME_VAR: &str = "SECURITY_EVENTS_STREAM_NAME";

/// Nombre de la variable de entorno, **opcional**, con la región AWS del
/// cliente Kinesis. Si falta, la resuelve la cadena por defecto de AWS.
pub const AWS_REGION_VAR: &str = "AWS_REGION";

/// Nombre de la variable de entorno, **opcional**, con el endpoint AWS
/// alternativo (solo LocalStack/desarrollo). Ausente en AWS real.
pub const AWS_ENDPOINT_URL_VAR: &str = "AWS_ENDPOINT_URL";

/// Optional seconds a report email may stay `pending` before the reaper
/// retries it (default 600).
pub const REPORT_EMAIL_REAPER_AFTER_SECS_VAR: &str = "REPORT_EMAIL_REAPER_AFTER_SECS";
/// Optional seconds between reaper ticks (default 60).
pub const REPORT_EMAIL_REAPER_INTERVAL_SECS_VAR: &str = "REPORT_EMAIL_REAPER_INTERVAL_SECS";

/// Optional SMTP host of the report email. Unset or blank disables the email.
pub const SMTP_HOST_VAR: &str = "SMTP_HOST";
/// Optional SMTP port (default 587).
pub const SMTP_PORT_VAR: &str = "SMTP_PORT";
/// Optional SMTP login user.
pub const SMTP_USERNAME_VAR: &str = "SMTP_USERNAME";
/// Optional SMTP login password (secret).
pub const SMTP_PASSWORD_VAR: &str = "SMTP_PASSWORD";
/// Optional sender address (defaults to `SMTP_USERNAME`).
pub const SMTP_FROM_VAR: &str = "SMTP_FROM";
/// Optional transport security: `starttls` (default, required) or `none`
/// (plain, no login; only for a local test sink such as Mailpit).
pub const SMTP_TLS_VAR: &str = "SMTP_TLS";

/// Largo máximo de un nombre de stream de Kinesis.
const MAX_STREAM_NAME_CHARS: usize = 128;

/// Configuración del servicio `ms-usuarios`, cargada desde variables de
/// entorno mediante [`Config::from_env`].
///
/// El campo `gateway_shared_secret` usa [`SecretString`] para que su
/// contenido nunca aparezca en texto plano al formatearlo con `{:?}` (p. ej.
/// vía `tracing::debug!`/`tracing::error!`) ni en un mensaje de panic —
/// requisito de `docs/security-scope.md`.
pub struct Config {
    /// URL de conexión a la base de datos PostgreSQL (`db-usuarios`).
    pub database_url: String,
    /// Host en el que el servidor HTTP debe hacer bind (p. ej. `0.0.0.0`).
    pub http_host: String,
    /// Puerto en el que el servidor HTTP debe hacer bind.
    pub http_port: u16,
    /// Credencial compartida que autentica al Gateway como llamante de este
    /// servicio (ver `docs/security-scope.md`). Redactada en `Debug`.
    pub gateway_shared_secret: SecretString,
    /// URL de conexión a PostgreSQL usada exclusivamente para aplicar
    /// migraciones (`sqlx::migrate!`), con el rol "dueño" de las tablas —
    /// distinto en producción del rol de aplicación `ms_usuarios_app` que
    /// usa `database_url` para servir tráfico HTTP (ver
    /// `migrations/20260918120100_lock_audit_log_permissions.sql`: el dueño
    /// de una tabla se salta cualquier `REVOKE`, así que ese rol no debe
    /// servir tráfico en producción). Si `MIGRATIONS_DATABASE_URL` no está
    /// presente en el entorno, cae de vuelta al valor de `database_url`
    /// (para dev/test con un único rol todopoderoso).
    pub migrations_database_url: String,
    /// Clave de cifrado en reposo (AES-256-GCM) de las credenciales SSH de
    /// red por usuario/objetivo (feature `network_credentials_api`): 32
    /// bytes, leída desde `CREDENTIALS_ENCRYPTION_KEY` como hex de 64
    /// caracteres. Se usa para cifrar `ssh_credentials_ref` antes de
    /// persistirla y descifrarla solo al resolver un objetivo — nunca se
    /// loggea (redactada por [`SecretBox`] en `Debug`).
    pub credentials_encryption_key: SecretSlice<u8>,
    /// Lista autoritativa de administradores, leída de
    /// `ADMIN_BOOTSTRAP_EMAILS` (separada por comas; ausente o vacía = sin
    /// administradores): un usuario es admin si y solo si su correo está
    /// aquí. Se aplica al arrancar y al aprovisionar el perfil. Su `Debug`
    /// solo muestra la cantidad.
    pub admin_bootstrap_emails: AdminEmails,
    /// Lista autoritativa de cuentas con permiso de escaneo en modo red, leída
    /// de `NETWORK_SCAN_EMAILS` (separada por comas; ausente o vacía = nadie):
    /// un usuario lo tiene si y solo si su correo está aquí. Se aplica (concede
    /// y revoca) al arrancar y al aprovisionar el perfil. Su `Debug` solo
    /// muestra la cantidad.
    pub network_scan_emails: NetworkScanEmails,
    /// Nombre del Kinesis Data Stream de eventos de seguridad. `None`
    /// (variable ausente o en blanco) desactiva la publicación. Ver
    /// [`SECURITY_EVENTS_STREAM_NAME_VAR`].
    pub security_events_stream_name: Option<String>,
    /// Región AWS del cliente Kinesis, si se indicó. Ver [`AWS_REGION_VAR`].
    pub aws_region: Option<String>,
    /// Endpoint AWS alternativo (solo LocalStack), si se indicó. Ver
    /// [`AWS_ENDPOINT_URL_VAR`].
    pub aws_endpoint_url: Option<String>,
    /// SMTP settings of the report email; `None` (no `SMTP_HOST`) disables it.
    /// The password is redacted in `Debug`.
    pub smtp: Option<SmtpSettings>,
    /// Threshold, interval and batch of the reaper that retries report emails
    /// stuck in `pending`. Only used when SMTP is configured.
    pub report_email_reaper: ReaperPolicy,
}

impl fmt::Debug for Config {
    /// Implementación manual para garantizar, de forma explícita y a prueba
    /// de futuros campos añadidos por descuido, que `gateway_shared_secret`
    /// y `credentials_encryption_key` nunca se imprimen en texto plano —
    /// [`SecretString`]/[`SecretBox`] ya redactan su propio `Debug`, pero lo
    /// dejamos explícito aquí como salvaguarda documentada.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &self.database_url)
            .field("http_host", &self.http_host)
            .field("http_port", &self.http_port)
            .field("gateway_shared_secret", &self.gateway_shared_secret)
            .field("migrations_database_url", &self.migrations_database_url)
            .field(
                "credentials_encryption_key",
                &self.credentials_encryption_key,
            )
            .field("admin_bootstrap_emails", &self.admin_bootstrap_emails)
            .field("network_scan_emails", &self.network_scan_emails)
            .field(
                "security_events_stream_name",
                &self.security_events_stream_name,
            )
            .field("aws_region", &self.aws_region)
            .field("aws_endpoint_url", &self.aws_endpoint_url)
            .field("smtp", &self.smtp)
            .field("report_email_reaper", &self.report_email_reaper)
            .finish()
    }
}

impl Config {
    /// Carga la configuración del servicio desde variables de entorno.
    ///
    /// Variables requeridas: `DATABASE_URL`, `HTTP_HOST`, `HTTP_PORT`,
    /// `GATEWAY_SHARED_SECRET` y `CREDENTIALS_ENCRYPTION_KEY`.
    /// `ADMIN_BOOTSTRAP_EMAILS` es **opcional** (ausente = sin
    /// administradores); una entrada que no sea un correo es un error de
    /// configuración ([`ConfigError::InvalidAdminEmails`]).
    /// `NETWORK_SCAN_EMAILS` es **opcional** (ausente = nadie puede escanear en
    /// modo red) y se valida igual ([`ConfigError::InvalidNetworkScanEmails`]).
    /// `MIGRATIONS_DATABASE_URL` es **opcional**: si está ausente,
    /// [`Config::migrations_database_url`] cae de vuelta al valor de
    /// `DATABASE_URL`.
    ///
    /// # Errores
    ///
    /// Devuelve [`ConfigError::MissingVar`] si falta alguna variable
    /// requerida, [`ConfigError::InvalidPort`] si `HTTP_PORT` no es un
    /// puerto TCP válido (`u16`), o [`ConfigError::InvalidEncryptionKey`]
    /// si `CREDENTIALS_ENCRYPTION_KEY` no decodifica a 32 bytes de hex.
    /// Nunca hace `panic!`.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// Carga la configuración consultando cada variable mediante `lookup`
    /// (nombre de variable → valor, o `None` si está ausente).
    ///
    /// Es la lógica pura detrás de [`Config::from_env`]: no toca el entorno
    /// del proceso, por lo que los tests la ejercitan con un mapa en memoria
    /// sin mutar estado global. Mismas variables, valores por defecto y
    /// errores que `from_env`.
    ///
    /// # Errores
    ///
    /// Los mismos que [`Config::from_env`].
    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<OsString>,
    {
        let database_url = read_required(&lookup, DATABASE_URL_VAR)?;
        let http_host = read_required(&lookup, HTTP_HOST_VAR)?;
        let raw_http_port = read_required(&lookup, HTTP_PORT_VAR)?;
        let gateway_shared_secret =
            SecretString::from(read_required(&lookup, GATEWAY_SHARED_SECRET_VAR)?);
        let credentials_encryption_key =
            decode_encryption_key(&read_required(&lookup, CREDENTIALS_ENCRYPTION_KEY_VAR)?)?;
        let admin_bootstrap_emails = read_admin_emails(&lookup)?;
        let network_scan_emails = read_network_scan_emails(&lookup)?;
        let migrations_database_url = lookup(MIGRATIONS_DATABASE_URL_VAR)
            .and_then(|value| value.into_string().ok())
            .unwrap_or_else(|| database_url.clone());

        let security_events_stream_name = read_stream_name(&lookup)?;
        let aws_region = read_optional(&lookup, AWS_REGION_VAR);
        let aws_endpoint_url = read_optional(&lookup, AWS_ENDPOINT_URL_VAR);

        let smtp = read_smtp(&lookup)?;
        let report_email_reaper = read_reaper(&lookup)?;

        let http_port = raw_http_port
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidPort {
                variable: HTTP_PORT_VAR,
            })?;

        Ok(Config {
            database_url,
            http_host,
            http_port,
            gateway_shared_secret,
            credentials_encryption_key,
            migrations_database_url,
            admin_bootstrap_emails,
            network_scan_emails,
            security_events_stream_name,
            aws_region,
            aws_endpoint_url,
            smtp,
            report_email_reaper,
        })
    }
}

/// Decodifica la variable `CREDENTIALS_ENCRYPTION_KEY` (hex de 64
/// caracteres) a una [`SecretBox`] de 32 bytes.
///
/// # Errores
///
/// Devuelve [`ConfigError::InvalidEncryptionKey`] si el valor no es hex
/// válido o no decodifica exactamente a 32 bytes. Trata el valor de la
/// variable como configuración sensible: el mensaje de error solo nombra la
/// variable, nunca su contenido (ver `docs/security-scope.md`).
fn decode_encryption_key(value: &str) -> Result<SecretSlice<u8>, ConfigError> {
    let bytes = hex::decode(value.trim()).map_err(|_| ConfigError::InvalidEncryptionKey {
        variable: CREDENTIALS_ENCRYPTION_KEY_VAR,
    })?;
    if bytes.len() != 32 {
        return Err(ConfigError::InvalidEncryptionKey {
            variable: CREDENTIALS_ENCRYPTION_KEY_VAR,
        });
    }
    Ok(SecretBox::from(bytes.into_boxed_slice()))
}

/// Reads the `SMTP_*` variables: no `SMTP_HOST` means the email is disabled.
/// Fails closed on an invalid port, TLS mode or sender, on a user without
/// password (or the reverse), and on a missing sender; errors name the
/// variable, never the value.
fn read_smtp(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<Option<SmtpSettings>, ConfigError> {
    let invalid = |variable| ConfigError::InvalidSmtp { variable };
    let Some(host) = read_optional(lookup, SMTP_HOST_VAR) else {
        return Ok(None);
    };
    let host_chars_ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'));
    if !host_chars_ok {
        return Err(invalid(SMTP_HOST_VAR));
    }
    let port = match read_optional(lookup, SMTP_PORT_VAR) {
        None => 587,
        Some(raw) => raw.parse::<u16>().map_err(|_| invalid(SMTP_PORT_VAR))?,
    };
    let tls = match read_optional(lookup, SMTP_TLS_VAR).as_deref() {
        None | Some("starttls") => SmtpTls::StartTls,
        Some("none") => SmtpTls::None,
        Some(_) => return Err(invalid(SMTP_TLS_VAR)),
    };
    let username = read_optional(lookup, SMTP_USERNAME_VAR);
    let password = read_optional(lookup, SMTP_PASSWORD_VAR).map(SecretString::from);
    if tls == SmtpTls::None && (username.is_some() || password.is_some()) {
        return Err(ConfigError::InsecureSmtpCredentials);
    }
    if username.is_some() != password.is_some() {
        return Err(invalid(SMTP_PASSWORD_VAR));
    }
    let from = read_optional(lookup, SMTP_FROM_VAR)
        .or_else(|| username.clone())
        .ok_or_else(|| invalid(SMTP_FROM_VAR))?;
    if from.parse::<lettre::message::Mailbox>().is_err() {
        return Err(invalid(SMTP_FROM_VAR));
    }
    let settings = SmtpSettings {
        host,
        port,
        username,
        password,
        from,
        tls,
    };
    // Builds the transport without connecting, so an unusable host fails the
    // startup instead of silently disabling the email later.
    SmtpMailer::new(&settings).map_err(|_| invalid(SMTP_HOST_VAR))?;
    Ok(Some(settings))
}

/// Reads the reaper durations (whole seconds; the interval at least 1, the
/// threshold at least [`MIN_REAPER_AFTER`]). Errors name the
/// variable only.
fn read_reaper(lookup: &impl Fn(&str) -> Option<OsString>) -> Result<ReaperPolicy, ConfigError> {
    let defaults = ReaperPolicy::default();
    let seconds = |variable: &'static str, default: Duration| match read_optional(lookup, variable)
    {
        None => Ok(default),
        Some(raw) => match raw.parse::<u64>() {
            Ok(secs) if secs >= 1 => Ok(Duration::from_secs(secs)),
            _ => Err(ConfigError::InvalidReportEmailReaper { variable }),
        },
    };
    let after = seconds(REPORT_EMAIL_REAPER_AFTER_SECS_VAR, defaults.after)?;
    if after < MIN_REAPER_AFTER {
        return Err(ConfigError::InvalidReportEmailReaper {
            variable: REPORT_EMAIL_REAPER_AFTER_SECS_VAR,
        });
    }
    Ok(ReaperPolicy {
        after,
        interval: seconds(REPORT_EMAIL_REAPER_INTERVAL_SECS_VAR, defaults.interval)?,
        batch: defaults.batch,
    })
}

/// Lee `ADMIN_BOOTSTRAP_EMAILS`: ausente = sin administradores. Un valor que
/// no es UTF-8 válido o con una entrada que no es un correo falla (cierra en
/// vez de interpretar mal la lista).
fn read_admin_emails(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<AdminEmails, ConfigError> {
    let invalid = || ConfigError::InvalidAdminEmails {
        variable: ADMIN_BOOTSTRAP_EMAILS_VAR,
    };
    let raw = match lookup(ADMIN_BOOTSTRAP_EMAILS_VAR) {
        Some(value) => value.into_string().map_err(|_| invalid())?,
        None => String::new(),
    };
    AdminEmails::parse(&raw).map_err(|_| invalid())
}

/// Lee `NETWORK_SCAN_EMAILS`: ausente = nadie. Mismas reglas de fallo cerrado
/// que [`read_admin_emails`].
fn read_network_scan_emails(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<NetworkScanEmails, ConfigError> {
    let invalid = || ConfigError::InvalidNetworkScanEmails {
        variable: NETWORK_SCAN_EMAILS_VAR,
    };
    let raw = match lookup(NETWORK_SCAN_EMAILS_VAR) {
        Some(value) => value.into_string().map_err(|_| invalid())?,
        None => String::new(),
    };
    NetworkScanEmails::parse(&raw).map_err(|_| invalid())
}

/// Lee una variable opcional: recorta espacios y trata ausente, en blanco o
/// no UTF-8 como no definida.
fn read_optional(
    lookup: &impl Fn(&str) -> Option<OsString>,
    variable: &'static str,
) -> Option<String> {
    lookup(variable)
        .and_then(|value| value.into_string().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Lee `SECURITY_EVENTS_STREAM_NAME`: ausente o en blanco = sin publicación.
/// Un valor que no es un nombre de stream de Kinesis (`[a-zA-Z0-9_.-]`, hasta
/// 128 caracteres) o que no es UTF-8 falla el arranque; el error nombra la
/// variable, nunca el valor.
fn read_stream_name(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<Option<String>, ConfigError> {
    let invalid = || ConfigError::InvalidStreamName {
        variable: SECURITY_EVENTS_STREAM_NAME_VAR,
    };
    let Some(raw) = lookup(SECURITY_EVENTS_STREAM_NAME_VAR) else {
        return Ok(None);
    };
    let raw = raw.into_string().map_err(|_| invalid())?;
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let valid = value.chars().count() <= MAX_STREAM_NAME_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if valid {
        Ok(Some(value.to_owned()))
    } else {
        Err(invalid())
    }
}

/// Lee una variable de entorno requerida, devolviendo un
/// [`ConfigError::MissingVar`] tipado (nunca un panic) si está ausente o no
/// es UTF-8 válido.
fn read_required(
    lookup: &impl Fn(&str) -> Option<OsString>,
    variable: &'static str,
) -> Result<String, ConfigError> {
    lookup(variable)
        .and_then(|value| value.into_string().ok())
        .ok_or(ConfigError::MissingVar { variable })
}

/// Error devuelto por [`Config::from_env`] cuando la configuración no puede
/// cargarse correctamente.
///
/// Ninguna variante contiene el valor de una variable de entorno: solo su
/// nombre, para no filtrar por accidente un secreto en el mensaje de error
/// (ver `docs/security-scope.md`).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Falta una variable de entorno requerida.
    #[error("falta la variable de entorno requerida: {variable}")]
    MissingVar {
        /// Nombre de la variable de entorno ausente.
        variable: &'static str,
    },
    /// El valor de una variable de entorno no tiene el formato esperado.
    #[error("la variable de entorno {variable} no contiene un puerto TCP válido")]
    InvalidPort {
        /// Nombre de la variable de entorno con el valor inválido.
        variable: &'static str,
    },
    /// El valor de `CREDENTIALS_ENCRYPTION_KEY` no es un hex de 64
    /// caracteres (no decodifica a 32 bytes).
    #[error(
        "la variable de entorno {variable} no contiene una clave de cifrado de 32 bytes \
         (hex de 64 caracteres)"
    )]
    InvalidEncryptionKey {
        /// Nombre de la variable de entorno con el valor inválido.
        variable: &'static str,
    },
    /// `SECURITY_EVENTS_STREAM_NAME` no es un nombre de stream de Kinesis
    /// válido. No incluye el valor.
    #[error("la variable de entorno {variable} no contiene un nombre de stream de Kinesis válido")]
    InvalidStreamName {
        /// Nombre de la variable de entorno con el valor inválido.
        variable: &'static str,
    },
    /// Alguna entrada de `ADMIN_BOOTSTRAP_EMAILS` no es un correo válido. No
    /// incluye el valor, que puede ser un correo real mal escrito.
    #[error("la variable de entorno {variable} contiene una entrada que no es un correo válido")]
    InvalidAdminEmails {
        /// Nombre de la variable de entorno con el valor inválido.
        variable: &'static str,
    },
    /// An `SMTP_*` variable is invalid or the set is incomplete. Names the
    /// variable only: the values include a password.
    #[error("the environment variable {variable} is invalid or incomplete for the SMTP settings")]
    InvalidSmtp {
        /// Name of the offending variable.
        variable: &'static str,
    },
    /// SMTP credentials with `SMTP_TLS=none` would travel in plain text.
    /// Names the variables only, never their values.
    #[error(
        "SMTP_TLS=none sends in plain text, so SMTP_USERNAME and SMTP_PASSWORD must not be set \
         with it: use SMTP_TLS=starttls or remove the credentials"
    )]
    InsecureSmtpCredentials,
    /// A report email reaper variable is not a whole number of seconds >= 1.
    #[error(
        "the environment variable {variable} must be a whole number of seconds, at least 1 \
         (REPORT_EMAIL_REAPER_AFTER_SECS: at least 120)"
    )]
    InvalidReportEmailReaper {
        /// Name of the offending variable.
        variable: &'static str,
    },
    /// Alguna entrada de `NETWORK_SCAN_EMAILS` no es un correo válido. No
    /// incluye el valor, que puede ser un correo real mal escrito.
    #[error("la variable de entorno {variable} contiene una entrada que no es un correo válido")]
    InvalidNetworkScanEmails {
        /// Nombre de la variable de entorno con el valor inválido.
        variable: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::OsString;

    use secrecy::ExposeSecret;

    use super::*;

    const SECRET_VALUE: &str = "top-secret-gateway-credential";

    /// Clave de cifrado de laboratorio: 32 bytes (0x07) codificados en hex.
    fn encryption_key_hex() -> &'static str {
        /// 64 caracteres: "07" * 32 bytes.
        const HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";
        HEX
    }

    /// Entorno en memoria: sustituye al entorno global del proceso, de modo
    /// que los tests no mutan estado compartido ni dependen de las variables
    /// de la shell de quien los ejecuta.
    struct FakeEnv(HashMap<&'static str, OsString>);

    impl FakeEnv {
        fn valid() -> Self {
            let mut env = FakeEnv(HashMap::new());
            env.set(DATABASE_URL_VAR, "postgres://user:pass@localhost/db");
            env.set(HTTP_HOST_VAR, "0.0.0.0");
            env.set(HTTP_PORT_VAR, "8080");
            env.set(GATEWAY_SHARED_SECRET_VAR, SECRET_VALUE);
            env.set(CREDENTIALS_ENCRYPTION_KEY_VAR, encryption_key_hex());
            env
        }

        fn set(&mut self, name: &'static str, value: impl Into<OsString>) {
            self.0.insert(name, value.into());
        }

        fn remove(&mut self, name: &'static str) {
            self.0.remove(name);
        }

        fn load(&self) -> Result<Config, ConfigError> {
            Config::from_lookup(|name| self.0.get(name).cloned())
        }
    }

    #[test]
    fn from_lookup_loads_valid_config_successfully() {
        let config = FakeEnv::valid()
            .load()
            .expect("la configuración válida debe cargar sin error");

        assert_eq!(config.database_url, "postgres://user:pass@localhost/db");
        assert_eq!(config.http_host, "0.0.0.0");
        assert_eq!(config.http_port, 8080);
        assert_eq!(config.gateway_shared_secret.expose_secret(), SECRET_VALUE);
        assert_eq!(
            config.credentials_encryption_key.expose_secret(),
            &[0x07u8; 32]
        );
    }

    #[test]
    fn from_lookup_returns_typed_error_when_encryption_key_is_missing() {
        let mut env = FakeEnv::valid();
        env.remove(CREDENTIALS_ENCRYPTION_KEY_VAR);

        assert!(matches!(
            env.load(),
            Err(ConfigError::MissingVar {
                variable: CREDENTIALS_ENCRYPTION_KEY_VAR
            })
        ));
    }

    #[test]
    fn from_lookup_returns_typed_error_when_encryption_key_is_not_valid_hex_of_32_bytes() {
        let mut env = FakeEnv::valid();
        env.set(CREDENTIALS_ENCRYPTION_KEY_VAR, "no-es-hex");

        assert!(matches!(
            env.load(),
            Err(ConfigError::InvalidEncryptionKey {
                variable: CREDENTIALS_ENCRYPTION_KEY_VAR
            })
        ));

        // Longitud incorrecta (62 caracteres hex = 31 bytes) también es un
        // error tipado.
        env.set(
            CREDENTIALS_ENCRYPTION_KEY_VAR,
            "07070707070707070707070707070707070707070707070707070707070707",
        );

        assert!(matches!(
            env.load(),
            Err(ConfigError::InvalidEncryptionKey {
                variable: CREDENTIALS_ENCRYPTION_KEY_VAR
            })
        ));
    }

    #[test]
    fn from_lookup_defaults_to_no_admins_when_admin_bootstrap_emails_is_unset_or_empty() {
        let mut env = FakeEnv::valid();

        let config = env
            .load()
            .expect("la configuración válida debe cargar sin error");
        assert!(config.admin_bootstrap_emails.is_empty());

        env.set(ADMIN_BOOTSTRAP_EMAILS_VAR, "  ");
        let config = env
            .load()
            .expect("la configuración válida debe cargar sin error");
        assert!(config.admin_bootstrap_emails.is_empty());
    }

    #[test]
    fn from_lookup_loads_admin_bootstrap_emails_trimmed_and_case_insensitive() {
        let mut env = FakeEnv::valid();
        env.set(
            ADMIN_BOOTSTRAP_EMAILS_VAR,
            " Admin-1@Example.test, admin-2@example.test ",
        );

        let config = env
            .load()
            .expect("la configuración válida debe cargar sin error");

        assert_eq!(config.admin_bootstrap_emails.len(), 2);
        assert!(config
            .admin_bootstrap_emails
            .contains("admin-1@example.test"));
        assert!(config
            .admin_bootstrap_emails
            .contains("ADMIN-2@example.test"));
    }

    #[test]
    fn from_lookup_returns_typed_error_without_the_value_when_an_admin_email_is_invalid() {
        let mut env = FakeEnv::valid();
        env.set(
            ADMIN_BOOTSTRAP_EMAILS_VAR,
            "admin-1@example.test,secret-typo",
        );

        let error = env.load().expect_err("una entrada inválida debe fallar");

        assert!(matches!(
            error,
            ConfigError::InvalidAdminEmails {
                variable: ADMIN_BOOTSTRAP_EMAILS_VAR
            }
        ));
        assert!(!error.to_string().contains("secret-typo"));
    }

    #[test]
    fn debug_format_of_config_never_contains_admin_emails() {
        let mut env = FakeEnv::valid();
        env.set(ADMIN_BOOTSTRAP_EMAILS_VAR, "admin-1@example.test");
        let config = env
            .load()
            .expect("la configuración válida debe cargar sin error");

        let debug_output = format!("{config:?}");

        assert!(!debug_output.contains("admin-1"));
    }

    #[test]
    fn from_lookup_defaults_to_nobody_when_network_scan_emails_is_unset_or_empty() {
        let mut env = FakeEnv::valid();
        assert!(env.load().unwrap().network_scan_emails.is_empty());

        env.set(NETWORK_SCAN_EMAILS_VAR, "  ");
        assert!(env.load().unwrap().network_scan_emails.is_empty());
    }

    #[test]
    fn from_lookup_loads_network_scan_emails_trimmed_and_case_insensitive() {
        let mut env = FakeEnv::valid();
        env.set(
            NETWORK_SCAN_EMAILS_VAR,
            " Ana@Example.test, bob@example.test ",
        );

        let config = env.load().unwrap();

        assert_eq!(config.network_scan_emails.len(), 2);
        assert!(config.network_scan_emails.contains("ana@example.test"));
        assert!(config.network_scan_emails.contains("BOB@example.test"));
        assert!(config.admin_bootstrap_emails.is_empty());
    }

    #[test]
    fn from_lookup_returns_typed_error_without_the_value_when_a_network_scan_email_is_invalid() {
        let mut env = FakeEnv::valid();
        env.set(NETWORK_SCAN_EMAILS_VAR, "ana@example.test,secret-typo");

        let error = env.load().expect_err("una entrada inválida debe fallar");

        assert!(matches!(
            error,
            ConfigError::InvalidNetworkScanEmails {
                variable: NETWORK_SCAN_EMAILS_VAR
            }
        ));
        assert!(!error.to_string().contains("secret-typo"));
    }

    #[test]
    fn debug_format_of_config_never_contains_network_scan_emails() {
        let mut env = FakeEnv::valid();
        env.set(NETWORK_SCAN_EMAILS_VAR, "ana-secret@example.test");

        let debug_output = format!("{:?}", env.load().unwrap());

        assert!(!debug_output.contains("ana-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn from_lookup_fails_closed_when_network_scan_emails_is_not_valid_utf8() {
        use std::os::unix::ffi::OsStringExt;

        let mut env = FakeEnv::valid();
        env.set(
            NETWORK_SCAN_EMAILS_VAR,
            OsString::from_vec(vec![0xff, 0xfe]),
        );

        assert!(matches!(
            env.load(),
            Err(ConfigError::InvalidNetworkScanEmails {
                variable: NETWORK_SCAN_EMAILS_VAR
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn from_lookup_fails_closed_when_admin_bootstrap_emails_is_not_valid_utf8() {
        use std::os::unix::ffi::OsStringExt;

        let mut env = FakeEnv::valid();
        env.set(
            ADMIN_BOOTSTRAP_EMAILS_VAR,
            OsString::from_vec(vec![0xff, 0xfe]),
        );

        assert!(matches!(
            env.load(),
            Err(ConfigError::InvalidAdminEmails {
                variable: ADMIN_BOOTSTRAP_EMAILS_VAR
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn from_lookup_treats_non_utf8_required_var_as_missing() {
        use std::os::unix::ffi::OsStringExt;

        let mut env = FakeEnv::valid();
        env.set(HTTP_HOST_VAR, OsString::from_vec(vec![0xff, 0xfe]));

        assert!(matches!(
            env.load(),
            Err(ConfigError::MissingVar {
                variable: HTTP_HOST_VAR
            })
        ));
    }

    #[test]
    fn from_lookup_returns_typed_error_when_required_var_is_missing() {
        let mut env = FakeEnv::valid();
        env.remove(GATEWAY_SHARED_SECRET_VAR);

        assert!(matches!(
            env.load(),
            Err(ConfigError::MissingVar {
                variable: GATEWAY_SHARED_SECRET_VAR
            })
        ));
    }

    #[test]
    fn from_lookup_returns_typed_error_when_port_is_not_a_valid_u16() {
        let mut env = FakeEnv::valid();
        env.set(HTTP_PORT_VAR, "not-a-port");

        assert!(matches!(
            env.load(),
            Err(ConfigError::InvalidPort {
                variable: HTTP_PORT_VAR
            })
        ));
    }

    #[test]
    fn from_lookup_loads_migrations_database_url_when_present() {
        let mut env = FakeEnv::valid();
        env.set(
            MIGRATIONS_DATABASE_URL_VAR,
            "postgres://migrator:pass@localhost/db",
        );

        let config = env
            .load()
            .expect("la configuración válida debe cargar sin error");

        assert_eq!(
            config.migrations_database_url,
            "postgres://migrator:pass@localhost/db"
        );
        assert_eq!(config.database_url, "postgres://user:pass@localhost/db");
    }

    #[test]
    fn from_lookup_falls_back_to_database_url_when_migrations_database_url_is_absent() {
        let config = FakeEnv::valid()
            .load()
            .expect("la configuración válida debe cargar sin error");

        assert_eq!(config.migrations_database_url, config.database_url);
    }

    #[test]
    fn debug_format_of_config_never_contains_the_raw_secret() {
        let config = FakeEnv::valid()
            .load()
            .expect("la configuración válida debe cargar sin error");

        let debug_output = format!("{config:?}");

        assert!(
            !debug_output.contains(SECRET_VALUE),
            "el Debug de Config no debe filtrar la credencial de servicio"
        );
        assert!(
            !debug_output.contains(encryption_key_hex()),
            "el Debug de Config no debe filtrar la clave de cifrado de credenciales"
        );
    }

    #[test]
    fn security_events_are_disabled_when_the_stream_name_is_unset_or_blank() {
        let config = FakeEnv::valid().load().expect("config válida");
        assert_eq!(config.security_events_stream_name, None);
        for blank in ["", "   ", "\t"] {
            let mut env = FakeEnv::valid();
            env.set(SECURITY_EVENTS_STREAM_NAME_VAR, blank);
            let config = env.load().expect("config válida");
            assert_eq!(
                config.security_events_stream_name, None,
                "{blank:?} debe tratarse como no definida"
            );
        }
    }

    #[test]
    fn security_events_stream_name_is_trimmed_and_loaded() {
        let mut env = FakeEnv::valid();
        env.set(SECURITY_EVENTS_STREAM_NAME_VAR, " security-events ");
        let config = env.load().expect("config válida");
        assert_eq!(
            config.security_events_stream_name.as_deref(),
            Some("security-events")
        );
    }

    #[test]
    fn invalid_security_events_stream_name_is_a_typed_error_without_the_value() {
        let too_long = "a".repeat(129);
        for invalid in ["has space", "semi;colon", "ñandú", too_long.as_str()] {
            let mut env = FakeEnv::valid();
            env.set(SECURITY_EVENTS_STREAM_NAME_VAR, invalid);
            let err = env.load().expect_err("nombre inválido");
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidStreamName { variable }
                        if variable == SECURITY_EVENTS_STREAM_NAME_VAR
                ),
                "esperaba InvalidStreamName para {invalid:?}, obtuve {err:?}"
            );
            assert!(!err.to_string().contains(invalid), "{err}");
        }
    }

    #[test]
    fn aws_region_and_endpoint_are_optional_trimmed_and_blank_means_unset() {
        let config = FakeEnv::valid().load().expect("config válida");
        assert_eq!(config.aws_region, None);
        assert_eq!(config.aws_endpoint_url, None);

        let mut env = FakeEnv::valid();
        env.set(AWS_REGION_VAR, " us-east-1 ");
        env.set(AWS_ENDPOINT_URL_VAR, " http://localstack:4566 ");
        let config = env.load().expect("config válida");
        assert_eq!(config.aws_region.as_deref(), Some("us-east-1"));
        assert_eq!(
            config.aws_endpoint_url.as_deref(),
            Some("http://localstack:4566")
        );

        let mut env = FakeEnv::valid();
        env.set(AWS_REGION_VAR, "  ");
        env.set(AWS_ENDPOINT_URL_VAR, "");
        let config = env.load().expect("config válida");
        assert_eq!(config.aws_region, None);
        assert_eq!(config.aws_endpoint_url, None);
    }

    fn smtp_env() -> FakeEnv {
        let mut env = FakeEnv::valid();
        env.set("SMTP_HOST", "smtp.gmail.com");
        env.set("SMTP_USERNAME", "reports@example.test");
        env.set("SMTP_PASSWORD", "app-password-value");
        env
    }

    #[test]
    fn smtp_is_disabled_when_the_host_is_unset_or_blank() {
        assert!(FakeEnv::valid().load().unwrap().smtp.is_none());
        let mut env = smtp_env();
        env.set("SMTP_HOST", "  ");
        assert!(env.load().unwrap().smtp.is_none());
    }

    #[test]
    fn smtp_defaults_to_port_587_required_starttls_and_the_username_as_sender() {
        let smtp = smtp_env().load().unwrap().smtp.expect("smtp configured");
        assert_eq!(smtp.host, "smtp.gmail.com");
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.tls, crate::report_email::smtp::SmtpTls::StartTls);
        assert_eq!(smtp.from, "reports@example.test");
        assert_eq!(smtp.username.as_deref(), Some("reports@example.test"));
        assert_eq!(
            smtp.password.as_ref().unwrap().expose_secret(),
            "app-password-value"
        );
    }

    #[test]
    fn smtp_from_overrides_the_username_and_port_and_tls_none_are_explicit() {
        let mut env = FakeEnv::valid();
        env.set("SMTP_HOST", "mailpit");
        env.set("SMTP_PORT", "1025");
        env.set("SMTP_TLS", "none");
        env.set("SMTP_FROM", "noreply@example.test");
        let smtp = env.load().unwrap().smtp.expect("smtp configured");
        assert_eq!(smtp.port, 1025);
        assert_eq!(smtp.tls, crate::report_email::smtp::SmtpTls::None);
        assert_eq!(smtp.from, "noreply@example.test");
        assert!(smtp.username.is_none() && smtp.password.is_none());
    }

    #[test]
    fn invalid_smtp_settings_fail_without_echoing_values() {
        for (name, value) in [
            ("SMTP_PORT", "not-a-port"),
            ("SMTP_TLS", "opportunistic"),
            ("SMTP_FROM", "not an address"),
        ] {
            let mut env = smtp_env();
            env.set(name, value);
            let err = env.load().expect_err("must fail closed");
            assert!(!err.to_string().contains(value), "{err}");
        }
        // Password without user, or neither user nor from: incomplete.
        let mut env = smtp_env();
        env.remove("SMTP_USERNAME");
        assert!(env.load().is_err());
        let mut env = FakeEnv::valid();
        env.set("SMTP_HOST", "mailpit");
        assert!(env.load().is_err(), "no sender address");
    }

    #[test]
    fn smtp_tls_none_with_credentials_is_refused_naming_the_variables_not_the_values() {
        let cases: [&[(&'static str, &'static str)]; 3] = [
            &[
                ("SMTP_USERNAME", "reports@example.test"),
                ("SMTP_PASSWORD", "plain-secret-pw"),
            ],
            &[("SMTP_USERNAME", "reports@example.test")],
            &[("SMTP_PASSWORD", "plain-secret-pw")],
        ];
        for creds in cases {
            let mut env = FakeEnv::valid();
            env.set("SMTP_HOST", "mailpit");
            env.set("SMTP_TLS", "none");
            env.set("SMTP_FROM", "noreply@example.test");
            for (name, value) in creds {
                env.set(name, *value);
            }
            let err = env.load().expect_err("credentials over plain text");
            assert!(matches!(err, ConfigError::InsecureSmtpCredentials), "{err}");
            let text = err.to_string();
            for named in ["SMTP_TLS", "SMTP_USERNAME", "SMTP_PASSWORD"] {
                assert!(text.contains(named), "{text}");
            }
            assert!(!text.contains("plain-secret-pw") && !text.contains("reports@example.test"));
        }
    }

    #[test]
    fn smtp_credentials_stay_valid_with_starttls_and_mailpit_without_them_stays_valid() {
        for tls in [None, Some("starttls")] {
            let mut env = smtp_env();
            if let Some(tls) = tls {
                env.set("SMTP_TLS", tls);
            }
            assert!(env.load().unwrap().smtp.is_some());
        }
        let mut env = FakeEnv::valid();
        env.set("SMTP_HOST", "mailpit");
        env.set("SMTP_TLS", "none");
        env.set("SMTP_FROM", "noreply@example.test");
        // Blank credentials count as unset.
        env.set("SMTP_USERNAME", " ");
        env.set("SMTP_PASSWORD", "");
        assert!(env.load().unwrap().smtp.is_some());
    }

    fn invalid_smtp_variable(env: &FakeEnv) -> &'static str {
        match env.load().expect_err("an unusable SMTP config must fail") {
            ConfigError::InvalidSmtp { variable } => variable,
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn an_unusable_smtp_config_with_a_host_fails_naming_the_variable() {
        let with = |name: &'static str, value: &'static str| {
            let mut env = smtp_env();
            env.set(name, value);
            env
        };
        assert_eq!(
            invalid_smtp_variable(&with("SMTP_PORT", "abc")),
            "SMTP_PORT"
        );
        assert_eq!(
            invalid_smtp_variable(&with("SMTP_PORT", "70000")),
            "SMTP_PORT"
        );
        assert_eq!(invalid_smtp_variable(&with("SMTP_PORT", "-1")), "SMTP_PORT");
        assert_eq!(invalid_smtp_variable(&with("SMTP_TLS", "tls")), "SMTP_TLS");
        assert_eq!(
            invalid_smtp_variable(&with("SMTP_FROM", "nope")),
            "SMTP_FROM"
        );
        assert_eq!(
            invalid_smtp_variable(&with("SMTP_HOST", "bad host")),
            "SMTP_HOST"
        );
        // No explicit sender and no username to default to.
        let mut env = FakeEnv::valid();
        env.set("SMTP_HOST", "smtp.example.test");
        assert_eq!(invalid_smtp_variable(&env), "SMTP_FROM");
        // Only one of username and password.
        let mut env = smtp_env();
        env.remove("SMTP_PASSWORD");
        assert_eq!(invalid_smtp_variable(&env), "SMTP_PASSWORD");
        let mut env = smtp_env();
        env.remove("SMTP_USERNAME");
        env.set("SMTP_FROM", "reports@example.test");
        assert_eq!(invalid_smtp_variable(&env), "SMTP_PASSWORD");
    }

    #[test]
    fn the_lab_placeholder_of_single_spaces_keeps_email_disabled() {
        let mut env = FakeEnv::valid();
        for name in ["SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD"] {
            env.set(name, " ");
        }
        assert!(env
            .load()
            .expect("a fresh lab deploy must start")
            .smtp
            .is_none());
    }

    #[test]
    fn config_debug_never_contains_the_smtp_password() {
        let debug = format!("{:?}", smtp_env().load().unwrap());
        assert!(!debug.contains("app-password-value"));
    }

    #[test]
    fn the_report_email_reaper_defaults_to_ten_minutes_checked_every_minute() {
        let reaper = FakeEnv::valid().load().unwrap().report_email_reaper;
        assert_eq!(reaper.after, Duration::from_secs(600));
        assert_eq!(reaper.interval, Duration::from_secs(60));
    }

    #[test]
    fn the_report_email_reaper_reads_both_durations_in_seconds() {
        let mut env = FakeEnv::valid();
        env.set("REPORT_EMAIL_REAPER_AFTER_SECS", "120");
        env.set("REPORT_EMAIL_REAPER_INTERVAL_SECS", "5");
        let reaper = env.load().unwrap().report_email_reaper;
        assert_eq!(reaper.after, Duration::from_secs(120));
        assert_eq!(reaper.interval, Duration::from_secs(5));
    }

    #[test]
    fn an_invalid_reaper_duration_fails_naming_only_the_variable() {
        for (variable, value) in [
            ("REPORT_EMAIL_REAPER_AFTER_SECS", "soon"),
            ("REPORT_EMAIL_REAPER_AFTER_SECS", "0"),
            ("REPORT_EMAIL_REAPER_INTERVAL_SECS", "-3"),
            ("REPORT_EMAIL_REAPER_INTERVAL_SECS", "0"),
        ] {
            let mut env = FakeEnv::valid();
            env.set(variable, value);
            let error = env.load().unwrap_err();
            assert!(error.to_string().contains(variable), "{error}");
            assert!(
                !error.to_string().contains(value) || value == "0",
                "{error}"
            );
        }
    }

    #[test]
    fn a_reaper_threshold_below_the_minimum_is_refused() {
        let mut env = FakeEnv::valid();
        env.set("REPORT_EMAIL_REAPER_AFTER_SECS", "119");
        let error = env.load().unwrap_err();
        assert!(
            error.to_string().contains("REPORT_EMAIL_REAPER_AFTER_SECS"),
            "{error}"
        );
        assert!(error.to_string().contains("120"), "{error}");
    }
}
