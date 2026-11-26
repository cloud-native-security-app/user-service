//! Composition root: construye los pools de conexión a PostgreSQL definidos
//! por [`Config`], aplica las migraciones de `migrations/` y ensambla el
//! router `axum` completo del servicio (perfil, histórico, auditoría y
//! `GET /health`).
//!
//! ## Por qué dos pools
//!
//! `migrations/20260918120100_lock_audit_log_permissions.sql` deja el rol
//! de aplicación `ms_usuarios_app` sin permiso de `UPDATE`/`DELETE` sobre
//! `audit_log` (RF-15) — pero el dueño de una tabla en PostgreSQL se salta
//! cualquier `REVOKE`, así que el rol que aplica `sqlx::migrate!` (dueño de
//! las tablas) no puede ser el mismo que sirve tráfico HTTP real en
//! producción sin anular ese endurecimiento fuera de los tests. Por eso
//! [`build_router`] usa dos conexiones distintas:
//!
//! - [`Config::migrations_database_url`]: solo para aplicar migraciones al
//!   arrancar, nunca para servir tráfico.
//! - [`Config::database_url`]: el pool que recibe [`Repository`] y sirve
//!   las peticiones HTTP reales.
//!
//! En dev/test ambas variables pueden apuntar al mismo rol (o la segunda
//! puede omitirse por completo, ver `src/config.rs`); en producción el
//! operador las separa.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::api;
use crate::config::Config;
use crate::messaging::kinesis::KinesisSecurityEventPublisher;
use crate::messaging::sqs::{QueueSetupError, SqsReportEmailConsumer, SqsReportEmailPublisher};
use crate::report_email::mailer::Mailer;
use crate::report_email::queue::{
    check_lease_covers_attempt, check_reaper_window, LeaseTooShortError, ReaperWindowError,
    ReportEmailRequestPublisher,
};
use crate::report_email::service::{ReportEmailService, RetryPolicy};
use crate::report_email::smtp::SmtpMailer;
use crate::repository::Repository;
use crate::security_events::{NoopSecurityEventPublisher, SecurityEventPublisher};

/// Tiempo máximo de espera para establecer una conexión con PostgreSQL al
/// arrancar (pool de migraciones y pool de aplicación).
///
/// Sin este límite `sqlx` reintenta durante su valor por defecto (30 s) antes
/// de rendirse. 10 s sobra para un handshake TCP/TLS contra una base de datos
/// sana o recién levantada y, si no responde, el proceso falla con un error
/// tipado lo bastante rápido para que el orquestador lo reinicie.
const DATABASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The assembled service: the HTTP router and, in queue mode, the report email
/// consumer task. The consumer stops when the token given to [`build_app`] is
/// cancelled; await `consumer` afterwards so an in-flight email finishes.
pub struct App {
    /// The complete `axum` router.
    pub router: Router,
    /// The report email consumer task, `None` without the queue.
    pub consumer: Option<JoinHandle<()>>,
}

/// Aplica las migraciones pendientes de `migrations/` contra
/// [`Config::migrations_database_url`] y, si tiene éxito, construye el
/// router `axum` completo (perfil, histórico, auditoría y `GET /health`)
/// listo para servir tráfico sobre [`Config::database_url`].
///
/// `GET /health` queda deliberadamente fuera del middleware de
/// autenticación aplicado por [`api::router`]: un orquestador de
/// infraestructura (RNF-09) debe poder comprobar la salud del proceso sin
/// conocer la credencial de servicio Gateway↔`ms-usuarios`.
///
/// # Errores
///
/// Devuelve [`WiringError`] si no se puede conectar con cualquiera de los
/// dos pools, o si la aplicación de migraciones falla. Nunca hace
/// `panic!` ni deja el router a medio ensamblar.
///
/// Si hay cola del correo del informe, el consumidor queda en una tarea que
/// nadie detiene: usa [`build_app`] cuando haga falta un apagado ordenado.
pub async fn build_router(config: &Config) -> Result<Router, WiringError> {
    Ok(build_app(config, CancellationToken::new()).await?.router)
}

/// Igual que [`build_router`], pero devuelve también la tarea del consumidor de
/// la cola del correo del informe (si está configurada), que se detiene al
/// cancelar `shutdown`.
///
/// # Errores
///
/// Los de [`build_router`], más [`WiringError::ReportEmailQueueUnavailable`] y
/// [`WiringError::ReaperWindowTooShort`] en modo cola.
pub async fn build_app(config: &Config, shutdown: CancellationToken) -> Result<App, WiringError> {
    build_app_with_connect_timeout(config, shutdown, DATABASE_CONNECT_TIMEOUT).await
}

/// Igual que [`build_app`], pero con un `connect_timeout` explícito para
/// ambos pools; permite a los tests usar un límite corto sin cambiar el
/// valor de producción.
async fn build_app_with_connect_timeout(
    config: &Config,
    shutdown: CancellationToken,
    connect_timeout: Duration,
) -> Result<App, WiringError> {
    migrate(&config.migrations_database_url, connect_timeout).await?;

    let database_pool = PgPoolOptions::new()
        .acquire_timeout(connect_timeout)
        .connect(&config.database_url)
        .await
        .map_err(|_| WiringError::DatabaseConnectionFailed)?;

    let health_pool = database_pool.clone();
    let repository = Repository::new(database_pool, config.credentials_encryption_key.clone())
        .with_admin_emails(config.admin_bootstrap_emails.clone())
        .with_network_scan_emails(config.network_scan_emails.clone())
        .with_security_events(build_security_event_publisher(config).await);

    // La lista es autoritativa: concede y revoca el rol de los usuarios que ya
    // existen antes de servir tráfico (idempotente).
    let changed = repository.sync_admin_roles().await.map_err(|error| {
        // El detalle va solo al log del servidor (sin datos personales).
        tracing::error!(%error, "no se pudo reconciliar los roles de administrador");
        WiringError::AdminBootstrapFailed
    })?;
    tracing::info!(changed, "roles de administrador reconciliados al arrancar");

    // Igual para el permiso de escaneo en modo red: la lista es autoritativa.
    let changed = repository
        .sync_network_scan_permissions()
        .await
        .map_err(|error| {
            tracing::error!(%error, "no se pudo reconciliar el permiso de escaneo de red");
            WiringError::NetworkScanBootstrapFailed
        })?;
    tracing::info!(
        changed,
        "permisos de escaneo de red reconciliados al arrancar"
    );

    let repository = Arc::new(repository);
    let mailer = build_mailer(config);
    // The reaper retries sends lost to a shutdown or crash; it only runs when
    // email is enabled (it never starts without a mailer).
    // One policy for the service, the API fallback and the startup checks.
    let retry = RetryPolicy::default();
    let reaper = Arc::new(ReportEmailService::new(
        repository.clone(),
        mailer.clone(),
        retry,
    ));

    // Queue mode: read the queue attributes first, so a reaper window that
    // could take a live message's row fails the startup before anything runs.
    let (consumer, report_publisher) = match &config.report_email_queue {
        Some(urls) => {
            let consumer = SqsReportEmailConsumer::connect(
                config.aws_region.as_deref(),
                config.aws_endpoint_url.as_deref(),
                urls.queue_url.clone(),
                urls.dlq_url.clone(),
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, "report email queue: startup failed");
                WiringError::ReportEmailQueueUnavailable(error)
            })?;
            let settings = consumer.settings();
            check_lease_covers_attempt(&settings, retry.attempt_timeout).map_err(|source| {
                WiringError::QueueLeaseTooShort {
                    queue: urls.queue_url.clone(),
                    source,
                }
            })?;
            // The reaper only runs with a mailer, so only then can it race.
            if mailer.is_some() {
                check_reaper_window(
                    &settings,
                    config.report_email_reaper.after,
                    retry.attempt_timeout,
                )?;
            }
            tracing::info!(
                visibility_timeout_secs = settings.visibility_timeout.as_secs(),
                max_receives = settings.max_receives,
                "report email: sending through the SQS queue"
            );
            let publisher: Arc<dyn ReportEmailRequestPublisher> =
                Arc::new(SqsReportEmailPublisher::from_client(
                    consumer.client().clone(),
                    urls.queue_url.clone(),
                ));
            (Some(consumer), Some(publisher))
        }
        None => (None, None),
    };

    reaper.spawn_reaper(config.report_email_reaper);
    let consumer = consumer.map(|consumer| {
        let service = reaper.clone();
        tokio::spawn(async move { consumer.run(service, shutdown).await })
    });

    let api_router = api::router_with_report_queue(
        repository,
        config.gateway_shared_secret.clone(),
        Some((mailer, retry)),
        report_publisher,
    );
    let health_router = Router::new()
        .route("/health", get(health))
        .with_state(health_pool);

    Ok(App {
        router: health_router.merge(api_router),
        consumer,
    })
}

/// Builds the SMTP mailer, or `None` (report email disabled) when `SMTP_HOST`
/// is unset. Opens no connection. `Config::from_lookup` already rejected
/// settings that cannot build a transport, so that branch is unreachable.
fn build_mailer(config: &Config) -> Option<Arc<dyn Mailer>> {
    let Some(settings) = &config.smtp else {
        tracing::info!("report email disabled: SMTP_HOST is not set");
        return None;
    };
    match SmtpMailer::new(settings) {
        Ok(mailer) => {
            tracing::info!(host = %settings.host, port = settings.port, "report email: sending through SMTP");
            Some(Arc::new(mailer))
        }
        Err(_) => {
            tracing::error!("report email disabled: the SMTP settings are not usable (config validation should have refused them)");
            None
        }
    }
}

/// Elige el adaptador de eventos de seguridad según la configuración: Kinesis
/// si `SECURITY_EVENTS_STREAM_NAME` está definida, si no el no-op (con un
/// único log informativo al arrancar). No abre conexiones: un Kinesis
/// inalcanzable solo se nota al publicar y nunca impide arrancar.
async fn build_security_event_publisher(config: &Config) -> Arc<dyn SecurityEventPublisher> {
    match &config.security_events_stream_name {
        Some(stream_name) => {
            tracing::info!(stream = %stream_name, "eventos de seguridad: publicando en Kinesis");
            Arc::new(
                KinesisSecurityEventPublisher::connect(
                    config.aws_region.as_deref(),
                    config.aws_endpoint_url.as_deref(),
                    stream_name.clone(),
                )
                .await,
            )
        }
        None => {
            tracing::info!(
                "eventos de seguridad desactivados: SECURITY_EVENTS_STREAM_NAME no está definida"
            );
            Arc::new(NoopSecurityEventPublisher)
        }
    }
}

/// Conecta con `migrations_database_url` y aplica las migraciones
/// pendientes de `migrations/` (`sqlx::migrate!`, embebidas en el binario en
/// tiempo de compilación). El pool se cierra al terminar: solo migra el
/// esquema, nunca sirve tráfico HTTP.
async fn migrate(
    migrations_database_url: &str,
    connect_timeout: Duration,
) -> Result<(), WiringError> {
    let migrations_pool = PgPoolOptions::new()
        .acquire_timeout(connect_timeout)
        .connect(migrations_database_url)
        .await
        .map_err(|_| WiringError::MigrationsConnectionFailed)?;

    let result = sqlx::migrate!("./migrations").run(&migrations_pool).await;

    migrations_pool.close().await;

    result.map_err(|_| WiringError::MigrationFailed)
}

/// `GET /health` (RNF-09): responde `200 OK` si el pool de aplicación puede
/// ejercer una consulta trivial (`SELECT 1`) contra PostgreSQL, o
/// `503 Service Unavailable` si falla — no se limita a confirmar que el
/// proceso está vivo.
async fn health(State(pool): State<PgPool>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&pool).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Error devuelto por [`build_router`] cuando el servicio no puede
/// inicializar su capa de persistencia.
///
/// Ninguna variante incluye el mensaje crudo de `sqlx` (que podría incluir
/// la URL de conexión, con credenciales) — ver `docs/security-scope.md`.
#[derive(Debug, thiserror::Error)]
pub enum WiringError {
    /// No se pudo conectar a la base de datos con el pool de migraciones.
    #[error("no se pudo conectar a la base de datos para aplicar migraciones")]
    MigrationsConnectionFailed,
    /// La aplicación de migraciones pendientes falló.
    #[error("fallo al aplicar las migraciones de base de datos")]
    MigrationFailed,
    /// No se pudo conectar a la base de datos con el pool de aplicación.
    #[error("no se pudo conectar a la base de datos de aplicación")]
    DatabaseConnectionFailed,
    /// No se pudo reconciliar el rol de administrador con
    /// `ADMIN_BOOTSTRAP_EMAILS`.
    #[error("fallo al reconciliar los roles de administrador")]
    AdminBootstrapFailed,
    /// No se pudo reconciliar el permiso de escaneo de red con
    /// `NETWORK_SCAN_EMAILS`.
    #[error("fallo al reconciliar el permiso de escaneo de red")]
    NetworkScanBootstrapFailed,
    /// The report email queue could not be read or is not usable at startup.
    #[error("la cola del correo del informe no está disponible: {0}")]
    ReportEmailQueueUnavailable(#[from] QueueSetupError),
    /// The lease of the queue does not exceed one SMTP attempt.
    #[error("la cola {queue} no sirve para el correo del informe: {source}")]
    QueueLeaseTooShort {
        /// URL of the queue.
        queue: String,
        /// The values compared.
        #[source]
        source: LeaseTooShortError,
    },
    /// `REPORT_EMAIL_REAPER_AFTER_SECS` does not outlast the queue window.
    #[error("{0}")]
    ReaperWindowTooShort(#[from] ReaperWindowError),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::{SecretBox, SecretString};
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    /// Puerto de loopback que no tiene nada escuchando: usado para
    /// verificar, sin depender de Docker, que un fallo de conectividad se
    /// traduce en un `WiringError`/`503` tipado en vez de un panic (mismo
    /// patrón que `repository.rs`).
    const UNREACHABLE_URL: &str = "postgres://user:pass@127.0.0.1:1/db";

    #[tokio::test]
    async fn health_returns_503_when_postgres_is_unreachable() {
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy(UNREACHABLE_URL)
            .expect("connect_lazy no debe fallar de forma síncrona");

        let status = health(State(pool)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn build_router_returns_typed_error_when_migrations_database_is_unreachable() {
        let config = Config {
            database_url: UNREACHABLE_URL.to_string(),
            http_host: "127.0.0.1".to_string(),
            http_port: 0,
            gateway_shared_secret: SecretString::from("test-secret".to_string()),
            credentials_encryption_key: SecretBox::from(vec![0x07u8; 32].into_boxed_slice()),
            migrations_database_url: UNREACHABLE_URL.to_string(),
            admin_bootstrap_emails: Default::default(),
            network_scan_emails: Default::default(),
            security_events_stream_name: None,
            aws_region: None,
            aws_endpoint_url: None,
            smtp: None,
            report_email_reaper: Default::default(),
            report_email_queue: None,
        };

        // Cota de seguridad ante cuelgues: con `acquire_timeout` de 1 s el
        // fallo llega en ~1 s; 10 s detecta una regresión (antes: 30 s).
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            build_app_with_connect_timeout(
                &config,
                CancellationToken::new(),
                Duration::from_secs(1),
            ),
        )
        .await
        .expect("la conexión inalcanzable debe fallar dentro de una cota, no colgarse");

        assert!(matches!(
            result,
            Err(WiringError::MigrationsConnectionFailed)
        ));
    }

    fn config_with(extra: &'static [(&'static str, &'static str)]) -> Config {
        Config::from_lookup(|name| {
            let base = [
                ("DATABASE_URL", "postgres://u:p@localhost/db"),
                ("HTTP_HOST", "127.0.0.1"),
                ("HTTP_PORT", "0"),
                ("GATEWAY_SHARED_SECRET", "s"),
                (
                    "CREDENTIALS_ENCRYPTION_KEY",
                    "0707070707070707070707070707070707070707070707070707070707070707",
                ),
            ];
            base.iter()
                .chain(extra.iter())
                .find(|(key, _)| *key == name)
                .map(|(_, value)| std::ffi::OsString::from(value))
        })
        .expect("valid config")
    }

    #[test]
    fn build_mailer_is_none_without_smtp_host_and_some_with_it() {
        assert!(build_mailer(&config_with(&[])).is_none());
        let with_smtp = config_with(&[
            ("SMTP_HOST", "smtp.example.test"),
            ("SMTP_USERNAME", "reports@example.test"),
            ("SMTP_PASSWORD", "pw"),
        ]);
        assert!(build_mailer(&with_smtp).is_some());
    }
}
