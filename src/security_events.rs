//! Puerto de eventos de seguridad de `user-service` y su tipo de mensaje
//! (feature `security_event_publisher`, tarea KAP-08): hechos inmutables que se
//! publican en el Kinesis Data Stream `security-events` para que el panel de
//! administración (KAP-09) y otros consumidores los lean sin acoplarse a quien
//! los produce. El contrato es `broker/contracts/security-event.schema.json`;
//! `tests/security_event_contract.rs` valida cada evento emitido contra él.
//! Es el espejo del módulo homónimo del Gateway (KAP-06) y de ms-nmap (KAP-07).
//!
//! `user-service` produce un solo tipo, `audit.recorded`, uno por cada entrada
//! que escribe en `audit_log` (ver [`crate::audit::recorded_event`] para el
//! mapeo de acciones). [`EventType`] cubre los 11 valores del contrato para
//! poder deserializar los ejemplos.
//!
//! Los adaptadores viven en [`crate::messaging::kinesis`] (real) y en este
//! módulo ([`NoopSecurityEventPublisher`], [`RecordingSecurityEventPublisher`]).
//!
//! ## Decisiones de diseño
//!
//! - **Un fallo de publicación nunca llega a la operación de negocio**: los
//!   puntos de emisión usan [`emit`]/[`emit_all`], que publican en una tarea
//!   `tokio` desacoplada con un tope de [`PUBLISH_TIMEOUT`] por evento y solo
//!   loggean el tipo de evento. El costo es que un evento puede perderse si el
//!   proceso muere antes de que la tarea corra; es aceptable porque
//!   `audit_log` es la fuente de verdad.
//! - **Los constructores validan el schema**: el constructor tipado rechaza con
//!   [`InvalidSecurityEvent`] un valor que el schema no aceptaría (largo,
//!   patrón). El error nombra el campo, nunca el valor.
//! - **Nada sensible**: ningún evento lleva correo, nombre, credenciales,
//!   material cifrado ni texto libre; la acción y el tipo de recurso son
//!   códigos cortos.
//! - **Clave de partición**: `actor_sub` ([`SecurityEvent::partition_key`]),
//!   como fija el plan para los eventos de auditoría.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Tiempo máximo que la tarea de [`emit`]/[`emit_all`] espera a que el
/// adaptador publique cada evento antes de soltarlo.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Máximo de caracteres de `actor_sub` según el schema.
const MAX_ACTOR_SUB_CHARS: usize = 128;
/// Máximo de caracteres de un slug de acción o tipo de recurso.
const MAX_SLUG_CHARS: usize = 64;

/// Tipo de un [`SecurityEvent`]; cubre los 11 valores del contrato aunque
/// `user-service` solo produce [`EventType::AuditRecorded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Un usuario pidió un escaneo y el Broker lo aceptó.
    #[serde(rename = "scan.requested")]
    ScanRequested,
    /// Un usuario pidió cancelar un escaneo y el Broker lo aceptó.
    #[serde(rename = "scan.cancelled")]
    ScanCancelled,
    /// ms-nmap empezó un escaneo.
    #[serde(rename = "scan.started")]
    ScanStarted,
    /// ms-nmap terminó un escaneo.
    #[serde(rename = "scan.completed")]
    ScanCompleted,
    /// ms-nmap falló un escaneo.
    #[serde(rename = "scan.failed")]
    ScanFailed,
    /// ms-nmap encontró un hallazgo alto o crítico.
    #[serde(rename = "finding.critical")]
    FindingCritical,
    /// Un usuario completó el login.
    #[serde(rename = "auth.login")]
    AuthLogin,
    /// Un usuario cerró sesión.
    #[serde(rename = "auth.logout")]
    AuthLogout,
    /// Una petición superó el límite de tasa.
    #[serde(rename = "ratelimit.hit")]
    RatelimitHit,
    /// Un mensaje se envió a una dead-letter queue.
    #[serde(rename = "message.deadlettered")]
    MessageDeadlettered,
    /// `user-service` registró una acción de auditoría.
    #[serde(rename = "audit.recorded")]
    AuditRecorded,
}

impl EventType {
    /// Valor del contrato (`audit.recorded`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScanRequested => "scan.requested",
            Self::ScanCancelled => "scan.cancelled",
            Self::ScanStarted => "scan.started",
            Self::ScanCompleted => "scan.completed",
            Self::ScanFailed => "scan.failed",
            Self::FindingCritical => "finding.critical",
            Self::AuthLogin => "auth.login",
            Self::AuthLogout => "auth.logout",
            Self::RatelimitHit => "ratelimit.hit",
            Self::MessageDeadlettered => "message.deadlettered",
            Self::AuditRecorded => "audit.recorded",
        }
    }
}

/// Servicio que produjo un [`SecurityEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    /// El Gateway.
    #[serde(rename = "gateway")]
    Gateway,
    /// ms-nmap.
    #[serde(rename = "nmap-service")]
    NmapService,
    /// `user-service` (este servicio).
    #[serde(rename = "user-service")]
    UserService,
}

/// Evento de seguridad inmutable: el sobre del contrato
/// `security-event.schema.json`. Se construye con el constructor tipado
/// ([`SecurityEvent::audit_recorded`]) o se deserializa de un registro del
/// stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityEvent {
    event_id: String,
    event_type: EventType,
    occurred_at: String,
    source: EventSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_sub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scan_id: Option<String>,
    payload: Value,
}

/// Un constructor de [`SecurityEvent`] recibió un valor que el schema
/// rechazaría. Nombra el campo, nunca el valor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("el evento '{event_type}' tiene un valor inválido en el campo '{field}'")]
pub struct InvalidSecurityEvent {
    /// Tipo del evento que se intentaba construir.
    pub event_type: &'static str,
    /// Campo (del sobre o del `payload`) con el valor inválido.
    pub field: &'static str,
}

/// Errores al publicar un [`SecurityEvent`]. Ninguna variante incluye el
/// cuerpo del evento.
#[derive(Debug, thiserror::Error)]
pub enum SecurityEventError {
    /// El adaptador no pudo entregar el evento al stream. La causa original
    /// se conserva en `source` (solo visible vía la cadena de `source()`).
    #[error("no se pudo publicar el evento de seguridad")]
    PublishFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// No se pudo serializar el evento a JSON.
    #[error("no se pudo serializar el evento de seguridad")]
    SerializationFailed(#[source] serde_json::Error),
}

/// Puerto: "publicar un [`SecurityEvent`]". [`crate::repository::Repository`]
/// guarda un `Arc<dyn SecurityEventPublisher>` para que los tests que no
/// ejercen eventos no necesiten LocalStack.
///
/// Los llamadores no usan este método directamente sino [`emit`]/[`emit_all`],
/// que garantizan que un fallo nunca afecte a la operación de negocio.
#[async_trait::async_trait]
pub trait SecurityEventPublisher: Send + Sync {
    /// Publica `event`, devolviendo éxito solo cuando el destino lo aceptó.
    async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError>;
}

impl SecurityEvent {
    /// `audit.recorded`: `user-service` escribió una entrada de auditoría de
    /// `actor_sub` con la acción `action` sobre un recurso `resource_type`.
    /// Ambos son slugs cortos (`[a-z][a-z0-9_.]{0,63}`), nunca texto libre;
    /// ver [`crate::audit::recorded_event`] para el mapeo desde las acciones
    /// de `audit_log`.
    pub fn audit_recorded(
        actor_sub: &str,
        action: &str,
        resource_type: &str,
    ) -> Result<Self, InvalidSecurityEvent> {
        let invalid = |field| InvalidSecurityEvent {
            event_type: EventType::AuditRecorded.as_str(),
            field,
        };
        if !(1..=MAX_ACTOR_SUB_CHARS).contains(&actor_sub.chars().count()) {
            return Err(invalid("actor_sub"));
        }
        if !valid_slug(action) {
            return Err(invalid("action"));
        }
        if !valid_slug(resource_type) {
            return Err(invalid("resource_type"));
        }
        Ok(Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::AuditRecorded,
            occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            source: EventSource::UserService,
            actor_sub: Some(actor_sub.to_string()),
            scan_id: None,
            payload: json!({ "action": action, "resource_type": resource_type }),
        })
    }

    /// UUID v4 único de este evento (los consumidores deduplican por él:
    /// Kinesis entrega al menos una vez).
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Tipo del evento.
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// Tipo del evento como texto del contrato.
    pub fn event_type_str(&self) -> &'static str {
        self.event_type.as_str()
    }

    /// Instante del evento, RFC 3339 en UTC.
    pub fn occurred_at(&self) -> &str {
        &self.occurred_at
    }

    /// Servicio que produjo el evento.
    pub fn source(&self) -> EventSource {
        self.source
    }

    /// `sub` del usuario que causó el evento, si aplica (siempre presente en
    /// `audit.recorded`).
    pub fn actor_sub(&self) -> Option<&str> {
        self.actor_sub.as_deref()
    }

    /// Identificador de escaneo, si aplica (nunca en `audit.recorded`).
    pub fn scan_id(&self) -> Option<&str> {
        self.scan_id.as_deref()
    }

    /// Carga útil específica del tipo de evento.
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// Clave de partición de Kinesis: `scan_id` si lo hay, si no `actor_sub`,
    /// si no `event_id` (la regla del contrato; en `audit.recorded` es el
    /// `actor_sub`).
    pub fn partition_key(&self) -> &str {
        self.scan_id
            .as_deref()
            .or(self.actor_sub.as_deref())
            .unwrap_or(&self.event_id)
    }
}

/// `true` si `value` cumple `^[a-z][a-z0-9_.]{0,63}$`.
fn valid_slug(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && value.chars().count() <= MAX_SLUG_CHARS
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
}

/// Emite `event` sin esperar ni propagar nada. Equivale a [`emit_all`] con un
/// único evento.
pub fn emit(
    publisher: &Arc<dyn SecurityEventPublisher>,
    event: Result<SecurityEvent, InvalidSecurityEvent>,
) {
    emit_all(publisher, vec![event]);
}

/// Emite `events` sin esperar ni propagar nada: los publica en orden desde una
/// única tarea `tokio` desacoplada, con tope de [`PUBLISH_TIMEOUT`] por
/// evento. Al primer fallo o timeout el resto del lote se descarta (si Kinesis
/// está caído, no tiene sentido encadenar timeouts). Un evento inválido o la
/// ausencia de runtime solo se loggean (tipo de evento y campo, nunca el
/// contenido). Es el único punto de emisión que debe usar el servicio.
pub fn emit_all(
    publisher: &Arc<dyn SecurityEventPublisher>,
    events: Vec<Result<SecurityEvent, InvalidSecurityEvent>>,
) {
    let events: Vec<SecurityEvent> = events
        .into_iter()
        .filter_map(|event| match event {
            Ok(event) => Some(event),
            Err(err) => {
                tracing::warn!(
                    event_type = err.event_type,
                    field = err.field,
                    "evento de seguridad descartado: valor inválido para el contrato"
                );
                None
            }
        })
        .collect();
    if events.is_empty() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("eventos de seguridad descartados: no hay runtime tokio activo");
        return;
    };
    let publisher = Arc::clone(publisher);
    runtime.spawn(async move {
        for event in &events {
            match tokio::time::timeout(PUBLISH_TIMEOUT, publisher.publish(event)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    tracing::error!(
                        event_type = event.event_type_str(),
                        "no se pudo publicar un evento de seguridad (la operación no se ve afectada)"
                    );
                    return;
                }
                Err(_) => {
                    tracing::error!(
                        event_type = event.event_type_str(),
                        "se agotó el tiempo publicando un evento de seguridad (la operación no se ve afectada)"
                    );
                    return;
                }
            }
        }
    });
}

/// Adaptador que descarta todo evento: se usa cuando
/// `SECURITY_EVENTS_STREAM_NAME` no está definida.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSecurityEventPublisher;

#[async_trait::async_trait]
impl SecurityEventPublisher for NoopSecurityEventPublisher {
    async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
        Ok(())
    }
}

/// Adaptador en memoria que conserva los eventos publicados, para tests que
/// verifican qué emite el servicio sin Kinesis.
#[derive(Debug, Default)]
pub struct RecordingSecurityEventPublisher {
    events: Mutex<Vec<SecurityEvent>>,
}

impl RecordingSecurityEventPublisher {
    /// Crea un grabador vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copia de los eventos publicados hasta ahora, en orden.
    pub fn events(&self) -> Vec<SecurityEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// Cede el turno al runtime (sin esperas de reloj) hasta que haya al
    /// menos `count` eventos, con un tope de intentos, y devuelve lo
    /// grabado. [`emit`] publica en una tarea aparte, así que los tests la
    /// usan en vez de dormir.
    pub async fn wait_for(&self, count: usize) -> Vec<SecurityEvent> {
        for _ in 0..10_000 {
            let events = self.events();
            if events.len() >= count {
                return events;
            }
            tokio::task::yield_now().await;
        }
        self.events()
    }
}

#[async_trait::async_trait]
impl SecurityEventPublisher for RecordingSecurityEventPublisher {
    async fn publish(&self, event: &SecurityEvent) -> Result<(), SecurityEventError> {
        self.events
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(event.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    #[test]
    fn audit_recorded_carries_actor_action_and_resource_type_with_user_service_source() {
        let event = SecurityEvent::audit_recorded("user-sub-1", "user.updated", "user").unwrap();
        assert_eq!(event.source(), EventSource::UserService);
        assert_eq!(event.event_type(), EventType::AuditRecorded);
        assert_eq!(event.actor_sub(), Some("user-sub-1"));
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event_type"], "audit.recorded");
        assert_eq!(value["source"], "user-service");
        assert_eq!(value["actor_sub"], "user-sub-1");
        assert_eq!(
            value["payload"],
            serde_json::json!({"action": "user.updated", "resource_type": "user"})
        );
        assert!(value.get("scan_id").is_none());
    }

    #[test]
    fn partition_key_is_the_actor_sub() {
        let event = SecurityEvent::audit_recorded("user-sub-1", "role.granted", "user").unwrap();
        assert_eq!(event.partition_key(), "user-sub-1");
    }

    #[test]
    fn envelope_has_uuid_v4_id_and_rfc3339_utc_timestamp() {
        let event = SecurityEvent::audit_recorded("s", "role.granted", "user").unwrap();
        let id = uuid::Uuid::parse_str(event.event_id()).expect("event_id debe ser UUID");
        assert_eq!(id.get_version_num(), 4);
        assert!(event.occurred_at().ends_with('Z'));
        chrono::DateTime::parse_from_rfc3339(event.occurred_at())
            .expect("occurred_at debe ser RFC 3339");
    }

    #[test]
    fn constructor_refuses_values_the_schema_would_reject() {
        let build = SecurityEvent::audit_recorded;
        assert!(build("", "a.b", "user").is_err());
        assert!(build(&"x".repeat(129), "a.b", "user").is_err());
        assert!(build(&"x".repeat(128), "a.b", "user").is_ok());
        assert!(build("s", "", "user").is_err());
        assert!(build("s", "Role Granted", "user").is_err());
        assert!(build("s", "1role", "user").is_err());
        assert!(build("s", &format!("a{}", "b".repeat(64)), "user").is_err());
        assert!(build("s", &format!("a{}", "b".repeat(63)), "user").is_ok());
        assert!(build("s", "role.granted", "").is_err());
        assert!(build("s", "role.granted", "User").is_err());
    }

    #[test]
    fn invalid_event_error_names_the_field_but_never_the_value() {
        let err = SecurityEvent::audit_recorded("secret-sub", "Secret Action!", "user")
            .expect_err("slug inválido");
        let text = err.to_string();
        assert!(text.contains("action"));
        assert!(!text.contains("Secret"));
        assert!(!text.contains("secret-sub"));
    }

    #[test]
    fn events_round_trip_through_json() {
        let event = SecurityEvent::audit_recorded("s", "role.granted", "user").unwrap();
        let parsed: SecurityEvent =
            serde_json::from_value(serde_json::to_value(&event).unwrap()).unwrap();
        assert_eq!(parsed, event);
    }

    #[tokio::test]
    async fn recording_publisher_keeps_published_events_in_order() {
        let recorder = RecordingSecurityEventPublisher::new();
        for action in ["role.granted", "role.revoked"] {
            recorder
                .publish(&SecurityEvent::audit_recorded("a", action, "user").unwrap())
                .await
                .unwrap();
        }
        let actions: Vec<_> = recorder
            .events()
            .iter()
            .map(|e| e.payload()["action"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(actions, ["role.granted", "role.revoked"]);
    }

    #[tokio::test]
    async fn noop_publisher_accepts_everything() {
        NoopSecurityEventPublisher
            .publish(&SecurityEvent::audit_recorded("a", "role.granted", "user").unwrap())
            .await
            .unwrap();
    }

    #[derive(Default)]
    struct FailingPublisher {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SecurityEventPublisher for FailingPublisher {
        async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(SecurityEventError::PublishFailed("kinesis caído".into()))
        }
    }

    /// Publicador que nunca responde: ejercita el tope de tiempo.
    #[derive(Default)]
    struct HangingPublisher {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SecurityEventPublisher for HangingPublisher {
        async fn publish(&self, _event: &SecurityEvent) -> Result<(), SecurityEventError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn emit_delivers_in_the_background() {
        let recorder = Arc::new(RecordingSecurityEventPublisher::new());
        let port: Arc<dyn SecurityEventPublisher> = recorder.clone();
        emit(
            &port,
            SecurityEvent::audit_recorded("a", "role.granted", "user"),
        );
        assert_eq!(recorder.wait_for(1).await.len(), 1);
    }

    #[tokio::test]
    async fn emit_all_publishes_in_order_and_skips_invalid_events() {
        let recorder = Arc::new(RecordingSecurityEventPublisher::new());
        let port: Arc<dyn SecurityEventPublisher> = recorder.clone();
        emit_all(
            &port,
            vec![
                SecurityEvent::audit_recorded("a", "role.granted", "user"),
                SecurityEvent::audit_recorded("", "role.granted", "user"),
                SecurityEvent::audit_recorded("b", "role.revoked", "user"),
            ],
        );
        let events = recorder.wait_for(2).await;
        let actors: Vec<_> = events.iter().map(|e| e.actor_sub().unwrap()).collect();
        assert_eq!(actors, ["a", "b"]);
    }

    #[tokio::test]
    async fn emit_with_a_failing_publisher_neither_panics_nor_blocks() {
        let failing = Arc::new(FailingPublisher::default());
        let port: Arc<dyn SecurityEventPublisher> = failing.clone();
        emit(
            &port,
            SecurityEvent::audit_recorded("a", "role.granted", "user"),
        );
        // `emit` es síncrona: si hubiera esperado o propagado el fallo, no
        // habría devuelto el control aquí.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn emit_all_stops_the_batch_after_the_first_failure() {
        let failing = Arc::new(FailingPublisher::default());
        let port: Arc<dyn SecurityEventPublisher> = failing.clone();
        emit_all(
            &port,
            vec![
                SecurityEvent::audit_recorded("a", "role.granted", "user"),
                SecurityEvent::audit_recorded("b", "role.granted", "user"),
            ],
        );
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(failing.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn emit_gives_up_on_a_publisher_that_never_answers_after_the_timeout() {
        let hanging = Arc::new(HangingPublisher::default());
        let port: Arc<dyn SecurityEventPublisher> = hanging.clone();
        emit_all(
            &port,
            vec![
                SecurityEvent::audit_recorded("a", "role.granted", "user"),
                SecurityEvent::audit_recorded("b", "role.granted", "user"),
            ],
        );
        // Con el reloj pausado, `sleep` adelanta el tiempo virtual sin esperar:
        // la tarea desacoplada vence su tope y descarta el resto del lote.
        tokio::time::sleep(PUBLISH_TIMEOUT + std::time::Duration::from_secs(1)).await;
        tokio::time::sleep(PUBLISH_TIMEOUT + std::time::Duration::from_secs(1)).await;
        assert_eq!(hanging.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn emit_without_a_tokio_runtime_drops_the_event_without_panicking() {
        let port: Arc<dyn SecurityEventPublisher> = Arc::new(NoopSecurityEventPublisher);
        emit(
            &port,
            SecurityEvent::audit_recorded("a", "role.granted", "user"),
        );
    }
}
