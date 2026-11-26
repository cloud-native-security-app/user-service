//! Arnés compartido de los tests de integración que corren contra un
//! LocalStack real (`localstack/localstack:4.4`, Kinesis y SQS) levantado con
//! `testcontainers`: sin mocks y sin cuenta AWS. Cada test levanta su propio
//! contenedor.
//!
//! Requiere Docker; los tests que lo usan están marcados
//! `#[ignore = "requiere Docker"]`.

// Cada binario de test (`tests/*.rs`) compila este módulo por separado y solo
// usa una parte de sus helpers.
#![allow(dead_code)]

use std::time::Duration;

use aws_sdk_kinesis::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_kinesis::types::{Record, ShardIteratorType, StreamStatus};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

pub const LOCALSTACK_TAG: &str = "4.4";
pub const REGION: &str = "us-east-1";

/// LocalStack en marcha más un cliente Kinesis ya apuntado a él. El
/// contenedor se destruye al soltar este valor.
pub struct LocalStack {
    _container: ContainerAsync<GenericImage>,
    pub endpoint: String,
    pub kinesis: aws_sdk_kinesis::Client,
    pub sqs: aws_sdk_sqs::Client,
}

/// Cola SQS y su DLQ, con la política de redrive ya aplicada.
pub struct QueueUrls {
    pub queue_url: String,
    pub dlq_url: String,
}

impl LocalStack {
    pub async fn start() -> Self {
        let container = GenericImage::new("localstack/localstack", LOCALSTACK_TAG)
            .with_exposed_port(4566.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready."))
            .with_startup_timeout(Duration::from_secs(180))
            .start()
            .await
            .expect("el contenedor LocalStack de test debe arrancar");
        let port = container
            .get_host_port_ipv4(4566.tcp())
            .await
            .expect("LocalStack debe publicar el puerto 4566");
        let endpoint = format!("http://127.0.0.1:{port}");
        let sqs = aws_sdk_sqs::Client::from_conf(
            aws_sdk_sqs::Config::builder()
                .behavior_version(aws_sdk_sqs::config::BehaviorVersion::latest())
                .region(aws_sdk_sqs::config::Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(aws_sdk_sqs::config::Credentials::new(
                    "test",
                    "test",
                    None,
                    None,
                    "localstack-test",
                ))
                .build(),
        );
        let kinesis = aws_sdk_kinesis::Client::from_conf(
            aws_sdk_kinesis::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new(REGION))
                .endpoint_url(&endpoint)
                .credentials_provider(Credentials::new(
                    "test",
                    "test",
                    None,
                    None,
                    "localstack-test",
                ))
                .build(),
        );
        Self {
            _container: container,
            endpoint,
            kinesis,
            sqs,
        }
    }

    /// Crea la cola `name` con su DLQ `name-dlq`: `VisibilityTimeout` de
    /// `visibility_secs` y redrive a la DLQ tras `max_receives` recepciones.
    pub async fn create_queue_with_dlq(
        &self,
        name: &str,
        visibility_secs: u32,
        max_receives: u32,
    ) -> QueueUrls {
        use aws_sdk_sqs::types::QueueAttributeName;

        let dlq_url = self
            .sqs
            .create_queue()
            .queue_name(format!("{name}-dlq"))
            .send()
            .await
            .expect("crear la DLQ")
            .queue_url
            .expect("URL de la DLQ");
        let dlq_arn = self
            .sqs
            .get_queue_attributes()
            .queue_url(&dlq_url)
            .attribute_names(QueueAttributeName::QueueArn)
            .send()
            .await
            .expect("atributos de la DLQ")
            .attributes
            .expect("atributos")
            .remove(&QueueAttributeName::QueueArn)
            .expect("ARN de la DLQ");
        let redrive =
            format!(r#"{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":{max_receives}}}"#);
        let queue_url = self
            .sqs
            .create_queue()
            .queue_name(name)
            .attributes(
                QueueAttributeName::VisibilityTimeout,
                visibility_secs.to_string(),
            )
            .attributes(QueueAttributeName::RedrivePolicy, redrive)
            .send()
            .await
            .expect("crear la cola")
            .queue_url
            .expect("URL de la cola");
        QueueUrls { queue_url, dlq_url }
    }

    /// Cuerpos que `queue_url` entrega ahora (long poll de `wait_secs`); los
    /// deja invisibles hasta que venza su visibilidad.
    pub async fn receive_bodies(&self, queue_url: &str, wait_secs: i32) -> Vec<String> {
        self.sqs
            .receive_message()
            .queue_url(queue_url)
            .wait_time_seconds(wait_secs)
            .max_number_of_messages(10)
            .send()
            .await
            .expect("recibir de la cola")
            .messages
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| m.body)
            .collect()
    }

    /// Mensajes en la cola, visibles o en vuelo.
    pub async fn queue_depth(&self, queue_url: &str) -> u32 {
        use aws_sdk_sqs::types::QueueAttributeName::{
            ApproximateNumberOfMessages as Visible,
            ApproximateNumberOfMessagesNotVisible as InFlight,
        };
        let attributes = self
            .sqs
            .get_queue_attributes()
            .queue_url(queue_url)
            .attribute_names(Visible)
            .attribute_names(InFlight)
            .send()
            .await
            .expect("atributos de la cola")
            .attributes
            .expect("atributos");
        [Visible, InFlight]
            .iter()
            .map(|name| attributes[name].parse::<u32>().expect("número"))
            .sum()
    }

    /// Crea el stream Kinesis `name` de 1 shard y espera a que esté `ACTIVE`
    /// (sondea con tope de intentos).
    pub async fn create_stream(&self, name: &str) {
        self.kinesis
            .create_stream()
            .stream_name(name)
            .shard_count(1)
            .send()
            .await
            .expect("crear el stream");
        for _ in 0..100 {
            let status = self
                .kinesis
                .describe_stream_summary()
                .stream_name(name)
                .send()
                .await
                .expect("describir el stream")
                .stream_description_summary
                .expect("resumen del stream")
                .stream_status;
            if status == StreamStatus::Active {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("el stream {name} no llegó a ACTIVE");
    }

    /// Lee desde el principio (`TRIM_HORIZON`) del único shard de `stream`
    /// hasta reunir `expected` registros (o agotar los intentos).
    pub async fn read_stream(&self, stream: &str, expected: usize) -> Vec<Record> {
        let shard_id = self
            .kinesis
            .list_shards()
            .stream_name(stream)
            .send()
            .await
            .expect("listar shards")
            .shards
            .expect("shards")
            .remove(0)
            .shard_id;
        let mut iterator = self
            .kinesis
            .get_shard_iterator()
            .stream_name(stream)
            .shard_id(shard_id)
            .shard_iterator_type(ShardIteratorType::TrimHorizon)
            .send()
            .await
            .expect("iterador del shard")
            .shard_iterator;
        let mut records = Vec::new();
        for _ in 0..50 {
            let Some(current) = iterator.take() else {
                break;
            };
            let out = self
                .kinesis
                .get_records()
                .shard_iterator(current)
                .send()
                .await
                .expect("leer registros");
            records.extend(out.records);
            if records.len() >= expected {
                break;
            }
            iterator = out.next_shard_iterator;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        records
    }
}
