//! Arnés compartido de los tests de integración que corren contra un
//! LocalStack real (`localstack/localstack:4.4`, solo Kinesis) levantado con
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
        }
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
