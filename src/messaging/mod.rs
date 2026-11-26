//! Adaptadores de salida hacia AWS: [`kinesis`] (publicación de eventos de
//! seguridad en el stream `security-events`, feature
//! `security_event_publisher`, tarea KAP-08) y [`sqs`] (cola del correo del
//! informe, productor y consumidor, RF-20).

pub mod kinesis;
pub mod sqs;
