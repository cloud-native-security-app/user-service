//! Adaptadores de salida hacia AWS (feature `security_event_publisher`,
//! tarea KAP-08). Hoy solo existe [`kinesis`]: la publicación de eventos de
//! seguridad en el stream `security-events`.

pub mod kinesis;
