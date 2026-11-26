# Decisiones y historial de features

Registro breve de las decisiones de diseño del servicio, destilado de la lista de
features del arnés anterior. Cada entrada: contexto, decisión.

## ADR-001 Scaffolding: lib + binario delgado

`src/lib.rs` declara los módulos (`config`, `domain`, `repository`, `audit`,
`api`) como `pub` para que `tests/` (crate externo) pueda importarlos;
`src/main.rs` solo inicializa tokio y `tracing` y llama a la lib. La lib activa
`#![deny(missing_docs)]`.

## ADR-002 Configuración solo por variables de entorno

`src/config.rs` carga todo desde el entorno y devuelve un error tipado si falta
una variable requerida (sin panics). Los secretos usan `secrecy` para que no se
filtren por `Debug`/`Display`. Nada de valores hardcodeados.

## ADR-003 Dominio puro

`UserProfile`, `ScanHistoryEntry` y la entrada de auditoría son tipos puros sin
dependencias de IO.

## ADR-004 Persistencia PostgreSQL con auditoría append-only

Migraciones versionadas de `sqlx` y repositorio en `src/repository.rs`.
`audit_log` solo admite `INSERT`/`SELECT` a nivel de base de datos (RF-15). Como
el dueño de una tabla se salta cualquier `REVOKE`, el rol que migra
(`MIGRATIONS_DATABASE_URL`) debe ser distinto del rol de aplicación
`ms_usuarios_app` (`DATABASE_URL`). Los tests usan dos pools por contenedor: uno
de superusuario para migrar y activar el login del rol de aplicación, y otro
con ese rol para ejercer el repositorio. Ver la migración
`20260918120100_lock_audit_log_permissions.sql`.

## ADR-005 API de perfil

`PUT/GET /users/me`, autorizados a nivel de fila contra la identidad reenviada
por el Gateway.

## ADR-006 API de histórico y auditoría

Registro de solicitudes de escaneo con su auditoría en la misma transacción,
actualización de estado de solicitudes propias y consulta de histórico (RF-13)
y auditoría (RF-15).

## ADR-007 Composition root y health check

`config -> repository -> api` se conecta en `run()` (`src/wiring.rs`), invocada
desde `main`. Se expone un endpoint de salud (RNF-09).

## ADR-008 Imagen Docker multi-stage

Builder `rust:1.98-bookworm`, runtime `distroless/cc-debian12:nonroot`. Las
migraciones se embeben en el binario en compilación.

## ADR-009 Contrato real de `X-Forwarded-User`

El Gateway envía JSON `{"sub": "...", "email": "..."}`. El middleware parsea el
JSON y usa el `sub` como único `user_id`; antes guardaba el JSON completo como
identificador. Se trató como regresión de las APIs de perfil e histórico.

## ADR-010 Credenciales de red por usuario/objetivo

Implementa `GET /users/me/scan-targets?target=<ip|cidr>` (consumido por
`gateway::usuarios_client::resolve_scan_target`) más un CRUD mínimo. Matching:
un `target_pattern` aplica si `target` es una IP contenida en él o es el mismo
CIDR; con varias coincidencias gana el prefijo más largo. `ssh_credentials_ref`
es una credencial SSH real de terceros: se cifra en reposo (AES-256-GCM,
`CREDENTIALS_ENCRYPTION_KEY`) y solo la devuelve el endpoint de resolución.

## ADR-011 Loguear el `RepoError` real

`From<RepoError> for ApiError` descartaba el error sin registrarlo, lo que
ocultó un 500 en AWS. Ahora se loguea el error real en el servidor y el cliente
sigue recibiendo un `ApiError::Internal` genérico.

## ADR-012 Rol de usuario y administradores por configuración

`users.role` (`user`/`admin`, `CHECK`, por defecto `user`) se expone en
`GET`/`PUT /users/me` para que el Gateway lo incluya en su JWT (KAP-04/05).
El rol nunca se acepta desde un cuerpo de petición: `upsert_user` no lo
escribe y `PUT /users/me` ignora campos desconocidos, igual que `email`.

**Decisión (suposición registrada):** `ADMIN_BOOTSTRAP_EMAILS` (separada por
comas, sin distinguir mayúsculas; ausente o vacía = sin administradores) es
**autoritativa**: un usuario es admin si y solo si su correo está en la lista.
Se aplica de forma idempotente (a) al arrancar sobre todas las filas, y (b) en
el aprovisionamiento del perfil, de modo que un usuario listado que entra por
primera vez ya es admin. Quitar un correo revoca el rol en el siguiente
arranque o en el siguiente aprovisionamiento de ese usuario. Una entrada que no
tiene forma de correo, o un valor no UTF-8, es un error de configuración que
impide arrancar (cierra en vez de interpretar mal la lista).

Cada cambio de rol escribe `role.granted`/`role.revoked` en `audit_log`, en la
misma transacción, con `target` igual al rol resultante y sin el correo. El rol
de aplicación conserva `UPDATE` a nivel de tabla sobre `users` (la
reconciliación corre con ese rol); la garantía de que no se escribe desde
peticiones está en la aplicación y en sus tests. El correo proviene de la
identidad verificada por el Gateway (`X-Forwarded-User`).

## ADR-015 Permiso de escaneo en modo red por lista de cuentas

El escaneo en modo red (sin credenciales) queda limitado a una lista de cuentas
(decisión del usuario, uso académico). `users.can_network_scan BOOLEAN NOT NULL
DEFAULT false` se expone como `can_network_scan` en `GET`/`PUT /users/me`
(campo aditivo; un consumidor anterior lo ignora). El Gateway lo lee al iniciar
sesión y lo revalida contra `GET /users/me` en cada escaneo de red, igual que
`require_admin` con `role`: no hay endpoint nuevo.

`NETWORK_SCAN_EMAILS` sigue el patrón de ADR-012: lista separada por comas,
**autoritativa** (los listados tienen el permiso, el resto no; vacía = nadie),
idempotente, aplicada al arrancar sobre todas las filas y en el aprovisionamiento
del perfil. Un correo aún no registrado no crea filas: recibe el permiso en su
primer `PUT /users/me`. Es independiente de `ADMIN_BOOTSTRAP_EMAILS` (un admin
no tiene el permiso salvo que figure en la lista). Nunca se acepta desde un
cuerpo de petición.

Decisión: el cambio de permiso **no** se audita en `audit_log` (a diferencia del
rol), porque las acciones de auditoría son un contrato cerrado con el stream
`security-events`; el estado vigente queda en `users` y la lista en la
configuración versionada de infraestructura.

## ADR-013 Eventos de seguridad `audit.recorded` hacia Kinesis

Contexto: el panel de administración (KAP-09) lee el stream `security-events`;
el contrato es `broker/contracts/security-event.schema.json` y
`user-service` produce `audit.recorded`, espejo de lo que hacen el Gateway
(KAP-06) y ms-nmap (KAP-07).

**Decisión:** el puerto `SecurityEventPublisher` (`src/security_events.rs`) y
su adaptador Kinesis (`src/messaging/kinesis.rs`, `aws-sdk-kinesis` 1.125.0)
publican un evento por cada entrada de `audit_log`. `Repository` emite **después**
de confirmar la escritura (tras `commit` en `reconcile_roles` y
`record_scan_request`; tras el `INSERT` en autocommit de `append_audit_entry`),
de modo que un rollback nunca emite. La emisión es una tarea `tokio`
desacoplada con tope de 5 s por evento que solo loggea el tipo de evento: un
Kinesis caído no cambia ninguna respuesta HTTP ni la fila de auditoría. El
costo, aceptado, es que un evento puede perderse si el proceso muere antes de
publicar (`audit_log` es la fuente de verdad; sin outbox). Cada evento se reintenta
en memoria hasta 3 veces con backoff exponencial y jitter completo (100 ms
base, 1,5 s por intento) dentro del tope de 5 s, y un fallo no descarta el
resto del lote.

Mapeo (`audit::recorded_event`; cualquier otra acción no se publica, porque su
texto no es un código conocido):

| `audit_log.action` | `payload.action` | `payload.resource_type` |
|---|---|---|
| `scan_requested` | `scan.requested` | `scan` |
| `role.granted` | `role.granted` | `user` |
| `role.revoked` | `role.revoked` | `user` |

`actor_sub` es el `user_id` de la entrada: en `scan_requested`, quien pidió el
escaneo; en `role.granted`/`role.revoked`, el usuario cuyo rol cambió (el cambio
lo aplica la lista `ADMIN_BOOTSTRAP_EMAILS`, no una persona). Es también la
clave de partición. El evento nunca lleva correo, nombre, objetivo del escaneo,
rol resultante ni texto libre. `SECURITY_EVENTS_STREAM_NAME` ausente o en
blanco activa el adaptador no-op con un único log informativo al arrancar.
`tests/security_event_contract.rs` valida cada evento contra el schema del
broker y `tests/kinesis_publisher_localstack.rs` /
`tests/audit_events_localstack.rs` lo hacen contra LocalStack.

## ADR-014 Puerto y protocolo de un hallazgo en el resultado almacenado

- **Decisión:** no se cambia código ni esquema. `scan_history.result` es `JSONB`
  y el reporte (`GET /users/me/scans/{scan_id}/report`) devuelve el valor
  almacenado sin interpretarlo, por lo que los campos opcionales `port` y
  `protocol` de cada `VulnFinding` (ausentes, `null` o con valor) viajan intactos.
- **Contexto:** `nmap-service` pasa a informar el puerto de cada hallazgo
  (`broker/contracts/scan-outcome.schema.json`, D-15 del broker) para que el
  reporte indique dónde está la vulnerabilidad.
- **Consecuencia:** no hay migración. Los tests de caracterización
  (`tests/repository.rs`, `tests/api.rs`) fijan el round trip para que un futuro
  modelo tipado de `result` no descarte los campos. Si el almacenamiento pasara
  a ser columnar, habría que añadir las columnas con una migración aditiva.

## ADR-016 Correo del informe por SQS, con el consumidor en user-service

- **Decisión:** con `REPORT_EMAIL_QUEUE_URL` y `REPORT_EMAIL_DLQ_URL`, el
  `PATCH /scans/{id}` con `COMPLETADO` publica un `ReportEmailRequest`
  (`{scan_id, requested_at}`, contrato `report-email-request.schema.json` del
  broker, D-19) en la cola `user-service-report-emails` y un consumidor dentro
  de este servicio (`src/messaging/sqs.rs`, hecho a imagen de `gateway/src/sqs.rs`)
  lo procesa. Sin esas variables el envío en proceso queda igual (RF-20).
- **Un intento por recepción:** cada recepción reclama la fila en Postgres
  (`claim_for_queue`, con una concesión), hace un único intento SMTP de 60 s y
  devuelve `Done` (se borra el mensaje) o `Retry` (se deja: SQS lo reentrega al
  vencer la visibilidad). En la última recepción, la fila pasa a `failed` con
  auditoría y el mensaje no se borra, de modo que la redrive policy lo mueve a la
  DLQ, donde se puede inspeccionar y reenviar. Los reintentos viven en SQS, no en
  memoria.
- **Atributos leídos al arrancar:** `GetQueueAttributes` entrega
  `VisibilityTimeout` y el `maxReceiveCount` de la `RedrivePolicy`. De ellos salen
  la concesión (90 % de la visibilidad: la reclamación ocurre un instante después
  de la recepción, así que una reentrega exactamente una visibilidad después
  tiene que encontrar la concesión vencida, o el reintento se tomaría por un
  duplicado y se borraría), el umbral de última recepción y la ventana que debe
  superar el reaper (`VisibilityTimeout` x `maxReceiveCount` + plazo del intento).
  El arranque también falla si la concesión no supera el plazo de un intento SMTP
  (la política de reintentos en uso), pues una reentrega podría tomar un envío
  vivo. Terraform queda como único sitio donde se cambian; una cola sin DLQ o sin
  visibilidad hace fallar el arranque.
- **Un mensaje por recepción:** un intento puede tardar 60 s y los mensajes de un
  lote se procesan en serie; con 10 por lote los últimos superarían la
  visibilidad, se reentregarían con la cuenta de recepciones incrementada sin
  haberse procesado y podrían marcar `failed` antes de tiempo.
- **Respaldo en proceso:** si la publicación falla o supera 5 s, se registra un
  aviso (sin cuerpo ni secretos) y se lanza `spawn_for_completed`, de modo que el
  correo no se pierde y el `PATCH` no queda bloqueado más que ese tope. El reaper
  se mantiene para esa ruta.
- **Al menos una vez:** SQS puede duplicar y el consumidor puede morir tras enviar;
  la reclamación atómica en Postgres (estado y marca de tiempo) es la
  idempotencia: `sent` y `disabled` son finales y una concesión viva no se toma.
  El correo solo se duplica si el proceso muere tras el envío y antes de guardar
  `sent`, igual que antes.
- **Malformados:** se copian a la DLQ con un `SendMessage` explícito y se borran;
  el cuerpo nunca se loguea (solo largo e id del mensaje). Si la copia falla se
  deja el mensaje para que lo resuelva la redrive.
- **Apagado:** un `CancellationToken` se cancela con SIGTERM o Ctrl-C (también
  detiene el servidor HTTP con `with_graceful_shutdown`); corta el long poll y el
  backoff, el correo en curso termina y el proceso espera la tarea del consumidor
  antes de salir. Los mensajes sin procesar reaparecen al vencer su visibilidad.
- **Consumidor caído:** si la tarea del consumidor termina (panic o retorno)
  mientras el servicio sigue corriendo, `run` lo registra, cancela el mismo token
  (el servidor HTTP se detiene) y falla con `RunError::ConsumerDied`; el proceso
  sale con código 1 y ECS lo reemplaza, en vez de seguir sirviendo HTTP sin nadie
  que consuma la cola.
- **Consecuencia:** el correo tarda al menos una visibilidad (~2 min) más por cada
  reintento. Los tests viven en `tests/report_email.rs` (LocalStack, Postgres y
  Mailpit) y `tests/report_email_request_contract.rs`.
