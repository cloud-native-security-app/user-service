# user-service

`ms-usuarios`: microservicio de identidad y auditoría dentro de una
plataforma de ciberseguridad blue/red team. Mantiene el perfil de cada
usuario autenticado (identidad ya verificada por el Gateway vía Google
OAuth 2.0 / OIDC), el histórico de escaneos que ha solicitado (RF-13) y el
registro **inmutable** de auditoría de quién solicitó qué escaneo y cuándo
(RF-15).

Este repo implementa **únicamente** `ms-usuarios`. `ms-nmap`, `ms-analisis`,
el Gateway y el Broker viven en otros repos. A diferencia de `ms-nmap`,
`ms-usuarios` **no pasa por el Broker**: habla directo y de forma síncrona
con el Gateway.

Stack: Rust (async con `tokio`, API HTTP con `axum`), persistencia en
PostgreSQL vía `sqlx`, tests de integración con `testcontainers`.

## Desarrollo

Verificación local completa (reemplaza al antiguo script de verificación):

```
make verify
```

Ejecuta `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, `cargo test -- --ignored` (tests de integración con
`testcontainers`, requieren Docker) y `cargo doc --no-deps`. Cada paso también
está disponible como target individual (`make fmt`, `make clippy`, `make test`,
`make test-integration`, `make doc`).

Las decisiones de diseño y el historial de features están en
`docs/decisions.md`.

## Desarrollo asistido por IA

El repositorio usa gentle-ai: los planes de trabajo (ODD) viven en
`odd/tasks/`, con copia de recuperación en Engram, y las reglas de revisión de
código (Gentleman Guardian Angel) están en `AGENTS.md`.

## CI/CD

### En cada pull request y push a `develop` (`.github/workflows/ci.yml`)

- **verify**: Rust 1.98 (el mismo del builder del `Dockerfile`) y `make verify`
  (fmt, clippy `-D warnings`, `cargo test`, `cargo test -- --ignored` con
  PostgreSQL real vía testcontainers en Docker, `cargo doc`).
- **docker-build**: `docker build .` sin push.

### En push a `main` (`.github/workflows/deploy.yml`)

Construye la imagen, la publica en ECR como `security-app/user-service:<sha>`
(y `:latest`) y despliega en el servicio ECS `user-service` del cluster
`security-app-cluster-v2`. Terraform (repo `infra`) es la única fuente de
verdad de la task definition (variables de entorno, `DATABASE_URL` y secretos
desde SSM, roles, logs): CI solo descarga la task definition más reciente de
la familia del servicio (no la que está corriendo, así no se pierden los cambios que registró Terraform), cambia la imagen del contenedor `user-service` por `<sha>`, registra
la nueva revisión y espera la estabilidad del servicio. Nada de esto se
versiona en este repo.

`user-service` no tiene load balancer: se alcanza solo desde otros servicios
por Service Connect (`user-service:8080`). "Estable" significa que la tarea
queda en estado `RUNNING` con `runningCount == desiredCount`.

Requisitos en GitHub (Learner Lab no tiene OIDC; los fija
`scripts/refresh-gh-secrets.sh` del repo `infra`):

| Nombre | Tipo | Quién lo define |
|--------|------|-----------------|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | secrets del repo | `infra` `scripts/refresh-gh-secrets.sh` |
| `AWS_REGION` | variable del repo | `infra` `scripts/refresh-gh-secrets.sh` |

Las credenciales de Learner Lab caducan: si el deploy falla al autenticarse,
ejecuta `scripts/refresh-gh-secrets.sh` en `infra` y vuelve a lanzar el workflow.

### Redeploy manual y rollback

- Redeploy: pestaña Actions, workflow **Deploy**, **Run workflow**
  (`workflow_dispatch`).
- Rollback: lanza **Run workflow** eligiendo la ref (rama o tag) de un commit
  anterior, que reconstruye y despliega esa imagen; o, sin reconstruir,
  `aws ecs update-service --cluster security-app-cluster-v2 --service user-service --task-definition <familia>:<revisión anterior>`.

## Despliegue (Docker)

El `Dockerfile` de la raíz produce una imagen multi-stage:

- **builder**: `rust:1.98-bookworm`, compila el binario `user_service` en
  release. Las migraciones de `migrations/` se copian a este stage porque
  `sqlx::migrate!("./migrations")` las embebe en el binario en tiempo de
  compilación (ver `src/wiring.rs`) — no hay que copiarlas por separado a la
  imagen final.
- **runtime**: `gcr.io/distroless/cc-debian12:nonroot`, contiene únicamente
  el binario `user_service` y los certificados CA del sistema (ya incluidos
  en la imagen base distroless), y corre como usuario no-root (`nonroot`,
  uid 65532).

La imagen final **no incluye**: la toolchain de Rust, el código fuente, ni
shell/coreutils (no hay `sh`, `ls`, gestor de paquetes, etc. — es una imagen
`distroless`).

### Construir

```
docker build -t user-service:local .
```

### Ejecutar

`user_service` lee **toda** su configuración de variables de entorno (ver
`src/config.rs`). Si falta alguna de las requeridas, el proceso termina con
un error tipado explícito, nunca con un panic:

| Variable | Requerida | Descripción |
|----------|-----------|-------------|
| `DATABASE_URL` | Sí | URL de conexión a PostgreSQL (`db-usuarios`) usada por el pool que sirve tráfico HTTP real, con el rol de aplicación `ms_usuarios_app` en producción |
| `HTTP_HOST` | Sí | Host en el que el servidor HTTP hace bind (p. ej. `0.0.0.0` dentro del contenedor) |
| `HTTP_PORT` | Sí | Puerto en el que el servidor HTTP hace bind |
| `GATEWAY_SHARED_SECRET` | Sí | Credencial compartida que autentica al Gateway como llamante de este servicio (ver `docs/security-scope.md`) |
| `CREDENTIALS_ENCRYPTION_KEY` | Sí | Clave de cifrado en reposo (AES-256-GCM) de las credenciales SSH de red (feature `network_credentials_api`): 32 bytes codificados como hex de 64 caracteres. Tan sensible como `GATEWAY_SHARED_SECRET` — no debe commitearse ni loggearse (ver `docs/security-scope.md` §"Credenciales de red") |
| `ADMIN_BOOTSTRAP_EMAILS` | No (ausente o vacía = sin administradores) | Correos de los administradores, separados por comas (se recortan espacios y no distingue mayúsculas). La lista es **autoritativa**: un usuario es `admin` si y solo si su correo está en ella. Se aplica (concede y revoca) al arrancar sobre los usuarios existentes y al aprovisionar el perfil (`PUT /users/me`). Una entrada que no sea un correo, o un valor que no sea UTF-8, impide el arranque. Cada cambio de rol queda en `audit_log` (`role.granted`/`role.revoked`) |
| `NETWORK_SCAN_EMAILS` | No (ausente o vacía = nadie) | Correos de las cuentas autorizadas a lanzar escaneos en modo red (sin credenciales), separados por comas (se recortan espacios y no distingue mayúsculas). La lista es **autoritativa**: un usuario tiene `can_network_scan = true` si y solo si su correo está en ella; quitar un correo revoca el permiso. Se aplica al arrancar sobre los usuarios existentes y al aprovisionar el perfil (`PUT /users/me`), así que un correo aún no registrado lo recibe en su primer inicio de sesión. Mismas reglas de validación que `ADMIN_BOOTSTRAP_EMAILS` (una entrada inválida o un valor no UTF-8 impide el arranque). Es independiente del rol `admin`. No genera entradas de auditoría |
| `SECURITY_EVENTS_STREAM_NAME` | No (ausente o en blanco = sin publicación) | Nombre del Kinesis Data Stream `security-events`. Si está definida, cada entrada que el servicio escribe en `audit_log` publica un evento `audit.recorded` (acción y tipo de recurso, `actor_sub` como clave de partición; nunca correo ni texto libre) **después** de confirmar la transacción. Un fallo de Kinesis solo se loggea y no altera ninguna respuesta ni la fila de auditoría. Un nombre que no sea `[a-zA-Z0-9_.-]` de hasta 128 caracteres impide el arranque. Requiere `kinesis:PutRecord` sobre el stream en el rol de la tarea |
| `SMTP_HOST` | No (ausente o en blanco = correo del informe desactivado; con host, un `SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS`, `SMTP_FROM` o par usuario/contraseña inválido o incompleto hace fallar el arranque con un error que nombra la variable, nunca el valor) | Servidor SMTP del correo que se envía al dueño del escaneo (a su correo de cuenta, nunca a otro) cuando un escaneo termina `COMPLETADO`. Sin host, el escaneo queda con `report_email_status = disabled` y no se envía nada. Producción: `smtp.gmail.com` con contraseña de aplicación |
| `SMTP_PORT` | No (587) | Puerto SMTP |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | No (van juntas) | Credenciales SMTP. La contraseña es un secreto: se redacta en `Debug` y nunca se loggea |
| `SMTP_FROM` | No (por defecto `SMTP_USERNAME`) | Dirección remitente. Sin `SMTP_USERNAME` es obligatoria |
| `SMTP_TLS` | No (`starttls`) | `starttls` exige STARTTLS (un servidor sin él se rechaza); `none` = texto plano sin login, solo para el sumidero Mailpit de pruebas; combinarlo con `SMTP_USERNAME` o `SMTP_PASSWORD` es un error de configuración y el servicio no arranca (las credenciales irían en texto plano) |
| `REPORT_EMAIL_REAPER_AFTER_SECS` | No (600) | Segundos que un correo de informe puede quedar `pending` antes de que el reaper lo reintente (un envío perdido por un apagado o un fallo del proceso). Entero >= 65 (el arranque falla si no supera 64 s, y el error nombra la variable y el mínimo). Cada intento SMTP tiene un plazo total de 60 s (conectar hasta DATA; al vencer cuenta como intento fallido y entra en el reintento normal), y entre intentos hay esperas de 2 s y 4 s. El reaper renueva la marca de reclamación antes de cada intento, así que el hueco máximo entre renovaciones de un envío vivo es el plazo del intento más la mayor espera (60 + 4 = 64 s), que debe ser menor que este umbral. Ese mínimo se calcula de la política de reintentos, no está fijo. Solo actúa con `SMTP_HOST` definido |
| `REPORT_EMAIL_REAPER_INTERVAL_SECS` | No (60) | Segundos entre pasadas del reaper (hasta 20 informes por pasada). Entero >= 1. El reintento usa la misma ruta que el envío normal y deja `sent` o `failed`. Garantía: al menos una vez. La reclamación atómica (`FOR UPDATE SKIP LOCKED`) y el latido evitan que otra pasada o instancia tome un informe que se sigue enviando; un envío vivo renueva su reclamación al menos cada plazo de intento más la mayor espera (menos que `REPORT_EMAIL_REAPER_AFTER_SECS`), así que el correo solo puede duplicarse si el proceso muere tras enviar y antes de guardar `sent`. Datos almacenados ilegibles (p. ej. un `scan_mode` inválido) dejan el informe en `failed`; un error transitorio de base de datos lo deja `pending` y se reintenta |
| `AWS_REGION` | No | Región del cliente Kinesis. Si falta, la resuelve la cadena por defecto de AWS. Las credenciales salen siempre de esa cadena (rol de la tarea ECS), nunca del código |
| `AWS_ENDPOINT_URL` | No | Endpoint AWS alternativo, solo para LocalStack/desarrollo. Ausente en AWS real |
| `MIGRATIONS_DATABASE_URL` | No (cae de vuelta a `DATABASE_URL` si está ausente) | URL de conexión usada **exclusivamente** para aplicar las migraciones al arrancar, con el rol "dueño" de las tablas |

`MIGRATIONS_DATABASE_URL` existe porque `migrations/20260918120100_lock_audit_log_permissions.sql`
deja al rol de aplicación `ms_usuarios_app` sin permiso de `UPDATE`/`DELETE`
sobre `audit_log` (RF-15) — pero en PostgreSQL el dueño de una tabla se salta
cualquier `REVOKE`. Si el mismo rol que migra el esquema (dueño de las
tablas) sirviera también el tráfico HTTP en producción, ese endurecimiento
quedaría anulado en la práctica. Por eso el rol que aplica las migraciones y
el rol `ms_usuarios_app` que atiende peticiones deben ser distintos en
producción: `MIGRATIONS_DATABASE_URL` apunta al primero, `DATABASE_URL` al
segundo. En dev/test ambas variables pueden apuntar al mismo rol
todopoderoso (o se puede omitir `MIGRATIONS_DATABASE_URL` por completo). El
aprovisionamiento concreto de esos dos roles/credenciales en un entorno de
despliegue real (Terraform, DBA, etc.) queda fuera del alcance de este repo.

```
docker run --rm \
  -e DATABASE_URL=postgres://ms_usuarios_app:pass@db-usuarios:5432/usuarios \
  -e MIGRATIONS_DATABASE_URL=postgres://migrator:pass@db-usuarios:5432/usuarios \
  -e HTTP_HOST=0.0.0.0 \
  -e HTTP_PORT=8080 \
  -e GATEWAY_SHARED_SECRET=change-me \
  -e CREDENTIALS_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  -e ADMIN_BOOTSTRAP_EMAILS=admin@example.com \
  -e NETWORK_SCAN_EMAILS=scanner@example.com \
  -p 8080:8080 \
  user-service:local
```

## API

Todas las rutas requieren dos headers en cada petición, verificados por un
middleware interno antes de tocar la base de datos (ver
`docs/security-scope.md`):

- `X-Gateway-Secret`: la credencial de servicio compartida
  (`GATEWAY_SHARED_SECRET`). Ausente o incorrecta → `401`.
- `X-Forwarded-User`: la identidad del usuario final ya verificada por el
  Gateway, como JSON `{"sub": "...", "email": "..."}`. Ausente/inválida →
  `400`. El `sub` es el único origen de verdad de `user_id`: nunca se
  confía en un `user_id` del cuerpo o la query.

| Método y ruta | Descripción |
|---------------|-------------|
| `PUT /users/me` | Crea o actualiza el perfil del llamante. Cuerpo: `{"display_name": "..."}`; cualquier otro campo (incluido `role`) se ignora |
| `GET /users/me` | Perfil del llamante (`user_id`, `email`, `display_name`, `role`, `created_at`); `404` si aún no tiene perfil. `role` es `"user"` o `"admin"` y lo lee el Gateway al iniciar sesión; nunca se acepta desde el cuerpo de una petición. `can_network_scan` (booleano, `false` por defecto) indica si la cuenta puede lanzar escaneos en modo red; el Gateway lo lee al iniciar sesión y lo revalida con este mismo `GET /users/me` en cada escaneo de red; tampoco se acepta desde el cuerpo |
| `POST /users/me/scans` | Registra una solicitud de escaneo (estado `Pendiente`) + su auditoría, en la misma transacción. Cuerpo: `{"target": "...", "scan_mode"?: "ssh"|"network"}`; `scan_mode` es opcional (por defecto `ssh`) y un valor desconocido se rechaza con `4xx` sin guardar nada. La respuesta incluye `scan_mode` |
| `GET /users/me/scans` | Histórico de escaneos del llamante. Cada entrada incluye `scan_mode` (`ssh` o `network`; las filas anteriores son `ssh`) y `failure_reason` (`null` si no hay) y nunca el resultado completo. Estados: `PENDIENTE`, `EN_PROGRESO`, `COMPLETADO`, `FALLIDO`, `CANCELADO` |
| `GET /users/me/scans/{scan_id}/report` | Resultado guardado de un escaneo propio (el JSON `ScanResult` tal cual). `404` si no existe o es de otro usuario, `409` si aún no está `COMPLETADO` con resultado |
| `PATCH /scans/{scan_id}` | Actualiza el estado de una solicitud propia; `404` si no existe, `403` si es de otro usuario. Cuerpo: `{"status": "...", "result"?: {...}, "failure_reason"?: "..."}`; `result` solo con `COMPLETADO` (objeto JSON, máx. 256 KB, `413` si lo supera), `failure_reason` solo con `FALLIDO`/`CANCELADO` (no vacío, máx. 500 caracteres); combinación inválida: `400`. Respuesta `204`. Los estados terminales (`COMPLETADO`, `FALLIDO`, `CANCELADO`) son finales: un PATCH posterior (p. ej. un `EN_PROGRESO` tardío o un reintento) es un no-op idempotente que conserva estado, `result` y `failure_reason` y responde `204`. Detalle en `odd/tasks/scan-report.md` |
| `GET /users/me/audit` | Auditoría del llamante (RF-15) |
| `POST /users/me/network-credentials` | Crea/actualiza (upsert por `user_id`+`target_pattern`) las credenciales de red del llamante para un objetivo. Cuerpo: `{"target_pattern": "203.0.113.7" \| "203.0.113.0/24" (IP o CIDR v4/v6), "network_user": "...", "ssh_credentials_ref": "...", "has_sudo": bool}`. `ssh_credentials_ref` se cifra en reposo y **nunca** aparece en la respuesta |
| `GET /users/me/network-credentials` | Credenciales de red del llamante, sin la credencial SSH |
| `DELETE /users/me/network-credentials/{id}` | Borra una entrada propia; un `id` ajeno o inexistente → `404` (nunca `403`) |
| `GET /users/me/scan-targets?target=<ip\|ip/cidr>` | Resuelve las credenciales que mejor matchean el objetivo (más específico gana). `400` si `target` no es IP/CIDR, `422` si no hay match. Respuesta EXACTA: `{"network_user": "...", "ssh_credentials_ref": "...", "has_sudo": bool}` — el shape que consume `gateway::usuarios_client::ScanTargetCredentials`. Único endpoint que devuelve la credencial SSH |
