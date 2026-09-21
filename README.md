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

El repositorio se desarrolla guiado por agentes de IA sobre un arnés
documental (`AGENTS.md`, `feature_list.json`, `docs/`, `CHECKPOINTS.md`),
igual que `broker` y `nmap-service`. Antes de tocar código, lee `CLAUDE.md`.

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
| `PUT /users/me` | Crea o actualiza el perfil del llamante. Cuerpo: `{"display_name": "..."}` |
| `GET /users/me` | Perfil del llamante; `404` si aún no tiene perfil |
| `POST /users/me/scans` | Registra una solicitud de escaneo (estado `Pendiente`) + su auditoría, en la misma transacción. Cuerpo: `{"target": "..."}` |
| `GET /users/me/scans` | Histórico de escaneos del llamante |
| `PATCH /scans/{scan_id}` | Actualiza el estado de una solicitud propia; `404` si no existe, `403` si es de otro usuario |
| `GET /users/me/audit` | Auditoría del llamante (RF-15) |
| `POST /users/me/network-credentials` | Crea/actualiza (upsert por `user_id`+`target_pattern`) las credenciales de red del llamante para un objetivo. Cuerpo: `{"target_pattern": "203.0.113.7" \| "203.0.113.0/24" (IP o CIDR v4/v6), "network_user": "...", "ssh_credentials_ref": "...", "has_sudo": bool}`. `ssh_credentials_ref` se cifra en reposo y **nunca** aparece en la respuesta |
| `GET /users/me/network-credentials` | Credenciales de red del llamante, sin la credencial SSH |
| `DELETE /users/me/network-credentials/{id}` | Borra una entrada propia; un `id` ajeno o inexistente → `404` (nunca `403`) |
| `GET /users/me/scan-targets?target=<ip\|ip/cidr>` | Resuelve las credenciales que mejor matchean el objetivo (más específico gana). `400` si `target` no es IP/CIDR, `422` si no hay match. Respuesta EXACTA: `{"network_user": "...", "ssh_credentials_ref": "...", "has_sudo": bool}` — el shape que consume `gateway::usuarios_client::ScanTargetCredentials`. Único endpoint que devuelve la credencial SSH |
