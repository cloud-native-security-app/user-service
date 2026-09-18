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
  -p 8080:8080 \
  user-service:local
```
