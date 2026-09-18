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

Pendiente — se documenta al implementar la feature `containerization` (ver
`feature_list.json`).
