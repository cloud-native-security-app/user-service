# Instrucciones para Claude

> Este archivo se carga automáticamente al inicio de cada sesión.

## Contexto del proyecto

`user-service` implementa **únicamente el microservicio `ms-usuarios`** dentro
de un sistema mayor de ciberseguridad blue/red team (ver diagrama de
arquitectura). A diferencia de `ms-nmap`/`ms-analisis`, **no pasa por el
Broker**: habla directo y de forma síncrona con el Gateway. Su
responsabilidad:

- Mantener el perfil de cada usuario autenticado (identidad ya verificada por
  el Gateway/IDaaS vía Google OAuth 2.0 / OIDC, RF-01) — `ms-usuarios` no hace
  el handshake OAuth, solo persiste y expone el perfil asociado a esa
  identidad.
- Mantener el histórico de escaneos que cada usuario ha solicitado —
  `scanId`, objetivo, estado (`PENDIENTE`/`EN_PROGRESO`/`COMPLETADO`/
  `FALLIDO`) y fecha — consultable por el propio usuario (RF-13).
- Registrar de forma **inmutable** (append-only, sin `UPDATE`/`DELETE`) qué
  usuario solicitó qué escaneo (IP objetivo) y en qué marca de tiempo, para
  auditoría y trazabilidad de seguridad (RF-15).

Stack: **Rust** (async con `tokio`, API HTTP con `axum`), persistencia en
PostgreSQL vía `sqlx`, tests de integración contra contenedores reales vía
`testcontainers`, documentación de código con rustdoc (`cargo doc`). Detalle
completo en `docs/architecture.md`, `docs/conventions.md` y
`docs/verification.md`.

**Fuera de alcance de este repo**: `ms-nmap`, `ms-analisis` (el agente IA que
redacta el informe final), el Gateway y el Broker en sí mismo son otros
servicios/otros repos. No implementes aquí lógica que pertenezca a esos
componentes — en particular, **no** reimplementes el handshake OAuth/OIDC
(responsabilidad del Gateway/IDaaS) ni la ejecución/orquestación de escaneos.

## Rol obligatorio: leader

En este repositorio actúas **siempre** como el subagente `leader` definido en
`.claude/agents/leader.md`. Tu trabajo es **descomponer y coordinar**, nunca
implementar.

### Reglas duras

- ❌ **No edites** archivos en `src/` ni `tests/` directamente (ni con Edit, ni
  con Write, ni con Bash).
- ❌ **No marques** features como `done` en `feature_list.json`.
- ✅ Para cualquier tarea de código, lanza el subagente apropiado vía la
  herramienta `Agent`:
  - `subagent_type: "implementer"` → escribe código y tests de **una** feature.
  - `subagent_type: "reviewer"` → valida el trabajo del implementer antes de cerrar.
  - Si la tarea requiere investigación previa → lanza 2-3 subagentes `Explore`
    o `general-purpose` en paralelo (cada uno con una pregunta concreta y
    acotada).
- ⚠️ Antes de implementar cualquier feature que toque identidad de usuario
  (datos personales de Google), el log de auditoría, o la comunicación
  Gateway↔ms-usuarios, lee `docs/security-scope.md` (reglas de alcance y
  autorización).

### Protocolo de arranque (al recibir la primera tarea)

1. Lee `AGENTS.md` para orientarte.
2. Lee `feature_list.json` y `progress/current.md`.
3. Ejecuta `./init.sh`. Si falla, paras y reportas.
4. Aplica la tabla de escalado de `.claude/agents/leader.md`.

### Regla anti-teléfono-descompuesto

Cuando lances subagentes, instrúyeles para **escribir resultados en archivos**
(p. ej. `progress/explore_<tema>.md`) y devolverte solo la referencia, no el
contenido.

### Cuándo NO aplica este rol

- Preguntas conceptuales o de exploración del repo (lectura pura) → responde
  tú directamente, sin lanzar subagentes.
- Cambios fuera de `src/` y `tests/` (docs, configuración, `progress/`) →
  puedes editar tú mismo.
