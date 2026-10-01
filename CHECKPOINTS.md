# CHECKPOINTS — Evaluación del estado final

> En sistemas multi-agente no se evalúa el camino, se evalúa el destino.
> Estos son los checkpoints objetivos que un juez (humano o IA) puede usar
> para decidir si el proyecto está sano.

## C1 — El arnés está completo

- [ ] Existen los archivos base: `init.sh`, `feature_list.json`,
      `CHECKPOINTS.md`.
- [ ] `./init.sh` termina con exit code 0.

## C2 — El estado es coherente

- [ ] Como mucho una feature en `in_progress` en `feature_list.json`.
- [ ] Toda feature `done` tiene tests asociados que pasan.
- [ ] Toda feature sustancial en curso tiene su documento ODD en
      `odd/tasks/<feature>.md` y su copia en Engram
      (`odd/<feature>/tasks`), sincronizados y sin tareas marcadas sin
      evidencia.

## C3 — El código respeta la arquitectura

- [ ] `src/` solo contiene los módulos previstos (`config`, `domain`,
      `repository`, `audit`, `api`, `wiring`), más `lib.rs` y un `main.rs`
      delgado.
- [ ] Toda dependencia en `Cargo.toml` está justificada por una feature de
      `feature_list.json`.
- [ ] No hay `println!`/`dbg!` sueltos para debug, ni `unwrap()`/`panic!()`
      fuera de tests sin justificar, ni TODOs sin contexto.
- [ ] `cargo doc --no-deps` genera sin warnings (todo ítem público tiene
      rustdoc).

## C4 — La verificación es real

- [ ] `tests/` tiene al menos un test de integración por módulo que cruza
      IO (`repository`, `api`).
- [ ] Los tests de `repository`/`api` corren contra un contenedor PostgreSQL
      real vía `testcontainers`, nunca contra `db-usuarios` de producción.
- [ ] Existe al menos un test que verifica que el log de auditoría rechaza
      `UPDATE`/`DELETE` a nivel de base de datos.
- [ ] `cargo test` muestra > 0 tests y todos verdes.
- [ ] `cargo clippy --all-targets -- -D warnings` no muestra advertencias.

## C5 — La sesión se cerró bien

- [ ] No hay archivos sin trackear sospechosos (`*.tmp`, `target/` fuera del
      `.gitignore`).
- [ ] Cada tarea cerrada tiene su commit (Conventional Commits) registrado
      como evidencia en su documento ODD.
- [ ] La sesión dejó su resumen en Engram (`mem_session_summary`).
- [ ] La última feature trabajada está reflejada en su estado correcto.

---

**Cómo usar este archivo:** antes de cerrar una sesión, el orquestador
(gentle-ai) o un revisor humano recorre cada checkbox, marca `[x]` o `[ ]`,
y no da la sesión por cerrada si quedan boxes vacíos en C1-C5. La revisión
de código de cada commit la hace el review nativo de gentle-ai
(`gentle-ai review`) cuando está activo; este archivo no la reemplaza.
