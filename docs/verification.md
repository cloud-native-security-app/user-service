# Verificación — Cómo demostrar que el trabajo funciona

> Regla de oro: **el agente no dice "funciona", lo demuestra**.
> Toda feature termina con evidencia ejecutable, no con afirmaciones.

## Niveles de verificación

### Nivel 0 — Documentación de código (obligatorio)

```bash
cargo doc --no-deps
```

Todo ítem público sin rustdoc (`///`) es motivo de `CHANGES_REQUESTED` en
revisión, no solo un nice-to-have.

### Nivel 1 — Tests unitarios (obligatorio)

Toda función pública de lógica pura (`domain`) tiene al menos un test que:

1. Cubre el camino feliz.
2. Cubre al menos un camino de error si la función puede fallar.

Comando:
```bash
cargo test
```

### Nivel 2 — Lints y formato (obligatorio)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Ningún warning de clippy se ignora en silencio; si es un falso positivo,
se documenta con `#[allow(...)]` y un comentario explicando por qué.

### Nivel 3 — Tests de integración (obligatorio para repository y api)

- `repository`: contra el contenedor PostgreSQL oficial levantado vía
  `testcontainers`, con las migraciones de `migrations/` aplicadas al
  arrancar el contenedor de test, nunca contra `db-usuarios` de producción.
- `api`: levanta el servicio `axum` real sobre el mismo contenedor Postgres
  de test y ejerce los endpoints con un cliente HTTP (`reqwest` o el cliente
  de test de `axum`), no llamando a los handlers como funciones sueltas.
- El log de auditoría tiene, además, un test de integración específico que
  intenta un `UPDATE`/`DELETE` directo sobre la tabla y espera que la base
  de datos lo rechace (permiso denegado) — ver `docs/security-scope.md`.
- Todo test de esta categoría se marca `#[ignore = "requiere Docker"]` (ver
  `docs/conventions.md`), se ejecuta con `cargo test -- --ignored`, y
  requiere Docker disponible (local o en CI). Si falla por falta de Docker,
  se documenta como bloqueo en `progress/current.md` — no se reemplaza por
  un mock.

## Anti-patrones (no hacer)

- ❌ "Añadí el endpoint, debería funcionar." → falta test ejecutable contra
  el servicio real.
- ❌ Test que solo verifica el status code HTTP. → tiene que comprobar el
  contenido concreto del cuerpo de la respuesta.
- ❌ Probar `repository`/`api` contra una base de datos de producción o
  compartida.
- ❌ Silenciar un warning de `clippy` con `#[allow(...)]` sin comentario.
- ❌ Marcar la feature como `done` sin pasar `./init.sh`.
- ❌ "Ya probé manualmente que el log de auditoría no se puede editar" sin
  un test que lo demuestre contra la base de datos real.

## Verificación final antes de cerrar

```bash
./init.sh           # debe terminar con [OK] Entorno listo
```

Si `./init.sh` está rojo, **no** marques nada como `done`. Anota el bloqueo
en `progress/current.md` y pon `"status": "blocked"` en `feature_list.json`.
