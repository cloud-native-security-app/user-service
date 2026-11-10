# flaky-unit-tests

Feature id: `flaky-unit-tests` | Branch: `fix/flaky_unit_tests` (apilada sobre `feature/user_role`, aún sin fusionar)

Origen: sección "Flaky unit test investigation" de `odd/tasks/user-role.md`.

## Objetivo

Eliminar dos fuentes de no determinismo en `cargo test --lib` sin cambiar el comportamiento de producción.

## Tareas

- [x] T1 Conexiones acotadas: `acquire_timeout` en el pool de migraciones y en el de aplicación (`src/wiring.rs`). Commit `2e9b915`.
- [x] T2 Carga de configuración sin entorno: `Config::from_lookup` (lógica pura) y `from_env` como envoltorio fino; tests con mapa en memoria; sin `unsafe`, `ENV_MUTEX` ni `EnvGuard` (`src/config.rs`). Commit `96ce0f0`.
- [x] T3 Documentación (este archivo).

## Decisiones

- `DATABASE_CONNECT_TIMEOUT` = 10 s en producción: sobra para un handshake TCP/TLS contra una base sana o recién levantada y falla tres veces más rápido que el valor por defecto de `sqlx` (30 s), de modo que el orquestador reinicia pronto. No se añadió a `Config` para no cambiar su API ni los literales de `tests/service_wiring.rs`; si un operador necesita ajustarlo, se puede mover allí.
- Los tests usan `build_router_with_connect_timeout(&config, 1 s)` (función privada), con una cota externa `tokio::time::timeout(10 s)` que detecta regresiones.
- `from_env` no tiene test propio: ejercitarlo exige leer o mutar el entorno real; la cobertura queda en `from_lookup`, y `from_env` es una sola línea (`std::env::var_os`). `tests/scaffolding.rs` ya lo orquesta de extremo a extremo.

## Evidencia TDD (strict)

- T1 RED: test con `tokio::time::timeout(10 s, build_router(&config))` -> `Elapsed(())`, `finished in 10.00s` (el pool esperaba los 30 s por defecto).
- T1 GREEN: con `acquire_timeout`, el mismo test (con 1 s) -> `ok`, `finished in 1.00s`.
- T2 RED: tests reescritos con `Config::from_lookup` -> `error[E0599]: no associated function named from_lookup`.
- T2 GREEN: 14 tests de `config` en verde; `rg "set_var|remove_var|ENV_MUTEX" src/` sin resultados.

## Resultados

- Suite `cargo test --lib`: antes 59 tests en ~30 s; ahora `59 passed; finished in 2.01s` (3 ejecuciones seguidas).
- Revisión pre-commit (GGA): aprobada en ambos commits.
