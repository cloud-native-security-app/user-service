# Reglas de revisión de código — user-service

> Reglas que usa el revisor automático (Gentleman Guardian Angel) sobre cada
> commit. Un diff que viole una regla marcada como **bloqueante** se rechaza.

## Contexto

`user-service` (`ms-usuarios`) es un microservicio Rust (tokio + axum + sqlx
sobre PostgreSQL). Recibe del Gateway una identidad ya verificada y guarda
perfiles, histórico de escaneos, auditoría y credenciales de red cifradas.

## Seguridad (bloqueante)

- Nunca escribir datos personales (`sub`, `email`, nombre de Google) ni
  secretos (credencial de servicio, claves de cifrado, credenciales de red)
  en logs de `tracing`, mensajes de error, respuestas HTTP o panic messages.
- Los errores internos nunca exponen detalle de infraestructura en el cuerpo
  de la respuesta HTTP: van como `ApiError::Internal` genérico y el detalle
  solo al log del servidor.
- Todo handler que reciba un identificador de recurso verifica que pertenece
  a la identidad reenviada por el Gateway antes de tocar la base de datos
  (`403` si no coincide). Nunca se confía en un `user_id` del cuerpo o query.
- Ningún secreto ni valor de configuración hardcodeado: todo sale de
  variables de entorno vía `src/config.rs`, con tipos que redactan su
  contenido (`secrecy`).
- `audit_log` es append-only: ningún `UPDATE`/`DELETE` sobre esa tabla, ni
  métodos que lo permitan en el repositorio.
- No agregar listeners públicos ni CORS abierto: el servicio solo habla con
  el Gateway.

## Corrección (bloqueante)

- Nada de `unwrap()`/`expect()`/`panic!()` fuera de tests, salvo condición
  irrecuperable documentada con un comentario.
- Errores tipados por módulo con `thiserror`; nada de `String` como error ni
  `anyhow` en firmas públicas.
- Ninguna llamada bloqueante dentro de código async (usar `spawn_blocking`).
- Las migraciones ya aplicadas no se editan: un cambio de esquema es una
  migración nueva en `migrations/`.

## Tests

- Todo cambio de comportamiento trae su test en el mismo commit.
- Los tests que cruzan IO (`repository`, `api`) corren contra PostgreSQL real
  vía `testcontainers` y se marcan `#[ignore = "requiere Docker"]`; nunca
  mocks de la base de datos.
- Datos de prueba sintéticos (`test-user-<n>@example.test`), nunca
  identidades reales.
- Nombres de test descriptivos del comportamiento
  (`find_user_returns_none_when_user_does_not_exist`).

## Estilo

- Código formateado con `cargo fmt` y sin warnings de
  `cargo clippy --all-targets -- -D warnings`.
- Todo ítem público lleva rustdoc `///` (el crate usa
  `#![deny(missing_docs)]`).
- Sin `println!`/`dbg!` de debug ni TODOs sin contexto.
- Nombres: `snake_case` para módulos, funciones y variables; `PascalCase`
  para tipos; `UPPER_SNAKE` para constantes.
