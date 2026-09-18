# Convenciones de código

> Homogeneidad extrema. La IA predice mejor cuando el repositorio se parece
> a sí mismo en todas partes.

## Estilo Rust

- **Edition:** 2021 o superior.
- **Formato:** `cargo fmt` (configuración por defecto salvo que se documente
  lo contrario en `rustfmt.toml`).
- **Lints:** `cargo clippy --all-targets -- -D warnings` debe pasar sin
  advertencias (incluye el código de `tests/`, no solo `src/`).
- **Async:** runtime `tokio`. Ninguna llamada bloqueante directamente en una
  tarea async — usar `spawn_blocking` si la dependencia no es nativamente
  async.
- **Errores:** tipos de error propios por módulo con `thiserror` (variantes
  específicas, no `String`). `anyhow` solo se permite en `main.rs` o en el
  borde del proceso, nunca en la firma pública de una función de dominio.
- **Nada de `unwrap()`/`expect()`/`panic!()`** fuera de tests, a menos que la
  condición sea verdaderamente irrecuperable y esté documentada con un
  comentario explicando por qué.
- **Rustdoc:** todo ítem público (`pub fn`, `pub struct`, `pub enum`,
  `pub trait`) lleva un comentario `///` explicando su propósito (qué hace,
  qué puede fallar). El crate activa `#![deny(missing_docs)]` en
  `src/lib.rs` (no en `src/main.rs`).
- **Tests de integración con IO real:** se levantan con el crate
  `testcontainers` (contenedor `postgres` oficial para `repository` y
  `api`). Nunca mocks de la base de datos — ver `docs/verification.md`.
- **Todo test que dependa de Docker vía `testcontainers` se marca**
  `#[ignore = "requiere Docker"]`. Así `cargo test` (sin flags) corre rápido
  y sin depender de Docker, y `cargo test -- --ignored` corre específicamente
  los de integración. `init.sh` ejecuta ambos.
- **Migraciones de base de datos** viven en `migrations/` (formato
  `sqlx migrate`), versionadas y nunca editadas tras haberse aplicado en
  algún entorno — un cambio de esquema es una migración nueva.

## Nombres

| Tipo                    | Convención        | Ejemplo                |
|-------------------------|-------------------|--------------------------|
| Módulos/archivos        | `snake_case`      | `repository.rs`, `api.rs` |
| Tipos/traits            | `PascalCase`      | `UserProfile`, `RepoError` |
| Funciones / variables   | `snake_case`      | `find_by_id`            |
| Constantes              | `UPPER_SNAKE`     | `DEFAULT_HTTP_PORT`     |
| Módulos privados        | prefijo `_` en el ítem, no en el módulo | `_internal_helper` |

## Estructura de un módulo

```rust
//! Una línea describiendo el propósito del módulo.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domain::UserProfile;

// tipos y lógica del módulo
```

- Imports: primero `std`, luego crates externos, luego `crate::...` — cada
  grupo separado por una línea en blanco (orden que aplica `rustfmt`
  automáticamente).

## Tests

- Tests unitarios: `#[cfg(test)] mod tests` al final del propio archivo, para
  lógica pura (`domain`). El módulo de test ve las funciones privadas del
  archivo vía `use super::*`.
- Tests de integración: en `tests/`, un archivo por módulo que cruza un
  límite de IO real (`repository`, `api`).
- Los tests de `repository`/`api` corren contra una instancia de PostgreSQL
  de prueba (contenedor `testcontainers`), nunca contra `db-usuarios` de
  producción.
- Nombres de test descriptivos:
  `find_by_id_returns_none_when_user_does_not_exist`.

## Manejo de errores (ejemplo)

```rust
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("no se pudo conectar a la base de datos")]
    ConnectionFailed,
    #[error("violación de restricción de base de datos: {0}")]
    Constraint(String),
    #[error("error inesperado de backend")]
    Backend,
}
```

Los mensajes de error nunca incluyen datos personales (email, nombre) ni
credenciales de sesión.

## Comentarios

Por defecto **no** se escriben. Solo se permiten cuando explican un *por qué*
no obvio (p. ej. workaround documentado, invariante sutil, restricción de
`docs/security-scope.md`). Los nombres deben hacer el resto.
