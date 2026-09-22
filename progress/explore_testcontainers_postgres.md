# Investigación: `testcontainers`/`testcontainers-modules` (Postgres) + `sqlx::migrate!` en tests de integración

Fecha: 2026-09-18. Verificado contra el estado real del repo (no supuestos de
versión sin comprobar).

## 1. Crates y versiones exactas (verificadas)

| Crate | Versión a usar | Cómo se verificó |
|---|---|---|
| `sqlx` | `0.8.6` (ya en `Cargo.lock`, features `postgres` + `runtime-tokio-rustls`) | `grep -A2 'name = "sqlx"' Cargo.lock` en este repo |
| `testcontainers-modules` (feature `postgres`) | `0.15.0` | `cargo add testcontainers-modules --dry-run --features postgres --dev` dentro de `user-service` → resuelve `0.15.0`. También está fijado en `../broker/Cargo.lock` (ahí usado con la feature `rabbitmq`, pero es la misma versión de crate) |
| `testcontainers` | `0.27` (p. ej. `0.27.3`) | `../broker/Cargo.lock` fija `testcontainers = 0.27.3`; docs.rs confirma que `testcontainers-modules 0.15.0` depende de `testcontainers ^0.27.0`; `cargo add testcontainers@0.27 --dry-run --dev` en `user-service` resuelve sin conflicto |

**Hallazgo importante:** el `Cargo.toml` actual de `user-service` ya trae
`testcontainers = "0.20"` en `[dev-dependencies]` (de la feature 1,
scaffolding). Esa versión **no es compatible** con
`testcontainers-modules 0.15.0` (que exige `testcontainers ^0.27.0`). Antes de
poder usar `testcontainers_modules::postgres`, el implementer debe:

- subir `testcontainers` de `"0.20"` a `"0.27"` (o directamente eliminar la
  entrada explícita y depender del re-export `testcontainers_modules::testcontainers`,
  ver más abajo), y
- añadir `testcontainers-modules = { version = "0.15.0", features = ["postgres"] }`
  a `[dev-dependencies]`.

Nota: `testcontainers-modules` re-exporta el crate `testcontainers` como
`testcontainers_modules::testcontainers`, así que en el código de test se
puede escribir `testcontainers_modules::testcontainers::runners::AsyncRunner`
sin depender directamente de `testcontainers` como crate separado — pero el
patrón que ya usa `broker` (ver `broker/tests/common/mod.rs`) depende de
`testcontainers` como crate propio (`use testcontainers::runners::AsyncRunner;`,
`use testcontainers::ContainerAsync;`), así que por consistencia con el
hermano conviene mantener ambas dependencias explícitas como hace `broker/Cargo.toml`:

```toml
[dev-dependencies]
testcontainers = "0.27"
testcontainers-modules = { version = "0.15.0", features = ["postgres"] }
```

**Verificación realizada sin tocar el repo real:** se corrió
`cargo add testcontainers-modules --dry-run --features postgres --dev` y
`cargo add testcontainers@0.27 --dry-run --dev` dentro de `user-service`
(ambos con `--dry-run`, que Cargo aborta explícitamente sin escribir
archivos). Se verificó con `git status --short` y `diff` contra copias de
respaldo de `Cargo.toml`/`Cargo.lock` que ningún archivo del repo quedó
modificado.

`tokio`: el `Cargo.toml` actual de `user-service` solo pide
`features = ["rt-multi-thread", "macros"]`. `broker` (que ya usa
`testcontainers`) pide además `"time"`, `"net"`, `"io-util"`. No son
estrictamente necesarias solo por `testcontainers`/`AsyncRunner` (que trae su
propio runtime interno vía `bollard`), pero si el helper de test agrega
lógica propia de espera/retry con `tokio::time::sleep` habrá que añadir la
feature `"time"`.

## 2. Snippet: contenedor + migraciones + `PgPool`

Patrón confirmado contra `docs.rs` (`testcontainers-modules 0.15.0`,
`testcontainers 0.27.3`) y contra el uso real ya existente en
`broker/tests/common/mod.rs` (mismo `AsyncRunner`/`ContainerAsync`, solo que
ahí con el módulo `RabbitMq` en vez de `Postgres`):

```rust
// tests/repository_postgres.rs (o tests/common/mod.rs si se comparte)

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres as PostgresImage;

/// Arranca un contenedor Postgres real y devuelve el contenedor (hay que
/// mantenerlo con vida mientras dure el test: al hacer `drop` del
/// `ContainerAsync`, testcontainers detiene y elimina el contenedor) junto
/// con un `PgPool` ya migrado.
async fn start_migrated_postgres() -> (ContainerAsync<PostgresImage>, PgPool) {
    // Imagen/tag explícitos para no depender del `latest` del día y quedar
    // alineados con la versión de Postgres de producción (mismo criterio
    // que `broker` fija RABBITMQ_TAG en vez de usar el tag por defecto).
    let container = PostgresImage::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("el contenedor Postgres debe arrancar");

    let host = container.get_host().await.expect("host del contenedor");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("puerto 5432 mapeado");

    // Credenciales por defecto de la imagen del módulo: user=postgres,
    // password=postgres, db=postgres (ver §1 y docs.rs de
    // `testcontainers_modules::postgres::Postgres`).
    let connection_string = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&connection_string)
        .await
        .expect("debe poder conectar al Postgres del contenedor");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("las migraciones deben aplicar limpio sobre una DB nueva");

    (container, pool)
}

#[tokio::test]
#[ignore = "requiere Docker"]
async fn algo_que_depende_del_esquema_migrado() {
    let (_container, pool) = start_migrated_postgres().await;

    // ... usar `pool` para ejercitar el repositorio real contra Postgres real ...

    // `_container` debe seguir viva (aunque no se use directamente) hasta
    // el final del test: si se descarta el valor de retorno de `.start()`
    // en vez de ligarlo a una variable, el contenedor se detiene de
    // inmediato y la conexión falla o queda huérfana.
}
```

Notas sobre el snippet:

- `sqlx::migrate!("./migrations")` es una macro que lee el directorio de
  migraciones **en tiempo de compilación** (ruta relativa a
  `CARGO_MANIFEST_DIR`) y embebe el SQL en el binario — a diferencia de
  `sqlx::query!`/`query_as!`, **no** requiere `DATABASE_URL` ni
  `SQLX_OFFLINE` para compilar. Hoy `migrations/` solo tiene `README.md` (sin
  archivos `.sql` reales todavía), así que la macro compila igual pero
  `.run()` no aplicará nada hasta que existan migraciones reales.
- El formato de archivo que `sqlx migrate add` genera y que la macro espera
  es `migrations/<timestamp>_<descripcion>.sql` (o `.up.sql`/`.down.sql` si
  se usan migraciones reversibles con `sqlx migrate add -r`).
- `PgPoolOptions`/`PgPool` están confirmados como API estable de
  `sqlx 0.8.x` bajo `sqlx::postgres::PgPoolOptions` (o el re-export
  `sqlx::PgPool` para el tipo del pool).

## 3. Aislamiento entre tests

Dos estrategias razonables, ambas compatibles con lo ya establecido en este
repo (cada archivo en `tests/*.rs` ya compila a un binario de test separado,
lo que da aislamiento de proceso entre archivos):

**a) Un contenedor por test (recomendado para empezar, más simple).**
Cada `#[tokio::test]` llama a `start_migrated_postgres()` y obtiene su propio
contenedor + su propia base `postgres` recién migrada desde cero. Cero
posibilidad de interferencia entre tests porque no comparten nada. Costo:
cada contenedor tarda del orden de 1-3 s en arrancar (más lento si la imagen
no está cacheada localmente); con pocos tests de integración por feature
(como es el patrón de este repo, un archivo `tests/<feature>.rs` por
feature) el costo total es asumible.

**b) Un contenedor compartido por binario de test + una base de datos nueva
por test.** Si el número de tests por archivo crece y el arranque de
contenedores empieza a dominar el tiempo de test, se puede levantar **un**
contenedor una sola vez (p. ej. con `tokio::sync::OnceCell` o
`std::sync::OnceLock` + un `tokio::Runtime` compartido, o con el crate
`ctor`/`once_cell`) y, para cada test, conectar como superusuario
(`postgres`/`postgres`), hacer `CREATE DATABASE test_<nombre_o_uuid>`,
conectar un `PgPool` nuevo a esa base y correr `sqlx::migrate!` contra ella.
Importante: los `#[tokio::test]` de un mismo archivo se ejecutan
**concurrentemente** por defecto (cada uno en su propio runtime de Tokio de
un solo hilo), así que si se comparte contenedor, **nunca** se debe compartir
también la base de datos entre tests — cada test necesita su propio nombre
de base (p. ej. derivado de `uuid::Uuid::new_v4()`) para que las
transacciones/filas de un test no contaminen otro.

Dado el tamaño actual del repo (pocas features, un archivo de test por
feature), la opción (a) es la que debería usar el implementer salvo que el
tiempo de test se vuelva un problema real.

## 4. Gotchas conocidos

- **Wait-for-ready ya viene resuelto por el módulo.** `testcontainers_modules::postgres::Postgres`
  define su propia condición de espera (`WaitFor`) para no devolver el
  control de `.start().await` hasta que Postgres acepta conexiones — no hace
  falta un `sleep`/retry manual en el caso común. Aun así, en CI lento o con
  el host muy cargado, algunos proyectos añaden un retry defensivo alrededor
  del primer `.connect()` (unos pocos intentos con backoff corto) para
  cubrir el borde en que la condición de espera se cumple pero el listener
  TCP tarda un instante más en aceptar. No fue posible confirmar el texto
  exacto del log que usa el `WaitFor` interno de esta versión sin descargar
  el código fuente del crate (no estaba cacheado localmente y no se instaló
  de verdad para no tocar el lockfile del repo) — si aparecen fallos
  intermitentes de conexión, revisar el código fuente de
  `testcontainers-modules 0.15.0` (`src/postgres/mod.rs` en el repo del
  crate) para ver la condición exacta.
- **Pin del tag de imagen.** Igual que `broker` fija `RABBITMQ_TAG` en vez de
  usar el tag por defecto del módulo, conviene fijar un tag de Postgres
  explícito (`.with_tag("16-alpine")` o la versión que use el `docker-compose.yml`
  de este repo/el Postgres de producción) para no depender de qué tag por
  defecto trae la versión del crate ni de sorpresas al actualizar Postgres
  en prod sin querer.
- **No soltar el `ContainerAsync`.** El contenedor se detiene/elimina al
  hacer `drop` del valor devuelto por `.start()`. Si se descarta el
  resultado (p. ej. `let _ = ... .start().await;` en vez de ligarlo a una
  variable con nombre), el contenedor puede pararse antes de que el test
  termine de usarlo. En el snippet de §2 por eso se devuelve y se mantiene
  `_container` vivo durante todo el test.
- **Pull de imagen en frío.** La primera vez que corre en una máquina/CI sin
  la imagen de Postgres cacheada, Docker tiene que descargarla — eso puede
  tardar bastante más que el arranque en sí. No es un bug del crate, es
  costo de Docker; si el timeout por defecto de `testcontainers` no alcanza
  en un runner de CI lento, se puede sobreescribir vía las variables de
  entorno que usa `testcontainers` para el cliente Docker (`DOCKER_HOST`,
  etc.) o simplemente pre-pullear la imagen en un paso previo del pipeline.
- **Convención `#[ignore = "requiere Docker"]`.** Ya es el patrón usado en
  todos los tests de integración de `broker` (`tests/topology_exists.rs`,
  etc.) para que `cargo test` normal no falle en máquinas sin Docker, y se
  corran explícitamente con `cargo test -- --ignored`. Se recomienda seguir
  exactamente esa convención aquí para consistencia entre los dos repos
  hermanos.
- **Posible colisión de `CryptoProvider` de `rustls` (riesgo, no confirmado
  para este caso concreto).** `broker/tests/common/mod.rs` documenta un bug
  real que les mordió: cuando en el mismo binario de test quedan enlazados
  dos proveedores criptográficos de `rustls` distintos (`ring` vía una
  dependencia y `aws-lc-rs` vía otra — en su caso `testcontainers`/`bollard`/
  `hyper-rustls` traen `aws-lc-rs` y `reqwest`/`rustls-platform-verifier`
  traen `ring`), la primera conexión TLS no falla con un error explícito:
  el hilo interno hace panic con *"Could not automatically determine the
  process-level CryptoProvider"* **en un hilo separado**, y el `.await` que
  depende de esa conexión se queda colgado para siempre (parece un cuelgue,
  no un fallo). En `user-service`, `sqlx` con la feature
  `runtime-tokio-rustls` también enlaza `rustls`, y `testcontainers`/`bollard`
  puede enlazar otro proveedor para hablar con el daemon Docker por TLS (uso
  remoto de Docker) o para otra dependencia transitiva. La conexión al
  Postgres del contenedor en sí es TCP plano (no usa TLS), así que en el
  caso más común esto no debería dispararse — pero si al añadir
  `testcontainers-modules` aparece un test que se cuelga sin error visible en
  vez de fallar, esto es lo primero a revisar. Mitigación usada por
  `broker` (aplicable igual aquí si hiciera falta): instalar el proveedor
  una sola vez por proceso al inicio del helper de test con
  `rustls::crypto::aws_lc_rs::default_provider().install_default()` dentro
  de un `std::sync::Once`.
- **No hace falta montar nada en el contenedor para las migraciones.** A
  diferencia del caso de `broker` con RabbitMQ (que monta
  `rabbitmq/definitions.json` vía `Mount::bind_mount` porque RabbitMQ carga
  su topología desde un archivo dentro del contenedor), acá las migraciones
  se aplican **desde fuera**, ejecutando SQL a través de la conexión de red
  ya abierta (`sqlx::migrate!(...).run(&pool)`), así que no se necesita
  `Mount`/`ImageExt::with_mount` en absoluto — más simple que el patrón de
  `broker`.

## Resumen de acción para el implementer

1. En `Cargo.toml`: subir `testcontainers` de `"0.20"` a `"0.27"` y añadir
   `testcontainers-modules = { version = "0.15.0", features = ["postgres"] }`
   a `[dev-dependencies]`.
2. Escribir un helper (p. ej. `tests/common/mod.rs`, mismo patrón que
   `broker`) que arranque `testcontainers_modules::postgres::Postgres`,
   obtenga host/puerto con `get_host()`/`get_host_port_ipv4(5432)`, construya
   la connection string `postgres://postgres:postgres@{host}:{port}/postgres`,
   abra un `PgPool` con `PgPoolOptions`/`PgPool::connect` y corra
   `sqlx::migrate!("./migrations").run(&pool).await`.
3. Marcar los tests que lo usan con `#[tokio::test] #[ignore = "requiere Docker"]`,
   igual que en `broker`.
4. Empezar con un contenedor por test (§3a); revisar hacia el modelo
   compartido (§3b) solo si el tiempo de test se vuelve un problema.
