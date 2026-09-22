# Investigación: `audit_log` append-only reforzado a nivel de PostgreSQL

> Investigación para la feature `postgres_persistence` (id 4). Cubre las 4
> preguntas del encargo: SQL de migración, el problema del superusuario de
> `testcontainers`, cómo evitar hardcodear una contraseña de producción en
> una migración versionada, y un test de integración Rust que verifique el
> rechazo por permisos. No incluye código de `src/`/`tests/` (esto es
> investigación pura del `leader`); el `implementer` debe traducir esto a
> archivos reales en la próxima sesión que tome la feature 4.

## Resumen ejecutivo

1. Dos migraciones separadas: una crea las 3 tablas (`users`, `scan_history`,
   `audit_log`) con sus FKs; otra crea (idempotentemente) el rol de
   aplicación `ms_usuarios_app` **sin contraseña ni LOGIN** y aplica
   `REVOKE`/`GRANT` explícitos — `audit_log` recibe únicamente
   `SELECT, INSERT`.
2. El contenedor oficial `postgres:<tag>` arranca con un único superusuario
   (`POSTGRES_USER`, por defecto `postgres`) que **ignora cualquier
   REVOKE**. La migración debe aplicarse con ese superusuario (o con un rol
   "dueño" en producción), pero el **pool de la aplicación / del test debe
   conectarse con un rol distinto** (`ms_usuarios_app`) que no sea dueño de
   las tablas. Dueño de la tabla == se salta los grants, sin excepción.
3. La contraseña real del rol de aplicación **nunca vive en `migrations/`**.
   La migración deja el rol en `NOLOGIN`. En producción, alguien fuera de
   `sqlx` (secretos/DBA/Terraform) ejecuta `ALTER ROLE ... LOGIN PASSWORD
   '...'`. En testcontainers, el arnés de test ejecuta ese mismo `ALTER
   ROLE` en runtime, con una contraseña generada para esa ejecución,
   **después** de correr las migraciones y **antes** de abrir el pool de la
   aplicación.
4. El test de integración abre dos pools (superusuario para fixtures/DDL,
   `ms_usuarios_app` para el intento de `UPDATE`/`DELETE`) y afirma que el
   `Result` es `Err(sqlx::Error::Database)` con SQLSTATE `42501`
   (`insufficient_privilege`) — nunca panic, nunca `Ok`.

---

## 1. SQL de las migraciones

`sqlx migrate add <nombre>` (sin `-r`, ver `docs/conventions.md`: las
migraciones no se revierten, un cambio de esquema es una migración nueva)
genera un único archivo `migrations/<timestamp>_<nombre>.sql`. Propongo dos
migraciones separadas porque tienen dueños de ejecución conceptualmente
distintos (esquema vs. seguridad/roles) y porque así una revisión de
seguridad puede auditar la segunda sin releer la primera.

### `migrations/<timestamp1>_create_core_schema.sql`

```sql
-- Tablas base de ms-usuarios. Se aplica con el rol "dueño" (el superusuario
-- del contenedor en test, o el rol migrador en producción) — nunca con el
-- rol de aplicación, para que el endurecimiento de permisos de la siguiente
-- migración tenga efecto real (el dueño de una tabla se salta cualquier
-- REVOKE, ver sección 2).

CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_history (
    scan_id      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (user_id),
    target       TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (
        status IN ('PENDIENTE', 'EN_PROGRESO', 'COMPLETADO', 'FALLIDO')
    ),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_history_user_id_idx ON scan_history (user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users (user_id),
    target      TEXT NOT NULL,
    action      TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_user_id_idx ON audit_log (user_id);
```

Notas de diseño:

- `status` como `TEXT` + `CHECK` en vez de un `ENUM` de Postgres: coincide
  con el encoding `SCREAMING_SNAKE_CASE` que ya usa `ScanStatus` en
  `src/domain.rs` (`PENDIENTE`/`EN_PROGRESO`/`COMPLETADO`/`FALLIDO`) sin
  necesitar un tipo `sqlx::Type` custom con `ALTER TYPE` en migraciones
  futuras (los `ENUM` de Postgres son incómodos de versionar: añadir un
  valor requiere `ALTER TYPE ... ADD VALUE`, que no puede correr dentro de
  una transacción en versiones antiguas de Postgres). Un `CHECK` es una
  migración normal si RF-07 añade un quinto estado.
- Los IDs son `TEXT` generados por la aplicación (`user_id` = `sub` de
  Google, `scan_id`/`id` = ULID/UUID generado en `repository.rs`), no
  `SERIAL`/`IDENTITY`, así que no hace falta `GRANT USAGE` sobre ninguna
  `SEQUENCE` en la migración de permisos.
- `CREATE TABLE IF NOT EXISTS` hace la migración segura de re-ejecutar
  manualmente en un entorno donde alguien ya la aplicó a mano — no depende
  de esto para idempotencia real (`sqlx` ya llexa su propia tabla
  `_sqlx_migrations` y no reaplica una migración con la misma versión), pero
  es barato y evita un fallo confuso si alguna vez se ejecuta fuera de
  `sqlx migrate run`.

### `migrations/<timestamp2>_lock_audit_log_permissions.sql`

```sql
-- Crea (si no existe) el rol de aplicación de ms-usuarios SIN contraseña ni
-- LOGIN embebidos, y aplica el endurecimiento de permisos de
-- docs/security-scope.md:
--   - users, scan_history: SELECT/INSERT/UPDATE para el rol de aplicación
--     (el repositorio nunca hace DELETE sobre estas tablas tampoco, pero
--     eso no se refuerza aquí porque no es un requisito de seguridad de
--     RF-15 — solo audit_log lo es).
--   - audit_log: SOLO SELECT/INSERT. Nunca UPDATE/DELETE, ni siquiera para
--     el propio código de la aplicación (ver docs/architecture.md
--     "Qué NO hacer").
--
-- Por qué el rol se crea sin contraseña: ver
-- progress/explore_audit_log_permissions.md sección 3. Resumen: una
-- contraseña embebida aquí quedaría fija en el historial de sqlx y se
-- aplicaría igual en producción que en un contenedor de test efímero. Este
-- rol se deja en NOLOGIN; quien active el login (con una contraseña
-- gestionada aparte) es responsabilidad de cada entorno, no de esta
-- migración.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ms_usuarios_app') THEN
        CREATE ROLE ms_usuarios_app NOLOGIN;
    END IF;
END
$$;

-- El rol necesita poder conectarse a la base de datos y usar el esquema
-- público — ninguno de los dos está garantizado por defecto (Postgres 15+
-- ya no concede USAGE sobre "public" a PUBLIC). current_database() hace la
-- migración portable entre el nombre de BD de producción y el nombre
-- arbitrario que testcontainers asigna al contenedor de test.
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO ms_usuarios_app', current_database());
END
$$;

GRANT USAGE ON SCHEMA public TO ms_usuarios_app;

-- Sin grants implícitos vía PUBLIC sobre ninguna de las 3 tablas.
REVOKE ALL ON users, scan_history, audit_log FROM PUBLIC;

-- users / scan_history: grants normales que necesita el repositorio
-- (upsert_user, find_user, insert_scan_history, update_scan_status,
-- list_scan_history).
GRANT SELECT, INSERT, UPDATE ON users TO ms_usuarios_app;
GRANT SELECT, INSERT, UPDATE ON scan_history TO ms_usuarios_app;

-- audit_log: append-only reforzado a nivel de base de datos (RF-15).
-- REVOKE explícito primero por si alguna vez alguien concede algo más
-- amplio por error en una migración futura mal escrita: esta migración es
-- la fuente de verdad de "audit_log es solo INSERT/SELECT" y se puede
-- volver a aplicar su intención re-ejecutándola a mano en un incidente.
REVOKE ALL ON audit_log FROM ms_usuarios_app;
GRANT SELECT, INSERT ON audit_log TO ms_usuarios_app;
-- Deliberadamente NUNCA: GRANT UPDATE ON audit_log ...
-- Deliberadamente NUNCA: GRANT DELETE ON audit_log ...
```

### Pitfall crítico que esto evita: dueño de tabla vs. rol con grants

Si la migración se ejecuta con el mismo rol que luego usa la aplicación (p.
ej. si en producción `DATABASE_URL` apunta a un rol que además es el
`OWNER` de `audit_log` porque fue el que corrió `CREATE TABLE`), **todo el
REVOKE es teatro**: el dueño de una tabla en Postgres puede hacer
`UPDATE`/`DELETE`/`DROP` sobre ella sin importar los `GRANT`/`REVOKE`
vigentes (y por defecto también se salta `ROW LEVEL SECURITY`, aunque aquí
no se usa RLS). Por eso:

- Las migraciones (`sqlx migrate run` / `sqlx::migrate!(...).run(&pool)`)
  se ejecutan con un pool conectado como el rol **dueño** — el superusuario
  del contenedor en test, o un rol migrador dedicado en producción (fuera
  del alcance de este documento decidir cuál exactamente: es una decisión
  de infraestructura, pero debe **no ser** `ms_usuarios_app`).
- El pool que usa `src/repository.rs` en tiempo de ejecución (`Config::database_url`
  en `src/config.rs`) se conecta como `ms_usuarios_app`, que solo tiene los
  `GRANT` de la segunda migración.
- Esto implica que, en la práctica, el servicio necesita **dos** cadenas de
  conexión distintas en algún punto de su ciclo de vida: una para aplicar
  migraciones (dueño) y otra para servir tráfico (`ms_usuarios_app`). Hoy
  `Config` solo expone `database_url` (una sola URL) — esto es una
  decisión que la feature `postgres_persistence` / `service_wiring` tiene
  que resolver explícitamente (p. ej. añadir `MIGRATIONS_DATABASE_URL` como
  variable de entorno opcional que, si está ausente, cae de vuelta a
  `database_url` para entornos donde el operador decide correr las
  migraciones con el mismo rol dueño-de-todo por simplicidad). Lo dejo
  señalado aquí para que quien implemente la feature 4 no lo descubra tarde
  vía un test que falla de forma confusa (`UPDATE` que "sí funciona" porque
  el pool de test resultó ser el dueño).

---

## 2. El problema del superusuario de `testcontainers`

`Cargo.toml` solo depende de `testcontainers = "0.20"` (0.20.1 en
`Cargo.lock`) — **no** de `testcontainers-modules`, así que no hay una
imagen `postgres::Postgres` lista; hay que montar `GenericImage` a mano
contra `postgres:<tag>` (imagen fijada por tag concreto, no `latest`, mismo
principio que pide la feature `containerization` para el `Dockerfile`).

Ese contenedor oficial, con las env vars típicas
(`POSTGRES_PASSWORD`/`POSTGRES_DB`/`POSTGRES_USER`), arranca con **un solo**
rol: el superusuario (`POSTGRES_USER`, `postgres` si no se especifica). Ese
rol es dueño de todo lo que se cree con él y **ignora cualquier REVOKE** —
si el test corriera el `UPDATE`/`DELETE` contra `audit_log` usando ese
mismo rol, el test "pasaría" (la DB rechazaría el `UPDATE`) solo si Postgres
decidiera aplicar los grants a un superusuario, lo cual **nunca** ocurre:
un superusuario se salta toda comprobación de privilegios. El test sería
un falso negativo si no se resuelve esto.

### Solución: dos pools de conexión dentro del mismo test

1. **Pool de superusuario** (`postgres://postgres:<POSTGRES_PASSWORD>@127.0.0.1:<puerto mapeado>/<POSTGRES_DB>`):
   se usa para (a) correr `sqlx::migrate!("./migrations").run(&superuser_pool)`
   — así las migraciones de la sección 1 se aplican con un rol dueño, igual
   que en producción correrían con el rol migrador — y (b) para el `ALTER
   ROLE` que activa el login del rol de aplicación (sección 3) y para
   insertar fixtures.
2. **Pool de aplicación** (`postgres://ms_usuarios_app:<password efímera>@127.0.0.1:<mismo puerto>/<mismo db>`):
   se abre **después** de que el pool de superusuario haya corrido las
   migraciones y activado el login de `ms_usuarios_app`. Este es el pool
   contra el que se ejecutan los `UPDATE`/`DELETE` que el test espera que
   fallen — y también sería, en un test de `repository.rs` real, el pool
   que se le pasa al repositorio bajo prueba (para que el test de
   `repository` refleje exactamente los permisos de producción, no los del
   superusuario).

El puerto mapeado se obtiene de `container.get_host_port_ipv4(5432)` (API
de `testcontainers` 0.20); ambos pools apuntan al mismo host:puerto:db,
solo cambia el usuario/contraseña de la cadena de conexión.

---

## 3. Por qué el rol NO se crea con `LOGIN PASSWORD '...'` fija en la migración, y cómo se resuelve en cada entorno

`sqlx` no tiene problema técnico en ejecutar `CREATE ROLE ... LOGIN
PASSWORD '...'` dentro de un archivo de `migrations/` — es SQL válido y
`sqlx::migrate!` lo corre igual que cualquier otro statement. El problema
**no es técnico, es de gestión de secretos**:

- Las migraciones de `sqlx` son **el mismo archivo, byte a byte**, el que
  se aplica en un contenedor de test efímero y el que se aplicaría en
  `db-usuarios` de producción (mismo `migrations/`, mismo historial en
  `_sqlx_migrations`). Si el `.sql` contuviera `PASSWORD 'algo-fijo'`, esa
  contraseña:
  - Queda en el historial de git para siempre (rotarla requiere una
    migración nueva que la cambie, pero la vieja sigue en el historial).
  - Es la **misma** en todos los entornos que corran esa migración, salvo
    que se edite el archivo por entorno — lo cual viola la regla de
    `docs/conventions.md` de que una migración no se edita tras aplicarse.
  - Viola `docs/security-scope.md` ("Ningún valor de configuración queda
    hardcodeado en el repo" aplica también a credenciales de base de
    datos, no solo a `GATEWAY_SHARED_SECRET`).

- Para un rol de **test** efímero dentro de un contenedor Docker que se
  destruye al terminar el test, hardcodear una contraseña sería aceptable
  en aislamiento (nadie fuera de ese contenedor puede usarla) — pero como
  la migración es compartida con producción, no se puede aprovechar esa
  laxitud sin comprometer producción.

### Solución adoptada: separar "estructura del rol" (migración) de "credencial del rol" (fuera de `sqlx`)

La migración de la sección 1 (`..._lock_audit_log_permissions.sql`) crea el
rol **condicionalmente** (`IF NOT EXISTS`, ver `DO $$ ... $$`) y lo deja en
`NOLOGIN` — sin contraseña, no puede conectarse nadie con él todavía. Es
100% reproducible en testcontainers (un contenedor nuevo nunca tiene el
rol, así que siempre entra por la rama `CREATE ROLE`) y 100% segura de
aplicar en producción (no habilita ningún acceso por sí sola).

Activar el login es responsabilidad de **cada entorno**, fuera del control
de versiones de `sqlx`:

- **Producción:** un proceso separado (Terraform/Ansible/runbook del DBA/
  gestor de secretos tipo Vault o AWS Secrets Manager) ejecuta, una vez,
  algo equivalente a:
  ```sql
  ALTER ROLE ms_usuarios_app WITH LOGIN PASSWORD '<secreto gestionado fuera de git>';
  ```
  y la contraseña resultante es la que recibe `Config::database_url` (o el
  futuro `Config` con dos URLs, ver sección 1) vía variable de entorno —
  igual que `GATEWAY_SHARED_SECRET` en `src/config.rs`, nunca en el
  repositorio.
- **Testcontainers (dev/CI):** el propio arnés de test, en Rust, ejecuta el
  `ALTER ROLE` en runtime contra el pool de superusuario, con una
  contraseña generada para esa ejecución del test (no necesita ser
  criptográficamente fuerte — vive en un contenedor Docker efímero
  accesible solo desde `127.0.0.1` en un puerto aleatorio mientras dura el
  test — pero sí debe generarse en Rust, no copiarse literal en un
  `.sql` versionado, para que quede claro por construcción que no es una
  credencial de producción reutilizable). El orden es:
  ```
  1. Levantar contenedor postgres:<tag> (GenericImage).
  2. Pool superusuario -> sqlx::migrate!("./migrations").run(&superuser_pool)
     (crea tablas + rol ms_usuarios_app en NOLOGIN + grants).
  3. Pool superusuario -> ALTER ROLE ms_usuarios_app LOGIN PASSWORD '<generada>'.
  4. Pool de aplicación -> conectar como ms_usuarios_app con esa contraseña.
  5. Ejercer el repositorio / intentar UPDATE-DELETE contra audit_log con
     el pool de aplicación.
  ```

  Caveat práctico de `sqlx`: `ALTER ROLE ... PASSWORD $1` con un parámetro
  bindeado (`.bind(password)`) **no** funciona de forma fiable — `ALTER
  ROLE`/`CREATE ROLE` son *utility statements* del parser de Postgres y no
  todos aceptan parámetros vía el protocolo extendido de la misma forma que
  un `SELECT`/`INSERT`. La forma robusta es interpolar el valor en el
  string SQL con `format!(...)`, generando la contraseña desde un alfabeto
  restringido (alfanumérico, vía `rand::distributions::Alphanumeric`) para
  no tener que escapar comillas ni arriesgar inyección — es aceptable
  porque el valor lo genera el propio test, nunca un usuario externo.

- **Alternativa descartada:** tener una migración `.sql` distinta para
  dev/test vs. producción (p. ej. `migrations/` vs. `migrations_test/`
  aplicada con un segundo `sqlx::Migrator` solo en tests). Es viable
  técnicamente (`sqlx::migrate::Migrator::new(Path::new("./migrations_test"))`),
  pero se descarta aquí porque duplica la fuente de verdad del esquema
  (dos carpetas que pueden divergir) para resolver un problema que ya
  resuelve mejor "el rol se crea sin credencial y cada entorno decide cómo
  activarlo" — que es además el patrón estándar de gestión de secretos de
  base de datos fuera de migraciones versionadas (Rails, Django, Flyway,
  etc. recomiendan lo mismo: la migración declara estructura y permisos,
  nunca contraseñas).

---

## 4. Test de integración Rust

Ubicación propuesta: `tests/audit_log_permissions.rs` (o una función dentro
de `tests/repository.rs` si la feature 4 agrupa ahí todos los tests de
integración de `repository` — decisión del `implementer`, `docs/conventions.md`
solo pide "un archivo por módulo que cruza un límite de IO real"). Usa la
API real de `testcontainers` 0.20.1 tal como está fijada en `Cargo.lock`;
`rand` no es dependencia hoy (`Cargo.toml`/`Cargo.lock` no lo tienen) así
que habría que añadirlo como `dev-dependency`, o generar la contraseña
efímera con algo ya disponible en `std` (p. ej. combinar
`std::time::SystemTime::now()` + el PID del proceso) si se prefiere no
añadir una dependencia nueva solo para esto — lo documento como decisión
abierta para el `implementer`.

```rust
//! tests/audit_log_permissions.rs
//!
//! Verifica, contra un Postgres real (testcontainers), que el rol de
//! aplicación `ms_usuarios_app` puede SELECT/INSERT sobre `audit_log` pero
//! que un UPDATE/DELETE directo falla por permisos (SQLSTATE 42501), nunca
//! por lógica de aplicación ni con un panic. Ver
//! progress/explore_audit_log_permissions.md para el diseño completo.

use sqlx::postgres::{PgPoolOptions, PgQueryResult};
use sqlx::Error as SqlxError;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const POSTGRES_IMAGE_TAG: &str = "16.4-alpine3.20"; // fijar por tag concreto, no "latest"
const POSTGRES_DB: &str = "db_usuarios_test";
const SUPERUSER: &str = "postgres";
const SUPERUSER_PASSWORD: &str = "postgres"; // solo dentro del contenedor efímero

#[tokio::test]
#[ignore = "requiere Docker"]
async fn update_and_delete_against_audit_log_fail_by_permissions() {
    let container = GenericImage::new("postgres", POSTGRES_IMAGE_TAG)
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", SUPERUSER)
        .with_env_var("POSTGRES_PASSWORD", SUPERUSER_PASSWORD)
        .with_env_var("POSTGRES_DB", POSTGRES_DB)
        .start()
        .await
        .expect("el contenedor postgres debe arrancar");

    let host_port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("el puerto 5432 del contenedor debe estar mapeado");

    let superuser_url = format!(
        "postgres://{SUPERUSER}:{SUPERUSER_PASSWORD}@127.0.0.1:{host_port}/{POSTGRES_DB}"
    );
    let superuser_pool = PgPoolOptions::new()
        .connect(&superuser_url)
        .await
        .expect("el pool de superusuario debe conectar");

    // Aplica exactamente las migraciones versionadas de migrations/,
    // igual que correría el proceso migrador real (nunca el rol de
    // aplicación, ver sección 1 de la investigación).
    sqlx::migrate!("./migrations")
        .run(&superuser_pool)
        .await
        .expect("las migraciones deben aplicarse limpiamente sobre un contenedor nuevo");

    // El rol ms_usuarios_app existe pero está en NOLOGIN (creado por la
    // migración de permisos). Activamos su login solo para este test, con
    // una contraseña generada en el propio proceso de test — nunca
    // hardcodeada en un .sql versionado (ver sección 3).
    let app_password = generate_ephemeral_password();
    sqlx::query(&format!(
        "ALTER ROLE ms_usuarios_app LOGIN PASSWORD '{app_password}'"
    ))
    .execute(&superuser_pool)
    .await
    .expect("debe poder activarse el login del rol de aplicación para el test");

    // Fixtures: un usuario y una entrada de auditoría reales, insertados
    // con el pool de superusuario (dueño de las tablas).
    sqlx::query("INSERT INTO users (user_id, email, display_name) VALUES ($1, $2, $3)")
        .bind("test-user-1")
        .bind("test-user-1@example.test")
        .bind("Test User")
        .execute(&superuser_pool)
        .await
        .expect("el fixture de usuario debe insertarse");

    sqlx::query(
        "INSERT INTO audit_log (id, user_id, target, action) VALUES ($1, $2, $3, $4)",
    )
    .bind("audit-1")
    .bind("test-user-1")
    .bind("192.0.2.10")
    .bind("scan_requested")
    .execute(&superuser_pool)
    .await
    .expect("el fixture de auditoría debe insertarse");

    // Pool de aplicación: el mismo rol con el que corre ms-usuarios en
    // producción, con solo los grants de la migración de permisos.
    let app_url = format!(
        "postgres://ms_usuarios_app:{app_password}@127.0.0.1:{host_port}/{POSTGRES_DB}"
    );
    let app_pool = PgPoolOptions::new()
        .connect(&app_url)
        .await
        .expect("el rol de aplicación debe poder conectarse tras activar su login");

    let update_result: Result<PgQueryResult, SqlxError> =
        sqlx::query("UPDATE audit_log SET action = $1 WHERE id = $2")
            .bind("tampered")
            .bind("audit-1")
            .execute(&app_pool)
            .await;
    assert_fails_with_permission_denied(update_result, "UPDATE");

    let delete_result: Result<PgQueryResult, SqlxError> =
        sqlx::query("DELETE FROM audit_log WHERE id = $1")
            .bind("audit-1")
            .execute(&app_pool)
            .await;
    assert_fails_with_permission_denied(delete_result, "DELETE");

    // Control positivo: con el MISMO rol y el MISMO pool, SELECT/INSERT sí
    // deben funcionar (si esto fallara, el test anterior podría estar
    // "pasando" por una razón equivocada, p. ej. credenciales rotas).
    let select_result = sqlx::query("SELECT id FROM audit_log WHERE id = $1")
        .bind("audit-1")
        .fetch_optional(&app_pool)
        .await
        .expect("SELECT debe seguir permitido para ms_usuarios_app");
    assert!(
        select_result.is_some(),
        "la fila de auditoría debe seguir intacta: ni el UPDATE ni el DELETE debieron aplicarse"
    );
}

/// Verifica que `result` es un error de base de datos con SQLSTATE `42501`
/// (`insufficient_privilege`) — nunca `Ok`, nunca otra variante de
/// `sqlx::Error` (lo que indicaría que el fallo fue por otra razón, p. ej.
/// un typo en el SQL, y el test estaría dando un falso positivo).
fn assert_fails_with_permission_denied(result: Result<PgQueryResult, SqlxError>, op: &str) {
    match result {
        Ok(_) => panic!(
            "{op} contra audit_log con el rol de aplicación tuvo éxito; \
             se esperaba que la base de datos lo rechazara por permisos"
        ),
        Err(SqlxError::Database(db_err)) => {
            assert_eq!(
                db_err.code().as_deref(),
                Some("42501"),
                "{op} contra audit_log falló, pero no por 'insufficient_privilege' \
                 (SQLSTATE 42501) sino: {db_err}"
            );
        }
        Err(other) => panic!(
            "{op} contra audit_log debía fallar con sqlx::Error::Database(..), \
             no con {other:?}"
        ),
    }
}

fn generate_ephemeral_password() -> String {
    // Contraseña de un rol NOLOGIN activado solo dentro de un contenedor
    // Docker efímero, accesible únicamente desde 127.0.0.1 en un puerto
    // aleatorio mientras dura este test — nunca una credencial real. Se
    // genera en Rust (no se hardcodea en un .sql versionado) para que la
    // migración de permisos sea reproducible sin acoplarse a ningún valor
    // fijo. Si se prefiere no añadir `rand` como dev-dependency, alcanza
    // con derivar algo no adivinable a partir de SystemTime + PID.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("el reloj del sistema debe ser posterior a UNIX_EPOCH")
        .as_nanos();
    format!("testpw{nanos}{}", std::process::id())
}
```

Notas sobre este test:

- El nombre de la función sigue la convención de `docs/conventions.md`
  (`<qué_prueba>_<condición>`).
- `#[ignore = "requiere Docker"]` como pide `docs/conventions.md` y
  `docs/verification.md` — corre con `cargo test -- --ignored`, no con
  `cargo test` a secas.
- Nunca usa `.unwrap()` sobre el resultado del `UPDATE`/`DELETE` en sí (eso
  sería un panic si la DB rechaza la operación, que es exactamente el
  camino feliz de este test) — solo hace `match`/`assert_eq!` explícitos,
  cumpliendo el punto 4 del encargo ("falla con un error de permisos, no
  con un panic").
- La sintaxis exacta de `GenericImage`/`AsyncRunner`/`with_wait_for` es la
  de `testcontainers` 0.20.x tal como está fijado en `Cargo.lock`
  (0.20.1); no se verificó compilando (esta es una investigación del
  `leader`, no una implementación — corresponde al `implementer` ajustarla
  si la firma exacta difiere al escribir el código real).

---

## Preguntas abiertas para quien implemente la feature 4

1. ¿Cómo expone `src/config.rs` la distinción entre "URL de migraciones
   (dueño)" y "URL de aplicación (`ms_usuarios_app`)"? Hoy `Config` solo
   tiene `database_url`. Ver sección 1, pitfall del dueño de tabla.
2. ¿El nombre del rol de aplicación (`ms_usuarios_app` en este documento)
   debe ser configurable vía env var, o es una constante del esquema? Lo
   traté como constante del esquema (vive en las migraciones, no en
   `Config`) porque es un detalle de infraestructura de base de datos, no
   una credencial en sí.
3. Si `service_wiring` (feature 7) ejecuta `sqlx::migrate!` al arrancar el
   proceso en producción, ¿con qué rol lo hace? Si el proceso de producción
   solo tiene la credencial de `ms_usuarios_app` (sin privilegios de dueño),
   **no podría** aplicar sus propias migraciones — habría que decidir si
   las migraciones de producción se aplican con un paso de despliegue
   separado (fuera del binario) en vez de con `sqlx::migrate!` embebido en
   `wiring.rs`. Señalado aquí porque afecta directamente el diseño de la
   feature 4 actual.
