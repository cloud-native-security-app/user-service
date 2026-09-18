# Review — feature 8 (containerization)

**Veredicto:** APPROVED

## Verificación realizada de primera mano (no solo lo reportado por el implementer)

- `./init.sh` re-ejecutado en este entorno: `[OK]` en todos los bloques —
  `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` sin
  warnings, `cargo test` (13 tests `api.rs` + 13 `repository.rs` + 2
  `service_wiring.rs` + unitarios, todos verdes; los marcados
  `#[ignore = "requiere Docker"]` corren en el segundo pase contra
  testcontainers reales), `cargo doc --no-deps` sin errores.
- `docker build -t user-service-review:local .` (nombre propio, distinto
  del `user-service:local` que usó el implementer) desde la raíz del repo:
  build exitoso, imagen final de **11.9MB** de contenido.
- `docker history user-service-review:local`: la única capa añadida sobre
  la base `distroless/cc-debian12:nonroot` es `COPY .../user_service`
  (5.9MB) + `LABEL` + `USER nonroot` + `ENTRYPOINT` — ninguna capa de
  toolchain/código fuente/`Cargo.lock` en el stage final (confirma que el
  stage `builder` se descarta correctamente).
- `docker run --rm --entrypoint /bin/sh user-service-review:local -c "echo hola"`
  → falla con `exec: "/bin/sh": stat /bin/sh: no such file or directory`,
  exit 127. Confirmado independientemente: no hay shell.
- `docker run --rm --entrypoint whoami ...` → `executable file not found`
  (tampoco hay coreutils). `docker inspect --format '{{json .Config.User}}'`
  → `"nonroot"`, confirmando `USER nonroot` antes del `ENTRYPOINT`.
- Probé además `docker run` del binario real sin `DATABASE_URL` configurada
  → el proceso termina con un log `ERROR` tipado (`falta la variable de
  entorno requerida: DATABASE_URL`) y exit limpio, **no** un panic ni un
  crash silencioso — coherente con `docs/conventions.md` §"Manejo de
  errores" y el acceptance de la feature 2.
- Verificación end-to-end real que yo mismo levanté: `docker network create
  review-net`, `postgres:16-alpine` como `review-pg`, y el contenedor de la
  imagen bajo revisión (`review-svc`) con las 4 env vars requeridas
  apuntando al Postgres de prueba (omití `MIGRATIONS_DATABASE_URL` a
  propósito para confirmar el fallback documentado). Resultado:
  - `curl -i http://127.0.0.1:18081/health` → `HTTP/1.1 200 OK`.
  - `docker exec review-pg psql -U postgres -d usuarios -c "\dt"` → tablas
    `users`, `scan_history`, `audit_log`, `_sqlx_migrations` creadas por las
    migraciones aplicadas al arrancar (embebidas en el binario, no copiadas
    aparte, confirmado también leyendo `src/wiring.rs:80` —
    `sqlx::migrate!("./migrations")`).
  - `docker exec review-pg psql -U postgres -d usuarios -c "\du"` → rol
    `ms_usuarios_app` creado por la migración de endurecimiento de
    `audit_log` (feature 4, ya aprobada), consistente con lo que documenta
    el README sobre la separación de roles.
  - Limpieza propia al terminar: `docker rm -f review-svc review-pg &&
    docker network rm review-net && docker rmi user-service-review:local`.
    Confirmado con `docker ps -a` / `docker images` que no queda ningún
    recurso huérfano de esta revisión (los contenedores `mongo`/`hannah-coffee`
    restantes son de sesiones ajenas no relacionadas con este repo).

## Revisión de archivos contra `docs/architecture.md` / `docs/conventions.md`

- **`Dockerfile`**: multi-stage `builder` (`rust:1.98-bookworm@sha256:...`)
  + `runtime` (`gcr.io/distroless/cc-debian12:nonroot@sha256:...`), ambas
  imágenes base fijadas por tag **y** por digest de 64 hex chars (verificado
  con `python3 -c "len(...)"` → 64 en ambos casos), nunca `latest`. El stage
  final (líneas 52-62) solo hace `COPY --from=builder .../user_service` y
  `USER nonroot` antes del `ENTRYPOINT` — no copia `Cargo.toml`/`Cargo.lock`,
  `src/`, ni la toolchain. Los certificados CA no se copian explícitamente
  porque ya vienen en `distroless/cc-debian12` (confirmado por el comentario
  del propio Dockerfile y por la naturaleza de la imagen base, que es el
  patrón estándar de `distroless/cc`). `migrations/` sí se copia en el stage
  `builder` (línea 41) porque `sqlx::migrate!("./migrations")` la necesita
  **en tiempo de compilación** para embeberla en el binario — confirmado
  leyendo `src/wiring.rs:80` — pero correctamente **no** se copia al stage
  final, que es lo que exige el acceptance. Mismo patrón estructural que
  `nmap-service/Dockerfile` (comparado línea a línea), sin el stage extra de
  `exploitdb` que no aplica aquí.
- **`.dockerignore`**: excluye `target/`, `.git/`, `.claude/`, `progress/`,
  `docs/` (y además `tests/`, `*.md`, `Dockerfile`, `.dockerignore`), sin
  excluir `Cargo.toml`/`Cargo.lock`/`src/`/`migrations/`, que sí hacen falta
  para el build. Cumple y excede el mínimo pedido.
- **`README.md` §"Despliegue (Docker)"**: documenta las 5 env vars en una
  tabla (`DATABASE_URL`, `HTTP_HOST`, `HTTP_PORT`, `GATEWAY_SHARED_SECRET`
  requeridas; `MIGRATIONS_DATABASE_URL` opcional) con una explicación clara
  de por qué existe la opcional (separar el rol dueño de las tablas, que
  puede saltarse el `REVOKE` de `audit_log` por ser su dueño, del rol
  `ms_usuarios_app` que sirve tráfico real) — coherente con
  `docs/security-scope.md` §"Log de auditoría". Incluye ejemplos
  funcionales de `docker build` y `docker run` (los reproduje yo mismo con
  variantes propias y funcionaron).
- **`docs/architecture.md` §"Despliegue"**: actualizado (antes hablaba en
  futuro de un Dockerfile que "se empaquetará"; ahora describe el estado
  real) explicando qué incluye la imagen final (binario + certificados CA
  del sistema) y qué NO incluye (toolchain, código fuente, shell/coreutils),
  y por qué no se copian las migraciones aparte. Consistente con lo que
  verifiqué en el Dockerfile real.
- **`Cargo.toml`**: `name = "user_service"`, sin `[[bin]]` explícito → el
  binario resultante se llama `user_service`, coincide con
  `cargo build --release --bin user_service` del Dockerfile y con
  `ENTRYPOINT ["/usr/local/bin/user_service"]`.
- Sin fuga de datos personales ni credenciales: el `Dockerfile` no
  hardcodea ningún valor de configuración (todas las env vars se inyectan en
  `docker run`, consistente con `docs/security-scope.md` §"Datos
  personales"); el mensaje de error que observé al correr sin
  `DATABASE_URL` no incluye ninguna cadena de conexión ni credencial.

## Checkpoints

- C1: [x] — `./init.sh` exit 0, los 4 archivos base y los 4 docs existen.
- C2: [x] — solo la feature 8 está `in_progress` en `feature_list.json`;
  todas las anteriores (`done`) tienen tests que pasan; `progress/current.md`
  describe la sesión activa sin basura de sesiones anteriores.
- C3: [x] — esta feature no toca `src/`; no introduce módulos nuevos ni
  dependencias en `Cargo.toml`; no hay `println!`/`dbg!`/`unwrap()` nuevos
  (no se tocó código Rust); `cargo doc --no-deps` sin warnings.
- C4: [x] — no aplica cambio a tests de esta feature (es infraestructura),
  pero los tests de integración existentes (`repository`, `api`,
  `service_wiring`) siguen corriendo verdes contra testcontainers reales, y
  yo mismo levanté un Postgres real adicional fuera de testcontainers para
  validar el binario empaquetado end-to-end. `cargo test` > 0 tests, todos
  verdes; `cargo clippy --all-targets -- -D warnings` sin advertencias.
- C5: [x] — `git status` solo muestra los archivos esperados
  (`Dockerfile`, `.dockerignore` nuevos; `README.md`, `docs/architecture.md`,
  `feature_list.json`, `progress/current.md` modificados); nada de
  `target/` ni temporales sin trackear.

## Cambios requeridos (si aplica)

Ninguno. La feature cumple todos los puntos del acceptance de
`feature_list.json` (id 8) y la verificación con Docker real que hice de
forma independiente reproduce los mismos resultados que reportó el
implementer en `progress/current.md` (build exitoso, ausencia de shell,
`GET /health` → 200 contra un Postgres real).
