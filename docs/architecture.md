# Arquitectura — Qué significa "hacer un buen trabajo"

> Este documento define el estándar de calidad. Los agentes revisores
> evalúan código contra este archivo. Si no está aquí, no es un requisito.

## Alcance de este repo

Este repo implementa **únicamente `ms-usuarios`**: mantiene el perfil de cada
usuario autenticado, el histórico de escaneos que ha solicitado (RF-13) y el
registro inmutable de auditoría de quién solicitó qué escaneo y cuándo
(RF-15). `ms-nmap`, `ms-analisis` (el agente IA que redacta el informe), el
Gateway y el Broker son otros servicios — no se implementan aquí.

Del diagrama de arquitectura del sistema
(`Diagrama_Arquitectura_Solucion_Cloud_Native_I-Página-2`): el navegador habla
con el Gateway (subred pública); el Gateway habla con el Identity Provider
(Google OAuth 2.0 / OIDC, RF-01) y, en subred privada, con `ms-usuarios`
directamente — **`ms-usuarios` no pasa por el Broker**, a diferencia de
`ms-nmap`/`ms-analisis`. Tiene su propia base de datos (`db-usuarios`, subred
privada, patrón database-per-service de RNF-05).

```
Browser ──▶ Gateway ──▶ Identity Provider (Google OAuth2/OIDC, RF-01)
              │
              └──(HTTP síncrono, subred privada)──▶ ms-usuarios ──▶ db-usuarios
```

## Decisiones de diseño ya tomadas

- **`ms-usuarios` no valida el token OAuth/OIDC.** Esa validación (firma,
  `exp`, `aud`, `iss`) es responsabilidad del Gateway (RNF-02). Lo que
  `ms-usuarios` recibe en cada petición es la identidad **ya verificada**
  (p. ej. `sub`/`email` de Google) que el Gateway reenvía — nunca el token
  crudo del usuario final. Ver `docs/security-scope.md` para cómo se
  autentica la llamada Gateway→ms-usuarios en sí misma.
- **Persistencia en PostgreSQL** vía el driver async `sqlx`, con migraciones
  versionadas (`sqlx migrate`). A diferencia de `ms-nmap` (documentos de
  forma variable, MongoDB), los datos de este servicio son relacionales por
  naturaleza: un usuario tiene N entradas de histórico de escaneo, y el log
  de auditoría es una tabla append-only con integridad referencial hacia el
  usuario que originó cada entrada.
- **API HTTP síncrona con `axum`**, consumida **únicamente** por el Gateway
  desde la subred privada — nunca expuesta directamente a internet (RNF-03).
  Se eligió `axum` por ser nativo del ecosistema `tokio` ya usado en
  `broker`/`nmap-service`, evitando introducir un segundo runtime async.
- **`src/lib.rs` + `src/main.rs` delgado**, mismo patrón que `nmap-service`:
  los tests de integración en `tests/` compilan como un crate externo, así
  que los módulos que necesiten test de integración (`repository`, `api`)
  deben ser `pub` en `src/lib.rs`.
- **El log de auditoría es inmutable por diseño, no solo por convención.**
  El rol de base de datos que usa `ms-usuarios` en producción solo tiene
  grant de `INSERT`/`SELECT` sobre la tabla de auditoría — ni `UPDATE` ni
  `DELETE` — reforzado con un test de integración que intenta mutar una fila
  y espera que la base de datos lo rechace. Ver `docs/security-scope.md`.
- **Autorización a nivel de fila:** un usuario solo puede leer su propio
  perfil, su propio histórico y sus propias entradas de auditoría —
  identificado por la identidad que reenvía el Gateway, nunca por un `id`
  arbitrario en la URL sin verificar que coincide con el llamante.
- **Sin mensajería asíncrona.** Si en el futuro se necesita que `ms-usuarios`
  publique o consuma eventos del Broker, es una decisión de producto que se
  discute y documenta como feature nueva — no se asume aquí (mismo principio
  que documenta `broker/docs/architecture.md`).

## Capas

1. **`config`** — carga de configuración desde variables de entorno (URL de
   Postgres, dirección/puerto de bind HTTP, credencial compartida
   Gateway↔ms-usuarios). Sin valores hardcodeados.
2. **`domain`** — tipos puros: `UserProfile`, `ScanHistoryEntry` (estado
   `PENDIENTE`/`EN_PROGRESO`/`COMPLETADO`/`FALLIDO`), `AuditEntry`. Sin IO.
3. **`repository`** — persistencia en PostgreSQL vía `sqlx`: perfiles,
   histórico de escaneos y auditoría (solo inserción). Migraciones
   versionadas en `migrations/`.
4. **`audit`** — helper de escritura del log de auditoría (append-only),
   invocado desde `api` en cada operación que lo requiera (RF-15); no expone
   ninguna forma de mutar o borrar una entrada ya escrita.
5. **`api`** — handlers y router `axum`: perfil de usuario, histórico de
   escaneos, consulta de auditoría. Cada handler exige la identidad
   reenviada por el Gateway y la usa para autorizar el acceso a nivel de
   fila (ver "Decisiones de diseño").
6. **`wiring`** — composition root: construye el pool de `sqlx` y demás
   adaptadores reales desde la `Config` y arma el router `axum`.
7. **`lib`** — declara `pub mod` para cada capa anterior y expone `pub async
   fn run(...)` que arma el servicio y lo pone a escuchar.
8. **`main`** — envoltorio delgado: inicializa runtime tokio, tracing y
   config, llama a `wiring` y a `lib::run(...)`. Sin lógica de negocio propia.

No introducir capas adicionales hasta que haya una razón concreta
documentada en `feature_list.json`.

## Manejo de errores

- Cada capa (`repository`, `api`) define su propio tipo de error con
  variantes específicas (`thiserror`, no un `String` genérico ni `Box<dyn
  Error>` como tipo de retorno de la API pública).
- Un fallo de `repository` se traduce en una respuesta HTTP de error
  apropiada (4xx/5xx) — nunca en un panic ni en un proceso que muere en
  silencio.
- Los datos personales (email, nombre) y cualquier credencial de sesión
  nunca aparecen en logs ni en cuerpos de error (ver `docs/security-scope.md`).

## Despliegue

> Detalle práctico (variables de entorno exactas, ejemplo de `docker run`)
> vive en `README.md` §"Despliegue" una vez exista el `Dockerfile` (feature
> `containerization`) — esta sección explica el *por qué*, no lo duplica.

El servicio se empaquetará con un `Dockerfile` multi-stage (stage builder con
la toolchain Rust, stage runtime mínimo tipo distroless, usuario no-root),
mismo patrón que `nmap-service`. No se asume todavía un proveedor cloud
concreto para `db-usuarios` ni para el propio servicio — se documenta en
términos genéricos hasta que el usuario decida una plataforma de despliegue,
mismo principio que documenta `broker/docs/architecture.md` §"Por qué no se
asume un proveedor cloud".

## Qué NO hacer

- No reimplementar la validación del token OAuth/OIDC (responsabilidad del
  Gateway).
- No exponer este servicio directamente a internet — solo el Gateway le
  habla, desde la subred privada.
- No permitir `UPDATE`/`DELETE` sobre el log de auditoría bajo ninguna
  circunstancia, ni siquiera para "corregir un dato erróneo" — se corrige
  con una entrada nueva, nunca mutando la anterior.
- No devolver el perfil, histórico o auditoría de un usuario a otro usuario
  distinto del autenticado.
