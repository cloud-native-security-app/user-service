# Alcance de seguridad y autorización

> `user-service` (`ms-usuarios`) maneja datos personales reales (identidad de
> Google de cada usuario) y es la fuente de verdad de auditoría de seguridad
> de la plataforma (RF-15). Este documento define los límites duros que
> aplican tanto al desarrollo (tests, ejemplos, datos de prueba) como al
> diseño del propio servicio. No es un documento legal — es la guía práctica
> que un agente de código debe seguir antes de tocar identidad de usuario,
> el log de auditoría o la comunicación con el Gateway.

## Autenticación: qué SÍ y qué NO hace este repo

- `ms-usuarios` **no** implementa el handshake OAuth 2.0 / OIDC contra
  Google, ni valida firma/`exp`/`aud`/`iss` de ningún token de usuario final
  — eso es responsabilidad del Gateway (RF-01, RNF-02). Si una feature
  pareciera requerir eso, **para y pregunta al usuario**: probablemente el
  alcance real es otro repo.
- Lo que este repo sí recibe es la identidad **ya verificada** que el
  Gateway reenvía en cada petición (p. ej. `sub`/`email` de Google). Todo
  handler de `api` la trata como el único origen de verdad de "quién hace
  esta petición" — nunca se confía en un `user_id` que venga solo en el
  cuerpo/query de la petición sin contrastarlo contra esa identidad.
- **La llamada Gateway→ms-usuarios en sí misma se autentica** con una
  credencial de servicio (p. ej. un secreto compartido en un header,
  configurado vía variable de entorno — ver `src/config.rs`), no con el
  token de usuario final. Este servicio corre en subred privada (RNF-03) y
  nunca se expone directamente a internet: ninguna feature debe añadir un
  listener público ni CORS abierto a orígenes fuera del Gateway.

## Datos personales

- Los identificadores de Google (`sub`, `email`, nombre) son datos
  personales. **Nunca** se escriben en logs (`tracing`), nunca en mensajes
  de error, nunca se incluyen en un panic message.
- La configuración (`src/config.rs`) lee la credencial de servicio
  Gateway↔ms-usuarios desde una variable de entorno — nunca hardcodeada en
  el repo.
- Ningún test, fixture o ejemplo de este repo usa una identidad de Google
  real: se generan valores sintéticos de laboratorio (p. ej.
  `test-user-<n>@example.test`).

## Autorización a nivel de fila

- Un usuario autenticado solo puede leer/escribir su **propio** perfil, su
  propio histórico de escaneos y sus propias entradas de auditoría. Todo
  handler que reciba un identificador en la URL (`/users/{id}/...`) debe
  verificar que coincide con la identidad reenviada por el Gateway antes de
  tocar la base de datos — un `id` que no coincide es `403`, no un query que
  "por suerte" no encuentra nada.
- Este repo **no** decide si un usuario está autorizado a escanear una IP o
  rango concreto (allowlist de red, permisos de negocio) salvo que una
  feature futura lo pida explícitamente y se documente en
  `feature_list.json` — no se improvisa como efecto secundario de otra
  feature.

## Log de auditoría (RF-15): inmutabilidad

- Cada entrada de auditoría (`quién`, `qué IP objetivo`, `cuándo`) se
  **inserta**, nunca se actualiza ni se borra. El rol de base de datos que
  usa el servicio en producción tiene grant de `INSERT`/`SELECT` sobre la
  tabla de auditoría **y nada más** — ni siquiera el propio código de la
  aplicación puede mutarla, aunque quisiera.
- Un error al escribir la entrada de auditoría se trata como un fallo real
  (se loggea y se propaga como error de la petición) — nunca se descarta en
  silencio "porque la operación principal ya se completó". La trazabilidad
  no es opcional.
- Si en el futuro se necesita "corregir" una entrada errónea, la solución es
  una entrada nueva que referencia a la anterior, nunca editar la existente.

## Comunicación y transporte

- Toda comunicación hacia este servicio viaja sobre la subred privada
  (RNF-03); no se asume ni se documenta un certificado TLS terminado por
  este propio servicio — eso vive en la capa de red/Gateway, salvo que el
  usuario decida lo contrario explícitamente.
- El rate limiting de solicitudes de un mismo usuario (RF-12) es
  responsabilidad del Gateway/API Manager, no de este repo.

## Si algo no está claro

Si una feature de `feature_list.json` roza alguno de estos límites y no está
claro cómo proceder, el agente **para y pregunta al usuario** en vez de
asumir qué está autorizado — igual que cualquier otro bloqueo, se documenta
en `progress/current.md`.
