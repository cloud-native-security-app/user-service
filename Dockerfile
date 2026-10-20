# syntax=docker/dockerfile:1
#
# Imagen de producción de ms-usuarios (feature 8: containerization).
#
# Multi-stage:
#   - builder: toolchain Rust completa, compila el binario `user_service` en
#     release.
#   - runtime: distroless/cc (glibc + certificados CA + usuario `nonroot`),
#     contiene únicamente el binario `user_service`. Sin toolchain, sin
#     código fuente, sin shell/coreutils. Las migraciones de `migrations/`
#     quedan embebidas en el binario en tiempo de compilación vía
#     `sqlx::migrate!("./migrations")` (ver `src/wiring.rs`), así que no
#     hace falta copiarlas a la imagen final por separado.
#
# Las imágenes base se fijan por tag concreto Y por digest (`@sha256:...`) para
# builds reproducibles. Al actualizar una base, refresca el digest con
# `docker buildx imagetools inspect <imagen:tag>`.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder

WORKDIR /app

# 1) Cachea la compilación de dependencias: con solo Cargo.toml/Cargo.lock y un
#    árbol de fuentes mínimo, `cargo build --release` compila todas las deps.
#    Mientras Cargo.toml/Cargo.lock no cambien, esta capa se reutiliza aunque
#    cambie `src/`.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo '//! placeholder para cachear dependencias' > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# 2) Copia el código real (incluidas las migraciones, que `sqlx::migrate!`
#    embebe en el binario en tiempo de compilación) y compila el binario.
#    Solo se recompila el crate propio, no las dependencias ya cacheadas.
COPY src ./src
COPY migrations ./migrations
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --bin user_service \
    && strip target/release/user_service

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
# distroless/cc-debian12: glibc + libgcc (para el binario Rust), paquete
# ca-certificates (TLS a Postgres vía rustls) y el usuario no-root `nonroot`
# (uid 65532). No trae shell ni gestor de paquetes.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

LABEL org.opencontainers.image.title="ms-usuarios" \
      org.opencontainers.image.description="Microservicio de identidad, histórico de escaneos y auditoría de la plataforma blue/red team" \
      org.opencontainers.image.source="https://github.com/o-aguirre/user-service"

COPY --from=builder /app/target/release/user_service /usr/local/bin/user_service

USER nonroot

ENTRYPOINT ["/usr/local/bin/user_service"]
