//! Handlers y router HTTP (`axum`) del servicio: perfil de usuario.
//!
//! Expone `PUT /users/me` (crea o actualiza el perfil del llamante) y
//! `GET /users/me` (consulta el perfil del llamante). El histórico de
//! escaneos y la consulta de auditoría (`/users/me/scans`, `/scans/{id}`,
//! `/users/me/audit`) se implementan en la feature `scan_history_api`.
//!
//! ## Autenticación de cada petición
//!
//! Ninguna ruta de este módulo valida el token OAuth/OIDC del usuario final
//! — eso es responsabilidad del Gateway (ver `docs/security-scope.md`). En
//! su lugar, cada petición debe traer dos headers, verificados por un
//! middleware interno **antes** de que un handler toque la base de datos:
//!
//! - [`GATEWAY_SECRET_HEADER`] (`X-Gateway-Secret`): la credencial de
//!   servicio compartida que autentica la llamada Gateway→`ms-usuarios` en
//!   sí misma (`Config::gateway_shared_secret`). Ausente o incorrecta →
//!   `401 Unauthorized`, comparada en tiempo constante para no filtrar el
//!   secreto por un ataque de temporización.
//! - [`FORWARDED_USER_HEADER`] (`X-Forwarded-User`): la identidad del
//!   usuario final ya verificada por el Gateway/IDaaS (p. ej. el `sub` de
//!   Google, RF-01). Es el **único** origen de verdad de `user_id` — nunca
//!   se confía en un `user_id` que venga en el cuerpo o en la query de la
//!   petición. Ausente → `400 Bad Request`.
//!
//! [`router`] construye el `Router` completo (con este middleware ya
//! aplicado) a partir de un [`Repository`] y el secreto de servicio, para
//! que tanto los tests de esta feature como la futura composition root
//! (`service_wiring`, feature 7) lo reutilicen sin duplicar el ensamblado.

use std::sync::Arc;

use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::domain::UserProfile;
use crate::repository::{RepoError, Repository};

/// Nombre del header con la credencial de servicio compartida
/// Gateway↔`ms-usuarios` (ver `docs/security-scope.md`).
pub const GATEWAY_SECRET_HEADER: &str = "X-Gateway-Secret";

/// Nombre del header con la identidad del usuario final ya verificada por
/// el Gateway/IDaaS (p. ej. el `sub` de Google, RF-01).
pub const FORWARDED_USER_HEADER: &str = "X-Forwarded-User";

/// Estado compartido por los handlers de este módulo.
///
/// Se envuelve en `Arc` porque [`Repository`] no deriva `Clone` y `axum`
/// exige que el estado del router sea `Clone` (barato: solo clona los
/// punteros compartidos, no la conexión ni el secreto).
#[derive(Clone)]
struct AppState {
    repository: Arc<Repository>,
    gateway_shared_secret: Arc<SecretString>,
}

/// Construye el router `axum` del perfil de usuario.
///
/// Aplica el middleware de autenticación (credencial de servicio + header
/// de identidad) a todas las rutas expuestas, así que ningún handler se
/// ejecuta sin una credencial de servicio válida y un header de identidad
/// presente. Este router se puede montar tal cual (o
/// anidar bajo un router mayor) desde la composition root del servicio
/// (feature `service_wiring`).
pub fn router(repository: Repository, gateway_shared_secret: SecretString) -> Router {
    let state = AppState {
        repository: Arc::new(repository),
        gateway_shared_secret: Arc::new(gateway_shared_secret),
    };

    Router::new()
        .route("/users/me", get(get_profile).put(put_profile))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_gateway_and_identity,
        ))
        .with_state(state)
}

/// Identidad del llamante, ya verificada por [`require_gateway_and_identity`]
/// e inyectada en las extensiones de la petición para que los handlers la
/// consuman vía el extractor [`Extension`].
#[derive(Clone)]
struct CallerIdentity(String);

/// Middleware que exige, en orden, la credencial de servicio y el header de
/// identidad — antes de que la petición llegue a cualquier handler y, por
/// tanto, antes de tocar la base de datos.
async fn require_gateway_and_identity(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let secret_is_valid = read_header(request.headers(), GATEWAY_SECRET_HEADER)
        .map(|provided| secrets_match(provided, &state.gateway_shared_secret))
        .unwrap_or(false);
    if !secret_is_valid {
        return ApiError::Unauthorized.into_response();
    }

    let forwarded_user =
        read_header(request.headers(), FORWARDED_USER_HEADER).map(|value| value.trim().to_string());

    match forwarded_user {
        Some(user_id) if !user_id.is_empty() => {
            request.extensions_mut().insert(CallerIdentity(user_id));
            next.run(request).await
        }
        _ => ApiError::MissingIdentity.into_response(),
    }
}

/// Lee un header como texto UTF-8, devolviendo `None` si está ausente o no
/// es UTF-8 válido (nunca hace `panic!`).
fn read_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// Compara `provided` contra el secreto de servicio configurado en tiempo
/// constante (`subtle::ConstantTimeEq`), para no filtrar por temporización
/// cuánto de la credencial coincide. Una diferencia de longitud se rechaza
/// de inmediato (no hay nada sensible que comparar byte a byte en ese caso)
/// antes de invocar la comparación de tiempo constante.
fn secrets_match(provided: &str, expected: &SecretString) -> bool {
    let expected_bytes = expected.expose_secret().as_bytes();
    let provided_bytes = provided.as_bytes();
    if expected_bytes.len() != provided_bytes.len() {
        return false;
    }
    expected_bytes.ct_eq(provided_bytes).into()
}

/// Cuerpo de la petición `PUT /users/me`.
///
/// Deliberadamente no incluye `user_id`: la identidad del perfil upserteado
/// es siempre la del header [`FORWARDED_USER_HEADER`], nunca un valor que
/// el llamante pudiera pasar en el cuerpo.
#[derive(Debug, Deserialize)]
struct UpsertProfileRequest {
    email: String,
    display_name: String,
}

/// `PUT /users/me` — crea el perfil del llamante si no existe, o actualiza
/// `email`/`display_name` si ya existía.
async fn put_profile(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
    Json(payload): Json<UpsertProfileRequest>,
) -> Result<Json<UserProfile>, ApiError> {
    let profile = UserProfile {
        user_id: identity.0,
        email: payload.email,
        display_name: payload.display_name,
        created_at: Utc::now(),
    };

    state
        .repository
        .upsert_user(&profile)
        .await
        .map_err(ApiError::from)?;

    let stored = state
        .repository
        .find_user(&profile.user_id)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::Internal)?;

    Ok(Json(stored))
}

/// `GET /users/me` — devuelve el perfil del llamante.
///
/// Un llamante sin perfil todavía creado recibe `404 Not Found`.
async fn get_profile(
    State(state): State<AppState>,
    Extension(identity): Extension<CallerIdentity>,
) -> Result<Json<UserProfile>, ApiError> {
    let profile = state
        .repository
        .find_user(&identity.0)
        .await
        .map_err(ApiError::from)?;

    profile.map(Json).ok_or(ApiError::NotFound)
}

/// Error de la API HTTP de este módulo.
///
/// Ninguna variante ni su `Display` incluyen el `user_id`, el email o el
/// nombre del llamante (ver `docs/security-scope.md`) — solo un mensaje
/// genérico apto para devolverse tal cual en el cuerpo de la respuesta.
#[derive(Debug, thiserror::Error)]
enum ApiError {
    /// Falta o es inválida la credencial de servicio Gateway↔`ms-usuarios`.
    #[error("falta o es inválida la credencial de servicio")]
    Unauthorized,
    /// Falta el header de identidad reenviado por el Gateway.
    #[error("falta el header de identidad del llamante")]
    MissingIdentity,
    /// El perfil solicitado no existe.
    #[error("el perfil solicitado no existe")]
    NotFound,
    /// Fallo interno (p. ej. de `repository`) no atribuible al llamante.
    #[error("error interno del servicio")]
    Internal,
}

impl From<RepoError> for ApiError {
    /// Traduce cualquier fallo de `repository` a un error interno genérico:
    /// el mensaje de [`RepoError`] nunca llega al cuerpo de la respuesta, ya
    /// que el objetivo es no exponer detalle de infraestructura al llamante.
    fn from(_: RepoError) -> Self {
        ApiError::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::MissingIdentity => StatusCode::BAD_REQUEST,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(ApiErrorBody::from(&self))).into_response()
    }
}

/// Cuerpo JSON devuelto para cualquier [`ApiError`].
#[derive(Serialize)]
struct ApiErrorBody {
    error: String,
}

impl From<&ApiError> for ApiErrorBody {
    fn from(error: &ApiError) -> Self {
        ApiErrorBody {
            error: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn header_map(name: &'static str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn secrets_match_returns_true_only_for_an_exact_match() {
        let expected = SecretString::from("correct-secret".to_string());

        assert!(secrets_match("correct-secret", &expected));
        assert!(!secrets_match("wrong-secret", &expected));
    }

    #[test]
    fn secrets_match_rejects_a_value_of_different_length() {
        let expected = SecretString::from("correct-secret".to_string());

        assert!(!secrets_match("correct-secret-but-longer", &expected));
        assert!(!secrets_match("", &expected));
    }

    #[test]
    fn read_header_returns_none_when_the_header_is_absent() {
        let headers = HeaderMap::new();

        assert_eq!(read_header(&headers, FORWARDED_USER_HEADER), None);
    }

    #[test]
    fn read_header_returns_the_value_when_present() {
        let headers = header_map(FORWARDED_USER_HEADER, "google-oauth2|123456");

        assert_eq!(
            read_header(&headers, FORWARDED_USER_HEADER),
            Some("google-oauth2|123456")
        );
    }
}
