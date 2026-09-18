//! Carga de configuración del servicio desde variables de entorno.
//!
//! Toda la configuración de `ms-usuarios` (URL de conexión a Postgres,
//! host/puerto de bind del servidor HTTP y la credencial de servicio que
//! autentica al Gateway como llamante, ver `docs/security-scope.md`) se lee
//! exclusivamente de variables de entorno — ningún valor queda hardcodeado
//! en el código. [`Config::from_env`] nunca hace `panic!`: cualquier
//! variable ausente o inválida se traduce en un [`ConfigError`] tipado.

use std::fmt;

use secrecy::SecretString;

/// Nombre de la variable de entorno con la URL de conexión a PostgreSQL.
const DATABASE_URL_VAR: &str = "DATABASE_URL";

/// Nombre de la variable de entorno con el host de bind del servidor HTTP.
const HTTP_HOST_VAR: &str = "HTTP_HOST";

/// Nombre de la variable de entorno con el puerto de bind del servidor HTTP.
const HTTP_PORT_VAR: &str = "HTTP_PORT";

/// Nombre de la variable de entorno con la credencial compartida que
/// autentica la llamada Gateway→`ms-usuarios` (ver `docs/security-scope.md`).
const GATEWAY_SHARED_SECRET_VAR: &str = "GATEWAY_SHARED_SECRET";

/// Configuración del servicio `ms-usuarios`, cargada desde variables de
/// entorno mediante [`Config::from_env`].
///
/// El campo `gateway_shared_secret` usa [`SecretString`] para que su
/// contenido nunca aparezca en texto plano al formatearlo con `{:?}` (p. ej.
/// vía `tracing::debug!`/`tracing::error!`) ni en un mensaje de panic —
/// requisito de `docs/security-scope.md`.
pub struct Config {
    /// URL de conexión a la base de datos PostgreSQL (`db-usuarios`).
    pub database_url: String,
    /// Host en el que el servidor HTTP debe hacer bind (p. ej. `0.0.0.0`).
    pub http_host: String,
    /// Puerto en el que el servidor HTTP debe hacer bind.
    pub http_port: u16,
    /// Credencial compartida que autentica al Gateway como llamante de este
    /// servicio (ver `docs/security-scope.md`). Redactada en `Debug`.
    pub gateway_shared_secret: SecretString,
}

impl fmt::Debug for Config {
    /// Implementación manual para garantizar, de forma explícita y a prueba
    /// de futuros campos añadidos por descuido, que `gateway_shared_secret`
    /// nunca se imprime en texto plano — `SecretString` ya redacta su propio
    /// `Debug`, pero lo dejamos explícito aquí como salvaguarda documentada.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &self.database_url)
            .field("http_host", &self.http_host)
            .field("http_port", &self.http_port)
            .field("gateway_shared_secret", &self.gateway_shared_secret)
            .finish()
    }
}

impl Config {
    /// Carga la configuración del servicio desde variables de entorno.
    ///
    /// Variables requeridas: `DATABASE_URL`, `HTTP_HOST`, `HTTP_PORT` y
    /// `GATEWAY_SHARED_SECRET`.
    ///
    /// # Errores
    ///
    /// Devuelve [`ConfigError::MissingVar`] si falta alguna variable
    /// requerida, o [`ConfigError::InvalidPort`] si `HTTP_PORT` no es un
    /// puerto TCP válido (`u16`). Nunca hace `panic!`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = read_required(DATABASE_URL_VAR)?;
        let http_host = read_required(HTTP_HOST_VAR)?;
        let raw_http_port = read_required(HTTP_PORT_VAR)?;
        let gateway_shared_secret = SecretString::from(read_required(GATEWAY_SHARED_SECRET_VAR)?);

        let http_port = raw_http_port
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidPort {
                variable: HTTP_PORT_VAR,
            })?;

        Ok(Config {
            database_url,
            http_host,
            http_port,
            gateway_shared_secret,
        })
    }
}

/// Lee una variable de entorno requerida, devolviendo un
/// [`ConfigError::MissingVar`] tipado (nunca un panic) si está ausente o no
/// es UTF-8 válido.
fn read_required(variable: &'static str) -> Result<String, ConfigError> {
    std::env::var(variable).map_err(|_| ConfigError::MissingVar { variable })
}

/// Error devuelto por [`Config::from_env`] cuando la configuración no puede
/// cargarse correctamente.
///
/// Ninguna variante contiene el valor de una variable de entorno: solo su
/// nombre, para no filtrar por accidente un secreto en el mensaje de error
/// (ver `docs/security-scope.md`).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Falta una variable de entorno requerida.
    #[error("falta la variable de entorno requerida: {variable}")]
    MissingVar {
        /// Nombre de la variable de entorno ausente.
        variable: &'static str,
    },
    /// El valor de una variable de entorno no tiene el formato esperado.
    #[error("la variable de entorno {variable} no contiene un puerto TCP válido")]
    InvalidPort {
        /// Nombre de la variable de entorno con el valor inválido.
        variable: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    /// Garantiza aislamiento entre tests: `std::env::set_var`/`remove_var`
    /// operan sobre el entorno global del proceso, así que los tests que
    /// tocan variables de entorno se serializan con un mutex para evitar
    /// condiciones de carrera entre hilos de test.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const SECRET_VALUE: &str = "top-secret-gateway-credential";

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set_valid_env() -> Self {
            let lock = ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Seguro: los tests de este módulo son la única fuente que muta
            // estas variables, y `ENV_MUTEX` serializa el acceso.
            unsafe {
                std::env::set_var(DATABASE_URL_VAR, "postgres://user:pass@localhost/db");
                std::env::set_var(HTTP_HOST_VAR, "0.0.0.0");
                std::env::set_var(HTTP_PORT_VAR, "8080");
                std::env::set_var(GATEWAY_SHARED_SECRET_VAR, SECRET_VALUE);
            }
            EnvGuard { _lock: lock }
        }

        fn clear_all(&self) {
            // Seguro por la misma razón que en `set_valid_env`.
            unsafe {
                std::env::remove_var(DATABASE_URL_VAR);
                std::env::remove_var(HTTP_HOST_VAR);
                std::env::remove_var(HTTP_PORT_VAR);
                std::env::remove_var(GATEWAY_SHARED_SECRET_VAR);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            self.clear_all();
        }
    }

    #[test]
    fn from_env_loads_valid_config_successfully() {
        let guard = EnvGuard::set_valid_env();

        let config = Config::from_env().expect("la configuración válida debe cargar sin error");

        assert_eq!(config.database_url, "postgres://user:pass@localhost/db");
        assert_eq!(config.http_host, "0.0.0.0");
        assert_eq!(config.http_port, 8080);
        assert_eq!(config.gateway_shared_secret.expose_secret(), SECRET_VALUE);

        drop(guard);
    }

    #[test]
    fn from_env_returns_typed_error_when_required_var_is_missing() {
        let guard = EnvGuard::set_valid_env();
        // Seguro por la misma razón que en `EnvGuard::set_valid_env`.
        unsafe {
            std::env::remove_var(GATEWAY_SHARED_SECRET_VAR);
        }

        let result = Config::from_env();

        assert!(matches!(
            result,
            Err(ConfigError::MissingVar {
                variable: GATEWAY_SHARED_SECRET_VAR
            })
        ));

        drop(guard);
    }

    #[test]
    fn from_env_returns_typed_error_when_port_is_not_a_valid_u16() {
        let guard = EnvGuard::set_valid_env();
        // Seguro por la misma razón que en `EnvGuard::set_valid_env`.
        unsafe {
            std::env::set_var(HTTP_PORT_VAR, "not-a-port");
        }

        let result = Config::from_env();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidPort {
                variable: HTTP_PORT_VAR
            })
        ));

        drop(guard);
    }

    #[test]
    fn debug_format_of_config_never_contains_the_raw_secret() {
        let guard = EnvGuard::set_valid_env();
        let config = Config::from_env().expect("la configuración válida debe cargar sin error");

        let debug_output = format!("{config:?}");

        assert!(
            !debug_output.contains(SECRET_VALUE),
            "el Debug de Config no debe filtrar la credencial de servicio"
        );

        drop(guard);
    }
}
