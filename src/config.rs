//! Carga de configuración del servicio desde variables de entorno.
//!
//! Toda la configuración de `ms-usuarios` (URL de conexión a Postgres,
//! host/puerto de bind del servidor HTTP y la credencial de servicio que
//! autentica al Gateway como llamante, ver `docs/security-scope.md`) se lee
//! exclusivamente de variables de entorno — ningún valor queda hardcodeado
//! en el código. [`Config::from_env`] nunca hace `panic!`: cualquier
//! variable ausente o inválida se traduce en un [`ConfigError`] tipado.

use std::fmt;

use secrecy::{SecretBox, SecretSlice, SecretString};

/// Nombre de la variable de entorno con la URL de conexión a PostgreSQL.
const DATABASE_URL_VAR: &str = "DATABASE_URL";

/// Nombre de la variable de entorno con el host de bind del servidor HTTP.
const HTTP_HOST_VAR: &str = "HTTP_HOST";

/// Nombre de la variable de entorno con el puerto de bind del servidor HTTP.
const HTTP_PORT_VAR: &str = "HTTP_PORT";

/// Nombre de la variable de entorno con la credencial compartida que
/// autentica la llamada Gateway→`ms-usuarios` (ver `docs/security-scope.md`).
const GATEWAY_SHARED_SECRET_VAR: &str = "GATEWAY_SHARED_SECRET";

/// Nombre de la variable de entorno, **opcional**, con la URL de conexión
/// usada exclusivamente para aplicar migraciones (ver
/// [`Config::migrations_database_url`]). Si está ausente, se usa el mismo
/// valor que `DATABASE_URL`.
const MIGRATIONS_DATABASE_URL_VAR: &str = "MIGRATIONS_DATABASE_URL";

/// Nombre de la variable de entorno con la clave de cifrado en reposo de las
/// credenciales SSH de red (`network_credentials.ssh_credentials_ref`, ver
/// `docs/security-scope.md` §"Credenciales de red"): 32 bytes codificados en
/// hex (64 caracteres). Se trata como configuración sensible del mismo
/// nivel que `GATEWAY_SHARED_SECRET` — nunca se hardcodea, nunca se loggea.
const CREDENTIALS_ENCRYPTION_KEY_VAR: &str = "CREDENTIALS_ENCRYPTION_KEY";

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
    /// URL de conexión a PostgreSQL usada exclusivamente para aplicar
    /// migraciones (`sqlx::migrate!`), con el rol "dueño" de las tablas —
    /// distinto en producción del rol de aplicación `ms_usuarios_app` que
    /// usa `database_url` para servir tráfico HTTP (ver
    /// `migrations/20260918120100_lock_audit_log_permissions.sql`: el dueño
    /// de una tabla se salta cualquier `REVOKE`, así que ese rol no debe
    /// servir tráfico en producción). Si `MIGRATIONS_DATABASE_URL` no está
    /// presente en el entorno, cae de vuelta al valor de `database_url`
    /// (para dev/test con un único rol todopoderoso).
    pub migrations_database_url: String,
    /// Clave de cifrado en reposo (AES-256-GCM) de las credenciales SSH de
    /// red por usuario/objetivo (feature `network_credentials_api`): 32
    /// bytes, leída desde `CREDENTIALS_ENCRYPTION_KEY` como hex de 64
    /// caracteres. Se usa para cifrar `ssh_credentials_ref` antes de
    /// persistirla y descifrarla solo al resolver un objetivo — nunca se
    /// loggea (redactada por [`SecretBox`] en `Debug`).
    pub credentials_encryption_key: SecretSlice<u8>,
}

impl fmt::Debug for Config {
    /// Implementación manual para garantizar, de forma explícita y a prueba
    /// de futuros campos añadidos por descuido, que `gateway_shared_secret`
    /// y `credentials_encryption_key` nunca se imprimen en texto plano —
    /// [`SecretString`]/[`SecretBox`] ya redactan su propio `Debug`, pero lo
    /// dejamos explícito aquí como salvaguarda documentada.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &self.database_url)
            .field("http_host", &self.http_host)
            .field("http_port", &self.http_port)
            .field("gateway_shared_secret", &self.gateway_shared_secret)
            .field("migrations_database_url", &self.migrations_database_url)
            .field(
                "credentials_encryption_key",
                &self.credentials_encryption_key,
            )
            .finish()
    }
}

impl Config {
    /// Carga la configuración del servicio desde variables de entorno.
    ///
    /// Variables requeridas: `DATABASE_URL`, `HTTP_HOST`, `HTTP_PORT`,
    /// `GATEWAY_SHARED_SECRET` y `CREDENTIALS_ENCRYPTION_KEY`.
    /// `MIGRATIONS_DATABASE_URL` es **opcional**: si está ausente,
    /// [`Config::migrations_database_url`] cae de vuelta al valor de
    /// `DATABASE_URL`.
    ///
    /// # Errores
    ///
    /// Devuelve [`ConfigError::MissingVar`] si falta alguna variable
    /// requerida, [`ConfigError::InvalidPort`] si `HTTP_PORT` no es un
    /// puerto TCP válido (`u16`), o [`ConfigError::InvalidEncryptionKey`]
    /// si `CREDENTIALS_ENCRYPTION_KEY` no decodifica a 32 bytes de hex.
    /// Nunca hace `panic!`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = read_required(DATABASE_URL_VAR)?;
        let http_host = read_required(HTTP_HOST_VAR)?;
        let raw_http_port = read_required(HTTP_PORT_VAR)?;
        let gateway_shared_secret = SecretString::from(read_required(GATEWAY_SHARED_SECRET_VAR)?);
        let credentials_encryption_key =
            decode_encryption_key(&read_required(CREDENTIALS_ENCRYPTION_KEY_VAR)?)?;
        let migrations_database_url =
            std::env::var(MIGRATIONS_DATABASE_URL_VAR).unwrap_or_else(|_| database_url.clone());

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
            credentials_encryption_key,
            migrations_database_url,
        })
    }
}

/// Decodifica la variable `CREDENTIALS_ENCRYPTION_KEY` (hex de 64
/// caracteres) a una [`SecretBox`] de 32 bytes.
///
/// # Errores
///
/// Devuelve [`ConfigError::InvalidEncryptionKey`] si el valor no es hex
/// válido o no decodifica exactamente a 32 bytes. Trata el valor de la
/// variable como configuración sensible: el mensaje de error solo nombra la
/// variable, nunca su contenido (ver `docs/security-scope.md`).
fn decode_encryption_key(value: &str) -> Result<SecretSlice<u8>, ConfigError> {
    let bytes = hex::decode(value.trim()).map_err(|_| ConfigError::InvalidEncryptionKey {
        variable: CREDENTIALS_ENCRYPTION_KEY_VAR,
    })?;
    if bytes.len() != 32 {
        return Err(ConfigError::InvalidEncryptionKey {
            variable: CREDENTIALS_ENCRYPTION_KEY_VAR,
        });
    }
    Ok(SecretBox::from(bytes.into_boxed_slice()))
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
    /// El valor de `CREDENTIALS_ENCRYPTION_KEY` no es un hex de 64
    /// caracteres (no decodifica a 32 bytes).
    #[error(
        "la variable de entorno {variable} no contiene una clave de cifrado de 32 bytes \
         (hex de 64 caracteres)"
    )]
    InvalidEncryptionKey {
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

    /// Clave de cifrado de laboratorio: 32 bytes (0x07) codificados en hex.
    fn encryption_key_hex() -> &'static str {
        /// 64 caracteres: "07" * 32 bytes.
        const HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";
        HEX
    }

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
                std::env::set_var(CREDENTIALS_ENCRYPTION_KEY_VAR, encryption_key_hex());
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
                std::env::remove_var(MIGRATIONS_DATABASE_URL_VAR);
                std::env::remove_var(CREDENTIALS_ENCRYPTION_KEY_VAR);
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
        assert_eq!(
            config.credentials_encryption_key.expose_secret(),
            &[0x07u8; 32]
        );

        drop(guard);
    }

    #[test]
    fn from_env_returns_typed_error_when_encryption_key_is_missing() {
        let guard = EnvGuard::set_valid_env();
        // Seguro por la misma razón que en `EnvGuard::set_valid_env`.
        unsafe {
            std::env::remove_var(CREDENTIALS_ENCRYPTION_KEY_VAR);
        }

        let result = Config::from_env();

        assert!(matches!(
            result,
            Err(ConfigError::MissingVar {
                variable: CREDENTIALS_ENCRYPTION_KEY_VAR
            })
        ));

        drop(guard);
    }

    #[test]
    fn from_env_returns_typed_error_when_encryption_key_is_not_valid_hex_of_32_bytes() {
        let guard = EnvGuard::set_valid_env();
        // Seguro por la misma razón que en `EnvGuard::set_valid_env`.
        unsafe {
            std::env::set_var(CREDENTIALS_ENCRYPTION_KEY_VAR, "no-es-hex");
        }

        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidEncryptionKey {
                variable: CREDENTIALS_ENCRYPTION_KEY_VAR
            })
        ));

        // Longitud incorrecta (62 caracteres hex = 31 bytes) también es un
        // error tipado.
        unsafe {
            std::env::set_var(
                CREDENTIALS_ENCRYPTION_KEY_VAR,
                "07070707070707070707070707070707070707070707070707070707070707",
            );
        }

        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidEncryptionKey {
                variable: CREDENTIALS_ENCRYPTION_KEY_VAR
            })
        ));

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
    fn from_env_loads_migrations_database_url_when_present() {
        let guard = EnvGuard::set_valid_env();
        // Seguro por la misma razón que en `EnvGuard::set_valid_env`.
        unsafe {
            std::env::set_var(
                MIGRATIONS_DATABASE_URL_VAR,
                "postgres://migrator:pass@localhost/db",
            );
        }

        let config = Config::from_env().expect("la configuración válida debe cargar sin error");

        assert_eq!(
            config.migrations_database_url,
            "postgres://migrator:pass@localhost/db"
        );
        assert_eq!(config.database_url, "postgres://user:pass@localhost/db");

        drop(guard);
    }

    #[test]
    fn from_env_falls_back_to_database_url_when_migrations_database_url_is_absent() {
        let guard = EnvGuard::set_valid_env();

        let config = Config::from_env().expect("la configuración válida debe cargar sin error");

        assert_eq!(config.migrations_database_url, config.database_url);

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
        assert!(
            !debug_output.contains(encryption_key_hex()),
            "el Debug de Config no debe filtrar la clave de cifrado de credenciales"
        );

        drop(guard);
    }
}
