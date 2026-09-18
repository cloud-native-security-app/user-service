//! Persistencia en PostgreSQL vía `sqlx`: perfiles, histórico de escaneos y
//! auditoría.
//!
//! [`Repository`] envuelve un [`sqlx::PgPool`] ya construido por el
//! llamante (en producción, la feature `service_wiring`; en los tests de
//! integración de este módulo, el propio test) — este módulo no decide con
//! qué rol de base de datos se conecta ese pool ni cómo se aplican las
//! migraciones de `migrations/`, solo ejecuta las consultas contra lo que
//! reciba. `audit_log` se refuerza como append-only a nivel de base de
//! datos (RF-15, ver `migrations/20260918120100_lock_audit_log_permissions.sql`
//! y `docs/security-scope.md`): este módulo, a propósito, no expone ningún
//! método `update`/`delete` para esa tabla, ni siquiera uno que dependiera
//! de que el rol de base de datos lo permitiera.

use sqlx::PgPool;

use crate::domain::{AuditEntry, ScanHistoryEntry, ScanStatus, UserProfile};

/// Acceso a la persistencia de `ms-usuarios` en PostgreSQL.
///
/// No construye ni configura el [`PgPool`] que recibe: eso es
/// responsabilidad de quien lo instancia (composition root en producción,
/// arnés de test en los tests de integración de este módulo).
pub struct Repository {
    pool: PgPool,
}

impl Repository {
    /// Construye un [`Repository`] a partir de un [`PgPool`] ya conectado.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Crea el perfil de `profile.user_id` si no existe, o actualiza
    /// `email`/`display_name` si ya existía (`created_at` del registro
    /// original se conserva).
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla (p. ej. sin conexión a
    /// la base de datos). Nunca hace `panic!`.
    pub async fn upsert_user(&self, profile: &UserProfile) -> Result<(), RepoError> {
        sqlx::query(
            "INSERT INTO users (user_id, email, display_name, created_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, \
             display_name = EXCLUDED.display_name",
        )
        .bind(&profile.user_id)
        .bind(&profile.email)
        .bind(&profile.display_name)
        .bind(profile.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Busca el perfil asociado a `user_id`.
    ///
    /// Un `user_id` inexistente devuelve `Ok(None)`, nunca un error.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla, nunca hace `panic!`.
    pub async fn find_user(&self, user_id: &str) -> Result<Option<UserProfile>, RepoError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT user_id, email, display_name, created_at FROM users WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(UserProfile::from))
    }

    /// Inserta una nueva entrada de histórico de escaneo (RF-13).
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla (p. ej. `entry.user_id`
    /// no referencia a un usuario existente: violación de la clave foránea
    /// hacia `users`). Nunca hace `panic!`.
    pub async fn insert_scan_history(&self, entry: &ScanHistoryEntry) -> Result<(), RepoError> {
        sqlx::query(
            "INSERT INTO scan_history (scan_id, user_id, target, status, requested_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&entry.scan_id)
        .bind(&entry.user_id)
        .bind(&entry.target)
        .bind(status_as_db_str(entry.status))
        .bind(entry.requested_at)
        .bind(entry.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Actualiza el estado de una entrada de histórico existente,
    /// refrescando `updated_at` al momento de la actualización.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError::NotFound`] si `scan_id` no existe, o
    /// [`RepoError`] si la consulta falla por otro motivo. Nunca hace
    /// `panic!`.
    pub async fn update_scan_status(
        &self,
        scan_id: &str,
        status: ScanStatus,
    ) -> Result<(), RepoError> {
        let result = sqlx::query(
            "UPDATE scan_history SET status = $1, updated_at = now() WHERE scan_id = $2",
        )
        .bind(status_as_db_str(status))
        .bind(scan_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }

        Ok(())
    }

    /// Devuelve el histórico de escaneos de `user_id`, ordenado por fecha
    /// de solicitud ascendente.
    ///
    /// Un `user_id` sin entradas (o inexistente) devuelve un `Vec` vacío,
    /// nunca un error.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla, nunca hace `panic!`.
    pub async fn list_scan_history(
        &self,
        user_id: &str,
    ) -> Result<Vec<ScanHistoryEntry>, RepoError> {
        let rows = sqlx::query_as::<_, ScanHistoryRow>(
            "SELECT scan_id, user_id, target, status, requested_at, updated_at \
             FROM scan_history WHERE user_id = $1 ORDER BY requested_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(ScanHistoryEntry::try_from).collect()
    }

    /// Inserta una nueva entrada en el log de auditoría (RF-15).
    ///
    /// Deliberadamente **no** existe ningún método `update`/`delete` en
    /// este `impl` para `audit_log`: la única forma de modificar el
    /// registro histórico es añadir una entrada nueva. Esto se refuerza
    /// además a nivel de base de datos (ver
    /// `migrations/20260918120100_lock_audit_log_permissions.sql`), así que
    /// incluso un `sqlx::query` manual con `UPDATE`/`DELETE` fallaría por
    /// permisos si el pool usa el rol de aplicación `ms_usuarios_app`.
    ///
    /// # Errores
    ///
    /// Un error al escribir la entrada de auditoría se propaga como
    /// [`RepoError`] — nunca se descarta en silencio (ver
    /// `docs/security-scope.md`).
    pub async fn append_audit_entry(&self, entry: &AuditEntry) -> Result<(), RepoError> {
        sqlx::query(
            "INSERT INTO audit_log (id, user_id, target, action, recorded_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(entry.id())
        .bind(entry.user_id())
        .bind(entry.target())
        .bind(entry.action())
        .bind(entry.recorded_at())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Fila cruda de la tabla `users`, mapeada a [`UserProfile`] vía `From`.
#[derive(sqlx::FromRow)]
struct UserRow {
    user_id: String,
    email: String,
    display_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserRow> for UserProfile {
    fn from(row: UserRow) -> Self {
        UserProfile {
            user_id: row.user_id,
            email: row.email,
            display_name: row.display_name,
            created_at: row.created_at,
        }
    }
}

/// Fila cruda de la tabla `scan_history`, mapeada a [`ScanHistoryEntry`] vía
/// `TryFrom` (el estado se valida contra las 4 variantes conocidas de
/// [`ScanStatus`]).
#[derive(sqlx::FromRow)]
struct ScanHistoryRow {
    scan_id: String,
    user_id: String,
    target: String,
    status: String,
    requested_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<ScanHistoryRow> for ScanHistoryEntry {
    type Error = RepoError;

    fn try_from(row: ScanHistoryRow) -> Result<Self, Self::Error> {
        Ok(ScanHistoryEntry {
            scan_id: row.scan_id,
            user_id: row.user_id,
            target: row.target,
            status: status_from_db_str(&row.status)?,
            requested_at: row.requested_at,
            updated_at: row.updated_at,
        })
    }
}

/// Codifica un [`ScanStatus`] al `TEXT` almacenado en `scan_history.status`
/// (coincide con la restricción `CHECK` de la migración y con el encoding
/// `SCREAMING_SNAKE_CASE` de `ScanStatus` en `src/domain.rs`).
fn status_as_db_str(status: ScanStatus) -> &'static str {
    match status {
        ScanStatus::Pendiente => "PENDIENTE",
        ScanStatus::EnProgreso => "EN_PROGRESO",
        ScanStatus::Completado => "COMPLETADO",
        ScanStatus::Fallido => "FALLIDO",
    }
}

/// Decodifica el `TEXT` almacenado en `scan_history.status` a un
/// [`ScanStatus`].
///
/// # Errores
///
/// Devuelve [`RepoError::Backend`] si el valor no coincide con ninguna de
/// las 4 variantes conocidas — no debería ocurrir nunca en la práctica
/// porque la restricción `CHECK` de la migración ya lo impide, pero se
/// maneja como error tipado en vez de un `panic!`/`unwrap()` por si el
/// esquema y este código llegaran a divergir.
fn status_from_db_str(value: &str) -> Result<ScanStatus, RepoError> {
    match value {
        "PENDIENTE" => Ok(ScanStatus::Pendiente),
        "EN_PROGRESO" => Ok(ScanStatus::EnProgreso),
        "COMPLETADO" => Ok(ScanStatus::Completado),
        "FALLIDO" => Ok(ScanStatus::Fallido),
        _ => Err(RepoError::Backend),
    }
}

/// Error devuelto por las operaciones de [`Repository`].
///
/// Ninguna variante contiene datos personales (email, nombre) ni el texto
/// crudo de un error de base de datos que pudiera incluirlos (ver
/// `docs/security-scope.md`) — solo el código SQLSTATE cuando se trata de
/// una violación de restricción.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// No se pudo establecer o mantener la conexión con la base de datos.
    #[error("no se pudo conectar a la base de datos")]
    ConnectionFailed,
    /// La consulta violó una restricción de base de datos (p. ej. una
    /// clave foránea o una restricción `CHECK`). El valor es el código
    /// SQLSTATE devuelto por PostgreSQL, no el mensaje completo del error
    /// (que podría incluir valores de columnas).
    #[error("violación de restricción de base de datos (SQLSTATE {0})")]
    Constraint(String),
    /// La fila solicitada no existe.
    #[error("la entrada solicitada no existe")]
    NotFound,
    /// Error inesperado de backend, no cubierto por las otras variantes.
    #[error("error inesperado de backend")]
    Backend,
}

impl From<sqlx::Error> for RepoError {
    /// Traduce un error crudo de `sqlx` a un [`RepoError`] tipado, nunca a
    /// un `panic!`. Los errores de conectividad (E/S, timeout/cierre del
    /// pool, TLS) se agrupan como [`RepoError::ConnectionFailed`]; los
    /// errores de base de datos se traducen a [`RepoError::Constraint`]
    /// usando solo el código SQLSTATE (nunca el mensaje completo, que en
    /// PostgreSQL puede incluir el valor de la columna que violó la
    /// restricción).
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::Database(db_err) => RepoError::Constraint(
                db_err
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "desconocido".to_string()),
            ),
            sqlx::Error::Io(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::Tls(_) => RepoError::ConnectionFailed,
            _ => RepoError::Backend,
        }
    }
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    #[test]
    fn status_round_trips_through_its_db_encoding() {
        for status in [
            ScanStatus::Pendiente,
            ScanStatus::EnProgreso,
            ScanStatus::Completado,
            ScanStatus::Fallido,
        ] {
            let encoded = status_as_db_str(status);
            let decoded = status_from_db_str(encoded).expect("debe decodificar su propio encoding");
            assert_eq!(decoded, status);
        }
    }

    #[test]
    fn status_from_db_str_rejects_unknown_value_instead_of_panicking() {
        let result = status_from_db_str("NO_EXISTE");

        assert!(matches!(result, Err(RepoError::Backend)));
    }

    /// No requiere Docker: usa `connect_lazy` contra un puerto de loopback
    /// que rechaza la conexión, para verificar que un fallo de
    /// conectividad se traduce en `RepoError::ConnectionFailed` en vez de
    /// un panic (parte del acceptance de la feature `postgres_persistence`
    /// que no depende de un Postgres real).
    #[tokio::test]
    async fn find_user_returns_connection_failed_when_database_is_unreachable() {
        // `acquire_timeout` corto para que el test falle rápido en vez de
        // esperar los 30s por defecto de sqlx antes de dar por perdida la
        // conexión al puerto de loopback que la rechaza inmediatamente.
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_lazy("postgres://user:pass@127.0.0.1:1/db")
            .expect("connect_lazy no debe fallar de forma síncrona");
        let repo = Repository::new(pool);

        let result = repo.find_user("someone").await;

        assert!(
            matches!(result, Err(RepoError::ConnectionFailed)),
            "se esperaba RepoError::ConnectionFailed, se obtuvo: {result:?}"
        );
    }
}
