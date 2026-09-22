//! Persistencia en PostgreSQL vía `sqlx`: perfiles, histórico de escaneos,
//! auditoría y credenciales de red.
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
//!
//! ## Credenciales de red (feature `network_credentials_api`)
//!
//! `ssh_credentials_ref` es una credencial SSH **real** hacia
//! infraestructura de terceros (ver `docs/security-scope.md` §"Credenciales
//! de red"), así que nunca se persiste en claro: este módulo la cifra con
//! AES-256-GCM antes de cada `INSERT`/`UPDATE` (nonce aleatorio por fila)
//! con la clave `Repository::encryption_key`, y la descifra únicamente en
//! [`Repository::resolve_scan_target`], el único punto donde el servicio la
//! devuelve. El parseo de IP/CIDR y el matching de objetivos (contención,
//! patrón más específico gana) son funciones puras — [`parse_target`] (pública
//! y de borde), más `network_matches`/`best_target_match` (privadas,
//! cubiertas por tests unitarios) — sin dependencia de IO, para poder
//! testearlas sin Docker.

use std::net::IpAddr;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ipnetwork::IpNetwork;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretSlice};
use sqlx::PgPool;

use crate::domain::{
    AuditEntry, NetworkCredential, ResolvedScanTarget, ScanHistoryEntry, ScanStatus, UserProfile,
};

/// Longitud del nonce de AES-256-GCM (96 bits, el tamaño que exige la
/// construcción `Aes256Gcm`).
const AES_GCM_NONCE_LEN: usize = 12;

/// Acceso a la persistencia de `ms-usuarios` en PostgreSQL.
///
/// No construye ni configura el [`PgPool`] que recibe: eso es
/// responsabilidad de quien lo instancia (composition root en producción,
/// arnés de test en los tests de integración de este módulo).
pub struct Repository {
    pool: PgPool,
    encryption_key: SecretSlice<u8>,
}

impl Repository {
    /// Construye un [`Repository`] a partir de un [`PgPool`] ya conectado y
    /// la clave de cifrado en reposo de las credenciales de red (ver
    /// `docs/security-scope.md` §"Credenciales de red").
    pub fn new(pool: PgPool, encryption_key: SecretSlice<u8>) -> Self {
        Self {
            pool,
            encryption_key,
        }
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

    /// Devuelve el `user_id` dueño de `scan_id`, para que el llamante
    /// (`api::patch_scan_status`) pueda verificar autorización a nivel de
    /// fila antes de mutar el estado del escaneo (ver
    /// `docs/security-scope.md` §"Autorización a nivel de fila": un `id` que
    /// no coincide con la identidad del llamante es `403`, no un `UPDATE`
    /// que "por suerte" no afecta ninguna fila).
    ///
    /// Un `scan_id` inexistente devuelve `Ok(None)`, nunca un error.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla, nunca hace `panic!`.
    pub async fn find_scan_owner(&self, scan_id: &str) -> Result<Option<String>, RepoError> {
        let owner: Option<(String,)> =
            sqlx::query_as("SELECT user_id FROM scan_history WHERE scan_id = $1")
                .bind(scan_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(owner.map(|(user_id,)| user_id))
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

    /// Registra, de forma atómica, una nueva entrada de histórico de
    /// escaneo (RF-13) y su correspondiente entrada de auditoría (RF-15) —
    /// ambos `INSERT` se ejecutan dentro de la misma transacción de base de
    /// datos: si el `INSERT` de `scan_history` tiene éxito pero el de
    /// `audit_log` falla (p. ej. porque `audit_entry.user_id()` viola la
    /// clave foránea hacia `users`), la transacción se revierte por
    /// completo y el histórico tampoco queda persistido.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si cualquiera de los dos `INSERT` falla, o si
    /// no se puede abrir/confirmar la transacción. Nunca hace `panic!`.
    pub async fn record_scan_request(
        &self,
        entry: &ScanHistoryEntry,
        audit_entry: &AuditEntry,
    ) -> Result<(), RepoError> {
        let mut tx = self.pool.begin().await?;

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
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO audit_log (id, user_id, target, action, recorded_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(audit_entry.id())
        .bind(audit_entry.user_id())
        .bind(audit_entry.target())
        .bind(audit_entry.action())
        .bind(audit_entry.recorded_at())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Devuelve las entradas de auditoría (RF-15) originadas por
    /// `user_id`, ordenadas por fecha de registro ascendente.
    ///
    /// Un `user_id` sin entradas (o inexistente) devuelve un `Vec` vacío,
    /// nunca un error.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla, nunca hace `panic!`.
    pub async fn list_audit_entries(&self, user_id: &str) -> Result<Vec<AuditEntry>, RepoError> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT id, user_id, target, action, recorded_at \
             FROM audit_log WHERE user_id = $1 ORDER BY recorded_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(AuditEntry::from).collect())
    }

    /// Crea o actualiza (upsert por `user_id` + `target_pattern`) la entrada
    /// de credenciales de red del usuario para un objetivo (feature
    /// `network_credentials_api`). El `id` de la fila lo asigna el llamante
    /// (generado por `api`, como el `scan_id` del histórico); al actualizar
    /// una entrada existente ese `id` original se conserva.
    ///
    /// `ssh_credentials_ref` se cifra con AES-256-GCM (nonce aleatorio por
    /// fila) antes del `INSERT`/`UPDATE` — nunca se persiste en claro. La
    /// entrada devuelta (`[`NetworkCredential`]`) no incluye la credencial.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla (p. ej. `user_id` no
    /// referencia a un usuario existente, o el cifrado falla — este último
    /// nunca ocurre con una clave válida). Nunca hace `panic!`.
    pub async fn upsert_network_credential(
        &self,
        id: uuid::Uuid,
        user_id: &str,
        target_pattern: &str,
        network_user: &str,
        ssh_credentials_ref: &str,
        has_sudo: bool,
    ) -> Result<NetworkCredential, RepoError> {
        let (ciphertext, nonce) =
            encrypt_secret(ssh_credentials_ref, self.encryption_key.expose_secret())?;

        let row = sqlx::query_as::<_, NetworkCredentialMetaRow>(
            "INSERT INTO network_credentials \
             (id, user_id, target_pattern, network_user, ssh_credentials_ref_ciphertext, \
              ssh_credentials_ref_nonce, has_sudo, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now()) \
             ON CONFLICT (user_id, target_pattern) DO UPDATE SET \
               network_user = EXCLUDED.network_user, \
               ssh_credentials_ref_ciphertext = EXCLUDED.ssh_credentials_ref_ciphertext, \
               ssh_credentials_ref_nonce = EXCLUDED.ssh_credentials_ref_nonce, \
               has_sudo = EXCLUDED.has_sudo, \
               updated_at = now() \
             RETURNING id, user_id, target_pattern, network_user, has_sudo, created_at, updated_at",
        )
        .bind(id)
        .bind(user_id)
        .bind(target_pattern)
        .bind(network_user)
        .bind(ciphertext)
        .bind(nonce)
        .bind(has_sudo)
        .fetch_one(&self.pool)
        .await?;

        Ok(NetworkCredential::from(row))
    }

    /// Devuelve las entradas de credenciales de red de `user_id`
    /// (feature `network_credentials_api`), sin la credencial SSH — la
    /// única salida posible de ese valor en claro es
    /// [`Repository::resolve_scan_target`].
    ///
    /// Un `user_id` sin entradas (o inexistente) devuelve un `Vec` vacío,
    /// nunca un error.
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError`] si la consulta falla, nunca hace `panic!`.
    pub async fn list_network_credentials(
        &self,
        user_id: &str,
    ) -> Result<Vec<NetworkCredential>, RepoError> {
        let rows = sqlx::query_as::<_, NetworkCredentialMetaRow>(
            "SELECT id, user_id, target_pattern, network_user, has_sudo, created_at, updated_at \
             FROM network_credentials WHERE user_id = $1 ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(NetworkCredential::from).collect())
    }

    /// Borra la entrada de credenciales de red con `id`, **solo si
    /// pertenece a `user_id`** (autorización a nivel de fila, ver
    /// `docs/security-scope.md`).
    ///
    /// Un `id` inexistente, o un `id` existente pero de otro usuario,
    /// devuelve [`RepoError::NotFound`] — el endpoint responde `404` en
    /// ambos casos sin revelar a quién pertenece la entrada (decisión
    /// explícita de la feature `network_credentials_api`).
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError::NotFound`] si el `DELETE` no afectó ninguna
    /// fila, o [`RepoError`] si la consulta falla por otro motivo. Nunca
    /// hace `panic!`.
    pub async fn delete_network_credential(
        &self,
        id: uuid::Uuid,
        user_id: &str,
    ) -> Result<(), RepoError> {
        let result = sqlx::query("DELETE FROM network_credentials WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(RepoError::NotFound);
        }

        Ok(())
    }

    /// Resuelve las credenciales de red de `user_id` que mejor matchean el
    /// objetivo `target` (IP exacta o CIDR, ya validado por el llamante) —
    /// feature `network_credentials_api`.
    ///
    /// Reglas de matching (ver la feature en `feature_list.json`): un
    /// `target_pattern` matchea si `target` es una IP contenida en él, o si
    /// son el mismo CIDR. Si varias entradas matchean, gana la de
    /// `target_pattern` más específico (prefijo más largo). El valor en
    /// claro de `ssh_credentials_ref` se descifra **solo** aquí — es el
    /// único punto del repositorio donde la credencial sale de su cifrado.
    ///
    /// Un usuario sin ninguna entrada que matchee devuelve `Ok(None)`,
    /// nunca un error (la API lo traduce a `422`).
    ///
    /// # Errores
    ///
    /// Devuelve [`RepoError::Backend`] si una `target_pattern` almacenada no
    /// se puede parsear (no debería ocurrir porque se valida al escribirse),
    /// si el descifrado falla (cifrado manipulado), o por cualquier otro
    /// fallo de consulta. Nunca hace `panic!`.
    pub async fn resolve_scan_target(
        &self,
        user_id: &str,
        target: IpNetwork,
    ) -> Result<Option<ResolvedScanTarget>, RepoError> {
        let rows = sqlx::query_as::<_, NetworkCredentialRow>(
            "SELECT target_pattern, network_user, ssh_credentials_ref_ciphertext, \
             ssh_credentials_ref_nonce, has_sudo \
             FROM network_credentials WHERE user_id = $1 ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let patterns = rows
            .iter()
            .map(|row| parse_target(&row.target_pattern).ok_or(RepoError::Backend))
            .collect::<Result<Vec<IpNetwork>, RepoError>>()?;

        let Some(index) = best_target_match(&patterns, target) else {
            return Ok(None);
        };

        let row = &rows[index];
        let ssh_credentials_ref = decrypt_secret(
            &row.ssh_credentials_ref_ciphertext,
            &row.ssh_credentials_ref_nonce,
            self.encryption_key.expose_secret(),
        )?;

        Ok(Some(ResolvedScanTarget {
            network_user: row.network_user.clone(),
            ssh_credentials_ref,
            has_sudo: row.has_sudo,
        }))
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

/// Fila cruda de la tabla `audit_log`, mapeada a [`AuditEntry`] vía `From`
/// (no hay estado que validar, a diferencia de `scan_history`, así que la
/// conversión no puede fallar).
#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    user_id: String,
    target: String,
    action: String,
    recorded_at: chrono::DateTime<chrono::Utc>,
}

impl From<AuditRow> for AuditEntry {
    fn from(row: AuditRow) -> Self {
        AuditEntry::new(row.id, row.user_id, row.target, row.action, row.recorded_at)
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

/// Fila de `network_credentials` con los metadatos de la entrada (sin el
/// cifrado de la credencial), mapeada a [`NetworkCredential`] vía `From`.
#[derive(sqlx::FromRow)]
struct NetworkCredentialMetaRow {
    id: uuid::Uuid,
    user_id: String,
    target_pattern: String,
    network_user: String,
    has_sudo: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// Fila de `network_credentials` con lo que necesita
/// [`Repository::resolve_scan_target`]: el patrón a cotejar, el usuario de
/// red y el cifrado en reposo de `ssh_credentials_ref` (ciphertext + nonce)
/// para poder descifrarla solo aquí.
#[derive(sqlx::FromRow)]
struct NetworkCredentialRow {
    target_pattern: String,
    network_user: String,
    ssh_credentials_ref_ciphertext: Vec<u8>,
    ssh_credentials_ref_nonce: Vec<u8>,
    has_sudo: bool,
}

impl From<NetworkCredentialMetaRow> for NetworkCredential {
    fn from(row: NetworkCredentialMetaRow) -> Self {
        NetworkCredential {
            id: row.id.to_string(),
            user_id: row.user_id,
            target_pattern: row.target_pattern,
            network_user: row.network_user,
            has_sudo: row.has_sudo,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Parsea un objetivo válido de la API: una IP exacta (v4 o v6) o un CIDR
/// (v4 o v6), vía el crate `ipnetwork`. Devuelve `None` si el valor no es
/// ninguna de las dos cosas — nunca hace `panic!`, y nunca acepta un
/// string inválido como si fuera un objetivo.
///
/// Es una función pura sin dependencia de IO: la usan tanto `api` para
/// validar en el borde (400 si devuelve `None`) como `repository` para
/// re-parsear las `target_pattern` almacenadas al resolver.
pub fn parse_target(value: &str) -> Option<IpNetwork> {
    if let Ok(network) = value.parse::<IpNetwork>() {
        return Some(network);
    }
    value.parse::<IpAddr>().ok().map(IpNetwork::from)
}

/// Devuelve `true` si `pattern` matchea `target` según la semántica de la
/// feature `network_credentials_api`: igualdad exacta (misma IP, o el mismo
/// CIDR), o `target` es una IP exacta contenida dentro del CIDR `pattern`.
///
/// Un objetivo que es en sí un CIDR solo matchea si es exactamente el mismo
/// CIDR — no si es una subred de otro (el contrato de la feature dice "si son
/// el mismo CIDR", no "si está contenido en otro CIDR").
fn network_matches(pattern: IpNetwork, target: IpNetwork) -> bool {
    if pattern == target {
        return true;
    }
    let target_is_exact_ip = match target.ip() {
        IpAddr::V4(_) => target.prefix() == 32,
        IpAddr::V6(_) => target.prefix() == 128,
    };
    target_is_exact_ip && pattern.contains(target.ip())
}

/// Índice del `target_pattern` entre `patterns` que mejor matchea `target`,
/// o `None` si ninguno matchea.
///
/// Si varias entradas matchean, gana la de prefijo más largo (más
/// específica). No puede haber empate a prefijo para un mismo usuario
/// porque la tabla impone unicidad en `(user_id, target_pattern)` — pero si
/// lo hubiera, `max_by_key` devolvería cualquiera de los empatados.
fn best_target_match(patterns: &[IpNetwork], target: IpNetwork) -> Option<usize> {
    patterns
        .iter()
        .enumerate()
        .filter(|(_, pattern)| network_matches(**pattern, target))
        .max_by_key(|(_, pattern)| pattern.prefix())
        .map(|(index, _)| index)
}

/// Cifra `value` con AES-256-GCM usando `key`, con un nonce aleatorio
/// (96 bits) distinto en cada llamada. Devuelve `(ciphertext, nonce)`; el
/// nonce se persiste junto al ciphertext para poder descifrar después.
///
/// # Errores
///
/// Devuelve [`RepoError::Backend`] si la operación de cifrado falla (no
/// debería ocurrir con una clave válida). Nunca hace `panic!`.
fn encrypt_secret(value: &str, key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RepoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), value.as_bytes())
        .map_err(|_| RepoError::Backend)?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Descifra el `ciphertext` cifrado con [`encrypt_secret`] usando `key` y el
/// `nonce` que se guardó junto a él.
///
/// # Errores
///
/// Devuelve [`RepoError::Backend`] si el nonce no tiene la longitud
/// esperada (96 bits), si el ciphertext fue manipulado (falla la
/// autenticación de AES-GCM), o si el resultado no es UTF-8 válido. Nunca
/// hace `panic!`.
fn decrypt_secret(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<String, RepoError> {
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(RepoError::Backend);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| RepoError::Backend)?;

    String::from_utf8(plaintext).map_err(|_| RepoError::Backend)
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
    use secrecy::ExposeSecret;
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    /// Clave de cifrado de laboratorio (32 bytes) para los tests que no
    /// requieren Docker.
    fn test_encryption_key() -> SecretSlice<u8> {
        SecretSlice::from(vec![0x07u8; 32])
    }

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
        let repo = Repository::new(pool, test_encryption_key());

        let result = repo.find_user("someone").await;

        assert!(
            matches!(result, Err(RepoError::ConnectionFailed)),
            "se esperaba RepoError::ConnectionFailed, se obtuvo: {result:?}"
        );
    }

    #[test]
    fn parse_target_accepts_exact_ipv4_and_ipv6_and_cidrs() {
        assert_eq!(
            parse_target("203.0.113.7"),
            Some("203.0.113.7/32".parse::<IpNetwork>().expect("ip v4"))
        );
        assert_eq!(
            parse_target("2001:db8::1"),
            Some("2001:db8::1/128".parse::<IpNetwork>().expect("ip v6"))
        );
        assert_eq!(
            parse_target("203.0.113.0/24"),
            Some("203.0.113.0/24".parse().expect("cidr v4"))
        );
        assert_eq!(
            parse_target("2001:db8::/32"),
            Some("2001:db8::/32".parse().expect("cidr v6"))
        );
        assert_eq!(parse_target("203.0.113.7/33"), None);
        assert_eq!(parse_target("2001:db8::/129"), None);
    }

    #[test]
    fn parse_target_rejects_invalid_values_instead_of_panicking() {
        for value in [
            "no-es-una-ip",
            "203.0.113.7/24-junk",
            "999.999.999.999",
            "",
            "203.0.113.",
        ] {
            assert_eq!(parse_target(value), None, "se esperaba None para {value:?}");
        }
    }

    #[test]
    fn network_matches_exact_same_cidr_but_not_overlapping_cidrs() {
        let pattern: IpNetwork = "203.0.113.0/24".parse().expect("cidr");
        let same_cidr: IpNetwork = "203.0.113.0/24".parse().expect("cidr");
        // Un objetivo que es en sí un CIDR solo matchea si es el mismo CIDR.
        let more_specific_cidr: IpNetwork = "203.0.113.0/28".parse().expect("cidr");
        assert!(network_matches(pattern, same_cidr));
        assert!(!network_matches(pattern, more_specific_cidr));

        let exact_ip: IpNetwork = "203.0.113.7/32".parse().expect("ip");
        assert!(network_matches(pattern, exact_ip));
        let exact_ip_v6: IpNetwork = "2001:db8::5/128".parse().expect("ip");
        assert!(network_matches(
            "2001:db8::/32".parse().expect("cidr"),
            exact_ip_v6
        ));
    }

    #[test]
    fn network_matches_exact_ip_does_not_match_a_larger_or_different_cidr() {
        let pattern: IpNetwork = "203.0.113.7/32".parse().expect("ip");
        let other_ip: IpNetwork = "203.0.113.8/32".parse().expect("ip");
        let contained_cidr: IpNetwork = "203.0.113.0/24".parse().expect("cidr");
        assert!(!network_matches(pattern, other_ip));
        assert!(!network_matches(pattern, contained_cidr));
    }

    #[test]
    fn best_target_match_prefers_the_most_specific_pattern() {
        let patterns = [
            "0.0.0.0/0".parse::<IpNetwork>().expect("any"),
            "203.0.113.0/24".parse::<IpNetwork>().expect("med"),
            "203.0.113.0/28".parse::<IpNetwork>().expect("spec"),
        ];
        let target: IpNetwork = "203.0.113.7/32".parse().expect("ip");

        assert_eq!(best_target_match(&patterns, target), Some(2));
    }

    #[test]
    fn best_target_match_returns_none_when_nothing_matches() {
        let patterns = ["10.20.0.0/16".parse::<IpNetwork>().expect("cidr")];
        let target: IpNetwork = "203.0.113.7/32".parse().expect("ip");

        assert_eq!(best_target_match(&patterns, target), None);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips_the_secret() {
        let key = test_encryption_key();
        let ciphertext = "lab-only-credential-ref".to_string();

        let (sealed, nonce) = encrypt_secret(&ciphertext, key.expose_secret()).expect("cifra");

        assert_ne!(sealed.as_slice(), ciphertext.as_bytes());
        assert_eq!(nonce.len(), AES_GCM_NONCE_LEN);

        let opened = decrypt_secret(&sealed, &nonce, key.expose_secret()).expect("descifra");
        assert_eq!(opened, ciphertext);
    }

    #[test]
    fn encrypt_uses_a_distinct_nonce_per_call() {
        let key = test_encryption_key();
        let secret = "mismo-secreto-distinto-nonce".to_string();

        let (first, first_nonce) = encrypt_secret(&secret, key.expose_secret()).expect("cifra");
        let (second, second_nonce) = encrypt_secret(&secret, key.expose_secret()).expect("cifra");

        assert_ne!(first_nonce, second_nonce);
        assert_ne!(
            first, second,
            "nonces distintos deben dar ciphertexts distintos"
        );
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext_instead_of_panicking() {
        let key = test_encryption_key();
        let (mut sealed, nonce) =
            encrypt_secret("credencial-de-lab", key.expose_secret()).expect("cifra");

        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;

        assert!(matches!(
            decrypt_secret(&sealed, &nonce, key.expose_secret()),
            Err(RepoError::Backend)
        ));
    }

    #[test]
    fn decrypt_rejects_an_invalid_nonce_length_instead_of_panicking() {
        let key = test_encryption_key();
        let (sealed, _nonce) =
            encrypt_secret("credencial-de-lab", key.expose_secret()).expect("cifra");

        assert!(matches!(
            decrypt_secret(&sealed, &[0u8; 7], key.expose_secret()),
            Err(RepoError::Backend)
        ));
    }

    #[test]
    fn decrypt_with_the_wrong_key_fails_instead_of_panicking() {
        let key: [u8; 32] = [0x07u8; 32];
        let wrong_key: [u8; 32] = [0x08u8; 32];
        let (sealed, nonce) = encrypt_secret("credencial-de-lab", &key).expect("cifra");

        assert!(matches!(
            decrypt_secret(&sealed, &nonce, &wrong_key),
            Err(RepoError::Backend)
        ));
    }
}
