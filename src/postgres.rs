use core::{error::Error, fmt};

use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;

/// Type alias for a `NoTLS` Postgres connection pool.
pub type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;

/// Setup a connection pool for PostgreSQL.
///
/// Connection string should be in the form:
/// `postgres://username:password@host:port`
pub async fn setup_connection_pool<S: ToString>(
    connection_string: S,
) -> Result<ConnectionPool, SetupPostgresError> {
    let manager = PostgresConnectionManager::new_from_stringlike(connection_string, NoTls)
        .map_err(|source| SetupPostgresError::InvalidConnectionString { source })?;

    let pool = Pool::builder()
        .build(manager)
        .await
        .map_err(|source| SetupPostgresError::BuildPoolError { source })?;

    Ok(pool)
}

#[derive(Debug)]
#[non_exhaustive]
/// Error kinds for setting up Postgres.
pub enum SetupPostgresError {
    #[non_exhaustive]
    /// The pool could not be built.
    BuildPoolError {
        /// The source of the error.
        source: tokio_postgres::Error,
    },

    #[non_exhaustive]
    /// The connection string provided was invalid.
    InvalidConnectionString {
        /// The source of the error.
        source: tokio_postgres::Error,
    },
}
impl fmt::Display for SetupPostgresError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::BuildPoolError { .. } => {
                write!(f, "failed to build connection pool")
            }
            Self::InvalidConnectionString { .. } => {
                write!(f, "invalid connection string")
            }
        }
    }
}
impl Error for SetupPostgresError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::BuildPoolError { source } => Some(source),
            Self::InvalidConnectionString { source } => Some(source),
        }
    }
}
