use core::{error::Error, fmt};

use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;

pub type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;

/// Setup a connection pool for PostgreSQL.
///
/// Connection string should be in the form:
/// `postgres://username:password@host:port`
pub async fn setup_connection_pool<S: ToString>(
    connection_string: S,
) -> Result<ConnectionPool, SetupPostgresError> {
    let manager = PostgresConnectionManager::new_from_stringlike(connection_string, NoTls)
        .map_err(|source| SetupPostgresError {
            kind: SetupPostgresErrorKind::InvalidConnectionString { source },
        })?;

    let pool = Pool::builder()
        .build(manager)
        .await
        .map_err(|source| SetupPostgresError {
            kind: SetupPostgresErrorKind::BuildPoolError { source },
        })?;

    Ok(pool)
}

#[derive(Debug)]
#[non_exhaustive]
pub struct SetupPostgresError {
    pub kind: SetupPostgresErrorKind,
}
impl fmt::Display for SetupPostgresError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error setting up postgres connection")
    }
}
impl Error for SetupPostgresError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.kind)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SetupPostgresErrorKind {
    #[non_exhaustive]
    BuildPoolError { source: tokio_postgres::Error },

    #[non_exhaustive]
    InvalidConnectionString { source: tokio_postgres::Error },
}
impl fmt::Display for SetupPostgresErrorKind {
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
impl Error for SetupPostgresErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::BuildPoolError { source } => Some(source),
            Self::InvalidConnectionString { source } => Some(source),
        }
    }
}
