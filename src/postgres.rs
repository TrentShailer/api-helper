use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use thiserror::Error;
use tokio_postgres::NoTls;

pub type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;

/// Setup a connection pool for PostgreSQL.
///
/// Connection string should be in the form:
/// `postgres://username:password@host:port`
pub async fn setup_connection_pool(
    connection_string: String,
) -> Result<ConnectionPool, SetupPostgresError> {
    let manager = PostgresConnectionManager::new_from_stringlike(connection_string, NoTls)
        .map_err(SetupPostgresError::ConnectionString)?;

    let pool = Pool::builder()
        .build(manager)
        .await
        .map_err(SetupPostgresError::BuildPool)?;

    Ok(pool)
}

#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum SetupPostgresError {
    #[error("{0}")]
    BuildPool(#[source] tokio_postgres::Error),

    #[error("{0}")]
    ConnectionString(#[source] tokio_postgres::Error),
}
