//! A cache for a JWKS.
use core::{error::Error, fmt};
use std::{collections::HashMap, sync::Arc};

use jiff::{SignedDuration, Timestamp};
use reqwest::{Client, StatusCode};
use tokio::sync::RwLock;

use crate::token::json_web_key::{JsonWebKeySet, VerifyingJsonWebKey, verifying};

/// A cache for a JSON web key set.
#[derive(Clone)]
pub struct JsonWebKeySetCache {
    /// The URL to the JSON web key set.
    pub url: String,
    /// The web client used to fetch from the JSON web key set.
    pub client: Client,
    /// The cached JSON web keys.
    pub cache: Arc<RwLock<HashMap<String, VerifyingJsonWebKey>>>,
    /// The time the cache was last refreshed.
    pub last_refresh: Arc<RwLock<Timestamp>>,
}

impl JsonWebKeySetCache {
    /// Create a new cache.
    pub fn new(jwks_url: String, client: Client) -> Self {
        Self {
            url: jwks_url,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            last_refresh: Arc::new(RwLock::new(Timestamp::UNIX_EPOCH)),
        }
    }

    /// Refresh the cache.
    pub async fn refresh(&self) -> Result<(), RefreshCacheError> {
        let now = Timestamp::now();

        let last_refresh = self.last_refresh.read().await;
        if last_refresh.duration_until(now) < SignedDuration::from_hours(4) {
            return Ok(());
        }
        drop(last_refresh);

        let jwks: JsonWebKeySet = self.client.get(&self.url).send().await?.json().await?;

        let mut cache = self.cache.write().await;

        for jwk in jwks.keys {
            let kid = jwk.kid.clone();
            let decoding_jwk = VerifyingJsonWebKey::try_from(jwk).map_err(|source| {
                RefreshCacheError::InvalidJwk {
                    kid: kid.clone(),
                    source,
                }
            })?;
            cache.insert(kid, decoding_jwk);
        }

        cache.retain(|_, key| {
            let elapsed = key.retrieved.duration_until(now);
            elapsed < SignedDuration::from_hours(24)
        });

        let mut last_refresh = self.last_refresh.write().await;
        *last_refresh = now;

        Ok(())
    }
}

/// Error variants from refreshing the cache.
#[derive(Debug)]
#[non_exhaustive]
pub enum RefreshCacheError {
    /// The client could not connect to the JSON web key set server.
    #[non_exhaustive]
    CouldNotConnect {
        /// The source of the error.
        source: reqwest::Error,
    },

    /// The JSON web key set sent back and invalid response.
    #[non_exhaustive]
    InvalidResponse {
        /// The source of the error.
        source: reqwest::Error,
    },

    /// The client request was invalid.
    #[non_exhaustive]
    InvalidRequest {
        /// The source of the error.
        source: reqwest::Error,
    },

    /// The JSON web key set sent back an error response.
    #[non_exhaustive]
    ErrorResponse {
        /// The response code.
        status: StatusCode,
        /// The source of the error.
        source: reqwest::Error,
    },

    /// A JSON web key in the JSON web key set is invalid.
    #[non_exhaustive]
    InvalidJwk {
        /// The JSON web key's ID.
        kid: String,
        /// The source of the error.
        source: verifying::FromJwkError,
    },
}
impl Error for RefreshCacheError {}
impl fmt::Display for RefreshCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CouldNotConnect { .. } => write!(f, "failed to connect to JWKS"),
            Self::InvalidResponse { .. } => write!(f, "invalid response from JWKS"),
            Self::InvalidRequest { .. } => write!(f, "invalid request to JWKS"),
            Self::ErrorResponse { status, .. } => {
                write!(f, "JWKS response has error status: {status}")
            }
            Self::InvalidJwk { kid, .. } => write!(f, "JWK `{kid}` is invalid"),
        }
    }
}
impl From<reqwest::Error> for RefreshCacheError {
    fn from(source: reqwest::Error) -> Self {
        if source.is_body() || source.is_decode() {
            Self::InvalidResponse { source }
        } else if source.is_builder() || source.is_request() {
            Self::InvalidRequest { source }
        } else if source.is_connect() || source.is_timeout() || source.is_redirect() {
            Self::CouldNotConnect { source }
        } else if source.is_status() {
            let status = source.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            Self::ErrorResponse { status, source }
        } else {
            Self::InvalidResponse { source }
        }
    }
}
