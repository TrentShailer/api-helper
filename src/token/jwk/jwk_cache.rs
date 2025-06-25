use core::{error::Error, fmt};
use std::collections::HashMap;

use jiff::{SignedDuration, Timestamp};
use reqwest::{Client, StatusCode};
use tokio::sync::RwLock;

use crate::token::jwk::{DecodingJwk, Jwks, decoding_jwk};

pub struct JwkCache {
    pub url: String,
    pub client: Client,
    pub cache: RwLock<HashMap<String, DecodingJwk>>,
    pub last_refresh: RwLock<Timestamp>,
}

impl JwkCache {
    pub fn new(jwks_url: String, client: Client) -> Self {
        Self {
            url: jwks_url,
            client,
            cache: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(Timestamp::UNIX_EPOCH),
        }
    }

    pub async fn refresh(&self) -> Result<(), RefreshCacheError> {
        let now = Timestamp::now();

        let last_refresh = self.last_refresh.read().await;
        if last_refresh.duration_until(now) < SignedDuration::from_hours(4) {
            return Ok(());
        }
        drop(last_refresh);

        let jwks: Jwks = self.client.get(&self.url).send().await?.json().await?;

        let mut cache = self.cache.write().await;

        for jwk in jwks.keys {
            let kid = jwk.kid.clone();
            let decoding_jwk =
                DecodingJwk::try_from(jwk).map_err(|source| RefreshCacheError::InvalidJwk {
                    kid: kid.clone(),
                    source,
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

#[derive(Debug)]
#[non_exhaustive]
pub enum RefreshCacheError {
    #[non_exhaustive]
    CouldNotConnect { source: reqwest::Error },

    #[non_exhaustive]
    InvalidResponse { source: reqwest::Error },

    #[non_exhaustive]
    InvalidRequest { source: reqwest::Error },

    #[non_exhaustive]
    ErrorResponse {
        status: StatusCode,
        source: reqwest::Error,
    },

    #[non_exhaustive]
    InvalidJwk {
        kid: String,
        source: decoding_jwk::FromJwkError,
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
