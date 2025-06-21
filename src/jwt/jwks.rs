use core::{error::Error, fmt, time::Duration};
use std::{collections::HashMap, time::Instant};

use jsonwebtoken::{
    DecodingKey,
    jwk::{Jwk, JwkSet},
};
use reqwest::{Client, StatusCode};
use tracing::warn;

pub struct Jwks {
    pub url: String,
    pub client: Client,
    pub cache: HashMap<String, (Instant, Jwk, DecodingKey)>,
}

impl Jwks {
    pub fn new(jwks_url: String, client: Client) -> Self {
        Self {
            url: jwks_url,
            client,
            cache: HashMap::new(),
        }
    }

    /// Fetch the JWKS from origin and return the keys.
    pub async fn fetch_jwks(&self) -> Result<Vec<Jwk>, FetchJwksError> {
        let body: JwkSet = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(FetchJwksError::from)?
            .json()
            .await
            .map_err(FetchJwksError::from)?;

        Ok(body.keys)
    }

    /// Try get the JWK, if the JWK is not present in the cache, update the cache.
    pub async fn try_get_jwk(
        &mut self,
        kid: &str,
    ) -> Result<Option<(&Jwk, &DecodingKey)>, GetJwkError> {
        // Clear any outdated cache items
        self.cache
            .retain(|_, (cached, _, _)| cached.elapsed() < Duration::from_secs(60 * 60 * 24));

        // If the cache does not contain the `kid`, check the JWKS.
        if !self.cache.contains_key(kid) {
            let jwks = self.fetch_jwks().await.map_err(|source| GetJwkError {
                kind: GetJwkErrorKind::FetchJwksError { source },
            })?;

            for jwk in jwks {
                if !jwk.is_supported()
                    || jwk.common.key_id.is_none()
                    || jwk.common.key_algorithm.is_none()
                {
                    continue;
                }
                let kid = jwk.common.key_id.clone().unwrap();
                let decoding_key = match DecodingKey::from_jwk(&jwk) {
                    Ok(key) => key,
                    Err(error) => {
                        warn!("Invalid JWK from JWKS (kid: {kid}): {error}");
                        continue;
                    }
                };

                self.cache.insert(kid, (Instant::now(), jwk, decoding_key));
            }
        }

        // Return the JWK from the cache
        Ok(self
            .cache
            .get(kid)
            .map(|(_, jwk, decoding_key)| (jwk, decoding_key)))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct GetJwkError {
    pub kind: GetJwkErrorKind,
}
impl Error for GetJwkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.kind)
    }
}
impl fmt::Display for GetJwkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to get JWK")
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum GetJwkErrorKind {
    #[non_exhaustive]
    FetchJwksError { source: FetchJwksError },
}
impl Error for GetJwkErrorKind {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            GetJwkErrorKind::FetchJwksError { source } => Some(source),
        }
    }
}
impl fmt::Display for GetJwkErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::FetchJwksError { .. } => write!(f, "failed to fetch JWKS"),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct FetchJwksError {
    pub source: reqwest::Error,
    pub kind: FetchJwksErrorKind,
}
impl Error for FetchJwksError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
impl fmt::Display for FetchJwksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to fetch JWKS")
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum FetchJwksErrorKind {
    #[non_exhaustive]
    CouldNotConnect,
    #[non_exhaustive]
    InvalidResponse,
    #[non_exhaustive]
    InvalidRequest,
    #[non_exhaustive]
    ErrorResponse { status: StatusCode },
}
impl Error for FetchJwksErrorKind {}
impl fmt::Display for FetchJwksErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchJwksErrorKind::CouldNotConnect => write!(f, "failed to connect"),
            FetchJwksErrorKind::InvalidResponse => write!(f, "invalid response"),
            FetchJwksErrorKind::InvalidRequest => write!(f, "invalid request"),
            FetchJwksErrorKind::ErrorResponse { status } => {
                write!(f, "response has error status: {status}")
            }
        }
    }
}
impl From<reqwest::Error> for FetchJwksError {
    fn from(value: reqwest::Error) -> Self {
        let kind = if value.is_body() || value.is_decode() {
            FetchJwksErrorKind::InvalidResponse
        } else if value.is_builder() || value.is_request() {
            FetchJwksErrorKind::InvalidRequest
        } else if value.is_connect() || value.is_timeout() || value.is_redirect() {
            FetchJwksErrorKind::CouldNotConnect
        } else if value.is_status() {
            let status = value.status().unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            FetchJwksErrorKind::ErrorResponse { status }
        } else {
            FetchJwksErrorKind::InvalidResponse
        };

        Self {
            source: value,
            kind,
        }
    }
}
