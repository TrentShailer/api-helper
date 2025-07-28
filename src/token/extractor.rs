//! Extractor for extracting and verifying the JWT token from the request.
use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use http::{StatusCode, request::Parts};

use crate::{
    ErrorResponse, HasHttpClient, InlineErrorResponse,
    token::{JsonWebKeySetCache, JsonWebToken},
};

/// Marker trait for if some state has a JSON web key set cache.
pub trait HasKeySetCache {
    /// Get the JSON web key set cache.
    fn jwks_cache(&self) -> &JsonWebKeySetCache;
}

/// Marker trait for if some state has a token revocation endpoint.
pub trait HasRevocationEndpoint {
    /// The endpoint to check if a token has been revoked.
    /// Will have `/{jwt.claims.tid}` appended to it.
    fn revocation_endpoint(&self) -> &str;
}

/// Extractor for extracting and verifying the JSON web token token from the request.
pub struct Token(pub JsonWebToken);

impl<S> OptionalFromRequestParts<S> for Token
where
    S: Send + Sync + HasKeySetCache + HasRevocationEndpoint + HasHttpClient,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match parts.headers.get("Authorization") {
            Some(_) => <Self as FromRequestParts<S>>::from_request_parts(parts, state)
                .await
                .map(Some),
            None => Ok(None),
        }
    }
}

impl<S> FromRequestParts<S> for Token
where
    S: Send + Sync + HasKeySetCache + HasRevocationEndpoint + HasHttpClient,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("Authorization")
            .ok_or_else(ErrorResponse::unauthenticated)?
            .to_str()
            .map_err(|_| ErrorResponse::unauthenticated())?;

        if !header.starts_with("bearer ") {
            return Err(ErrorResponse::unauthenticated());
        }

        let token = &header[7..];

        let token =
            JsonWebToken::deserialize(token).ok_or_else(|| ErrorResponse::unauthenticated())?;

        let cache_contains_key = {
            let cache_lock = state.jwks_cache().cache.read().await;
            cache_lock.contains_key(&token.header.kid)
        };

        if !cache_contains_key {
            state
                .jwks_cache()
                .refresh(state.http_client())
                .await
                .internal_server_error()?;
        }

        let cache_lock = state.jwks_cache().cache.read().await;
        let decoding_jwk = cache_lock
            .get(&token.header.kid)
            .ok_or_else(ErrorResponse::unauthenticated)?;

        if !decoding_jwk.verify(&token).internal_server_error()? {
            return Err(ErrorResponse::unauthenticated());
        }

        if token.claims.is_expired() {
            return Err(ErrorResponse::unauthenticated());
        }

        let is_revoked = {
            let endpoint = format!("{}/{}", state.revocation_endpoint(), token.claims.tid);

            let status = state
                .http_client()
                .get(&endpoint)
                .send()
                .await
                .internal_server_error()?
                .status();

            match status {
                StatusCode::NOT_FOUND => false,
                StatusCode::OK => true,
                status => {
                    log::error!("received status {status} from revocation endpoint");
                    return Err(ErrorResponse::internal_server_error());
                }
            }
        };

        if is_revoked {
            return Err(ErrorResponse::unauthenticated());
        }

        Ok(Self(token))
    }
}
