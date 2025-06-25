//! Extractor for extracting and verifying the JWT token from the request.
use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};

use crate::{
    ErrorResponse, InternalServerError,
    token::{JsonWebKeySetCache, JsonWebToken, json_web_token::Header},
};

/// Marker trait for if some state has a JSON web key set cache.
pub trait HasKeySetCache {
    /// Get the JSON web key set cache.
    fn jwks_cache(&self) -> &JsonWebKeySetCache;
}

/// Extractor for extracting and verifying the JSON web token token from the request.
pub struct Token(pub JsonWebToken);

impl<S> OptionalFromRequestParts<S> for Token
where
    S: Send + Sync + HasKeySetCache,
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
    S: Send + Sync + HasKeySetCache,
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

        let (header, _) = token
            .split_once('.')
            .ok_or_else(ErrorResponse::unauthenticated)?;
        let header = Header::decode(header).map_err(|_| ErrorResponse::unauthenticated())?;

        let cache_contains_key = {
            let cache_lock = state.jwks_cache().cache.read().await;
            cache_lock.contains_key(&header.kid)
        };

        if !cache_contains_key {
            state.jwks_cache().refresh().await.internal_server_error()?;
        }

        let cache_lock = state.jwks_cache().cache.read().await;
        let decoding_jwk = cache_lock
            .get(&header.kid)
            .ok_or_else(ErrorResponse::unauthenticated)?;

        let jwt = decoding_jwk
            .jwk
            .alg
            .verify(token, &decoding_jwk.key)
            .internal_server_error()?
            .ok_or_else(ErrorResponse::unauthenticated)?;

        Ok(Self(jwt))
    }
}
