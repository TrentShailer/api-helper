use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};

use crate::{
    ErrorResponse, InternalServerError,
    token::{JwkCache, Jwt, jwt::Header},
};

pub trait HasJwksCache {
    fn jwks_cache(&self) -> &JwkCache;
}

pub struct Token(pub Jwt);

impl<S> OptionalFromRequestParts<S> for Token
where
    S: Send + Sync + HasJwksCache,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match parts.headers.get("Authorization") {
            Some(_) => {
                <Self as axum::extract::FromRequestParts<S>>::from_request_parts(parts, state)
                    .await
                    .map(Some)
            }
            None => Ok(None),
        }
    }
}

impl<S> FromRequestParts<S> for Token
where
    S: Send + Sync + HasJwksCache,
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

        Ok(Token(jwt))
    }
}
