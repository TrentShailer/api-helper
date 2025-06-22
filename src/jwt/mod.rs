mod claims;
mod encoder;
mod jwks;

use core::str::FromStr;
use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use jsonwebtoken::{Algorithm, TokenData, Validation};
use tokio::sync::Mutex;

use crate::{ErrorResponse, InternalServerError};

pub use claims::Claims;
pub use encoder::{EncodeJwtError, EncodeJwtErrorKind, JwtEncoder};
pub use jwks::{FetchJwksError, FetchJwksErrorKind, GetJwkError, GetJwkErrorKind, Jwks};

pub trait JwksState {
    fn jwks(&self) -> Arc<Mutex<Jwks>>;
}

pub struct Jwt(pub TokenData<Claims>);

impl<S> OptionalFromRequestParts<S> for Jwt
where
    S: Send + Sync + JwksState,
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

impl<S> FromRequestParts<S> for Jwt
where
    S: Send + Sync + JwksState,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("Authorization")
            .ok_or_else(ErrorResponse::unauthenticated)?;

        let header = header
            .to_str()
            .map_err(|_| ErrorResponse::unauthenticated())?;

        if !header.starts_with("bearer ") {
            return Err(ErrorResponse::unauthenticated());
        }

        let token = &header[7..];

        let header =
            jsonwebtoken::decode_header(token).map_err(|_| ErrorResponse::unauthenticated())?;
        let kid = header.kid.ok_or_else(ErrorResponse::unauthenticated)?;

        let jwks_mutex = state.jwks();
        let mut jwks = jwks_mutex.lock().await;

        let (jwk, decoding_key) = jwks
            .try_get_jwk(&kid)
            .await
            .internal_server_error()?
            .ok_or_else(ErrorResponse::unauthenticated)?;

        let algorithm =
            Algorithm::from_str(&jwk.common.key_algorithm.unwrap().to_string()).unwrap(); // Guaranteed by JWKS `is_supported`.

        let mut validation = Validation::new(algorithm);
        validation.set_required_spec_claims(&["exp", "nbf", "sub"]);
        validation.validate_nbf = false; // Validation is done manually
        validation.validate_exp = false; // Validation is done manually

        let token = jsonwebtoken::decode::<Claims>(token, decoding_key, &validation)
            .map_err(|_| ErrorResponse::unauthenticated())?;

        // Validate NBF and exp
        let now: usize = jiff::Timestamp::now()
            .as_millisecond()
            .try_into()
            .internal_server_error()?;
        if token.claims.nbf > now + 1000 * 60 * 5 {
            return Err(ErrorResponse::unauthenticated());
        }
        if token.claims.exp < now - 1000 * 60 * 5 {
            return Err(ErrorResponse::unauthenticated());
        }

        Ok(Jwt(token))
    }
}
