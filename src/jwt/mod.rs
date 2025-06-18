mod claims;
mod encoder;
mod jwks;

use core::str::FromStr;
use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use jsonwebtoken::{Algorithm, TokenData, Validation};
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

use crate::{ErrorResponse, Problem, ReportUnexpected};

pub use claims::Claims;
pub use encoder::{EncodeJwtError, EncodeJwtErrorKind, JwtEncoder};
pub use jwks::{FetchJwksError, FetchJwksErrorKind, GetJwkError, GetJwkErrorKind, Jwks};

pub trait JwksState {
    fn jwks(&self) -> Arc<Mutex<Jwks>>;
}

pub struct Jwt<T: DeserializeOwned>(pub TokenData<T>);

impl<S, T> FromRequestParts<S> for Jwt<T>
where
    S: Send + Sync + JwksState,
    T: DeserializeOwned,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("Authorization")
            .ok_or_else(ErrorResponse::unuathenticated)?;

        let header = header.to_str().map_err(|_| {
            ErrorResponse::single(
                StatusCode::BAD_REQUEST,
                Problem::new("invalid-header", "The request contained an invalid header.")
                    .pointer("$.Authorization"),
            )
        })?;

        if !header.starts_with("bearer ") {
            return Err(ErrorResponse::single(
                StatusCode::BAD_REQUEST,
                Problem::new("invalid-header", "The request contained an invalid header.")
                    .pointer("$.Authorization"),
            ));
        }

        let token = &header[7..];

        let header =
            jsonwebtoken::decode_header(token).map_err(|_| ErrorResponse::unuathenticated())?;
        let kid = header.kid.ok_or_else(ErrorResponse::unuathenticated)?;

        let jwks_mutex = state.jwks();
        let mut jwks = jwks_mutex.lock().await;

        let (jwk, decoding_key) = jwks
            .try_get_jwk(&kid)
            .await
            .report_error("could not get jwk")
            .map_err(|_| ErrorResponse::server_error())?
            .ok_or_else(ErrorResponse::unuathenticated)?;

        let algorithm =
            Algorithm::from_str(&jwk.common.key_algorithm.unwrap().to_string()).unwrap(); // Guaranteed by JWKS `is_supported`.

        let mut validation = Validation::new(algorithm);
        validation.set_required_spec_claims(&["exp", "nbf", "sub"]);
        validation.validate_nbf = true;
        validation.validate_exp = true;

        let token = jsonwebtoken::decode::<T>(token, decoding_key, &validation)
            .map_err(|_| ErrorResponse::unuathenticated())?;

        Ok(Jwt(token))
    }
}
