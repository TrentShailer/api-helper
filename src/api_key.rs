use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};

use crate::ErrorResponse;

pub struct ApiKey(pub String);

#[derive(Clone)]
pub struct ApiKeyConfig {
    pub allowed_api_keys: Vec<String>,
    pub header: String,
}

pub trait ApiKeyState {
    fn api_key_config(&self) -> &ApiKeyConfig;
}

impl<S> OptionalFromRequestParts<S> for ApiKey
where
    S: Send + Sync + ApiKeyState,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let config = state.api_key_config();

        match parts.headers.get(&config.header) {
            Some(_) => {
                <Self as axum::extract::FromRequestParts<S>>::from_request_parts(parts, state)
                    .await
                    .map(Some)
            }
            None => Ok(None),
        }
    }
}

impl<S> FromRequestParts<S> for ApiKey
where
    S: Send + Sync + ApiKeyState,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = state.api_key_config();

        let header = parts
            .headers
            .get(&config.header)
            .ok_or_else(ErrorResponse::unauthenticated)?
            .to_str()
            .map_err(|_| ErrorResponse::unauthenticated())?
            .to_owned();

        if !config.allowed_api_keys.contains(&header) {
            return Err(ErrorResponse::unauthenticated());
        }

        Ok(ApiKey(header))
    }
}
