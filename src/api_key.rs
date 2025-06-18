use axum::{extract::FromRequestParts, http::request::Parts};

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
            .ok_or_else(ErrorResponse::unuathenticated)?
            .to_str()
            .map_err(|_| ErrorResponse::unuathenticated())?
            .to_owned();

        if !config.allowed_api_keys.contains(&header) {
            return Err(ErrorResponse::unuathenticated());
        }

        Ok(ApiKey(header))
    }
}
