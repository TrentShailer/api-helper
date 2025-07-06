use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use http::request::Parts;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ErrorResponse;

/// Extractor to validate the request's API key.
pub struct ApiKey(pub String);

/// Config for the trusted API keys.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyValidationConfig {
    /// List of trusted API keys.
    pub allowed_api_keys: Vec<String>,

    /// The header to look for the API keys in.
    pub header: String,
}
impl Default for ApiKeyValidationConfig {
    fn default() -> Self {
        Self {
            allowed_api_keys: Default::default(),
            header: "X-TS-API-Key".to_string(),
        }
    }
}

/// Mark that some State has an API config.
pub trait HasApiKeyValidationConfig {
    /// Get the API config.
    fn api_key_config(&self) -> &ApiKeyValidationConfig;
}

impl<S> OptionalFromRequestParts<S> for ApiKey
where
    S: Send + Sync + HasApiKeyValidationConfig,
{
    type Rejection = ErrorResponse;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let config = state.api_key_config();

        match parts.headers.get(&config.header) {
            Some(_) => <Self as FromRequestParts<S>>::from_request_parts(parts, state)
                .await
                .map(Some),
            None => Ok(None),
        }
    }
}

impl<S> FromRequestParts<S> for ApiKey
where
    S: Send + Sync + HasApiKeyValidationConfig,
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

        Ok(Self(header))
    }
}
