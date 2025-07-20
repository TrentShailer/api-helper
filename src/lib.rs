//! Helpers for working with APIs

mod api_key;
mod base64;
mod cors;
mod json;
mod postgres;
mod problem;
mod state;
pub mod token;
pub mod webauthn;

pub use api_key::{ApiKey, ApiKeyValidationConfig, HasApiKeyValidationConfig};
pub use base64::{DecodeBase64, EncodeBase64, maybe_serde_url_base64, serde_url_base64};
pub use cors::cors_layer;
pub use json::Json;
pub use postgres::{ConnectionPool, SetupPostgresError, setup_connection_pool};
pub use problem::{ErrorResponse, InternalServerError, Problem};
pub use state::{CreateHttpClientError, HasHttpClient, HttpClientConfig};
