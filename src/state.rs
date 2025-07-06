use core::str::FromStr;

use http::header::{HeaderMap, HeaderName, HeaderValue, InvalidHeaderName, InvalidHeaderValue};
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Trait for if some state has an HTTP client.
pub trait HasHttpClient {
    /// Return the HTTP client
    fn http_client(&self) -> &Client;
}

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The config for an HTTP client.
pub struct HttpClientConfig {
    api_key_header: String,
    api_key: String,
}
impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            api_key_header: "X-TS-API-Key".to_string(),
            api_key: "some-api-key".to_string(),
        }
    }
}
impl HttpClientConfig {
    /// Create an HTTP client from the config.
    pub fn http_client(&self) -> Result<Client, CreateHttpClientError> {
        let mut header_map = HeaderMap::new();

        let api_key = HeaderValue::from_str(&self.api_key).map_err(|source| {
            CreateHttpClientError::invalid_header_value(source, self.api_key.clone())
        })?;
        let api_key_header_name = HeaderName::from_str(&self.api_key_header).map_err(|source| {
            CreateHttpClientError::invalid_header_name(source, self.api_key_header.clone())
        })?;
        header_map.insert(api_key_header_name, api_key);

        Client::builder()
            .default_headers(header_map)
            .build()
            .map_err(CreateHttpClientError::build_client)
    }
}

/// Error variants for creating an HTTP client.
#[derive(Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum CreateHttpClientError {
    #[non_exhaustive]
    InvalidHeaderValue {
        source: InvalidHeaderValue,
        value: String,
    },

    #[non_exhaustive]
    InvalidHeaderName {
        source: InvalidHeaderName,
        name: String,
    },

    #[non_exhaustive]
    BuildClient { source: reqwest::Error },
}
impl core::fmt::Display for CreateHttpClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self {
            Self::InvalidHeaderValue { value, .. } => {
                write!(f, "`{value}` is not a valid header value")
            }
            Self::BuildClient { .. } => write!(f, "could not build the HTTP client"),
            Self::InvalidHeaderName { name, .. } => {
                write!(f, "`{name}` is not a valid header name")
            }
        }
    }
}
impl core::error::Error for CreateHttpClientError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self {
            Self::InvalidHeaderValue { source, .. } => Some(source),
            Self::InvalidHeaderName { source, .. } => Some(source),
            Self::BuildClient { source, .. } => Some(source),
        }
    }
}
impl CreateHttpClientError {
    #[allow(missing_docs)]
    pub fn invalid_header_value(source: InvalidHeaderValue, value: String) -> Self {
        Self::InvalidHeaderValue { source, value }
    }

    #[allow(missing_docs)]
    pub fn build_client(source: reqwest::Error) -> Self {
        Self::BuildClient { source }
    }

    #[allow(missing_docs)]
    pub fn invalid_header_name(source: InvalidHeaderName, name: String) -> Self {
        Self::InvalidHeaderName { source, name }
    }
}
