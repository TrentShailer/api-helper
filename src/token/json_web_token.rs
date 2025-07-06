//! A decoded JSON web token.
use core::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A decoded JSON web token.
#[derive(Debug, Clone)]
pub struct JsonWebToken {
    /// The JWT header.
    pub header: Header,
    /// The JWT claims.
    pub claims: Claims,
}

/// The JWT header.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Header {
    /// The algorithm used to sign the JSON web token.
    pub alg: Algorithm,
    /// The type of algorithm used to sign the JSON web token.
    pub typ: String,
    /// The ID of the key used to sign the JSON web token.
    pub kid: String,
}

impl Header {
    /// Encode the JSON representation of the header as URL Base64.
    pub fn encode(&self) -> Result<String, EncodeError> {
        let json = serde_json::to_string(&self)?;
        Ok(Base64UrlUnpadded::encode_string(json.as_bytes()))
    }

    /// Decode the header from URL Base64 encoded JSON.
    pub fn decode(value: &str) -> Result<Self, DecodeError> {
        let bytes = Base64UrlUnpadded::decode_vec(value)?;

        let header = serde_json::from_slice(&bytes)?;

        Ok(header)
    }
}

/// The JSON web token claims.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    /// The ID of this specific token.
    pub tid: String,
    /// The expiry of the JSON web token.
    #[serde(with = "serde_sec")]
    pub exp: Timestamp,
    /// The time when the JSON web token was issued.
    #[serde(with = "serde_sec")]
    pub iat: Timestamp,
    /// The subject of the token.
    pub sub: String,
    /// The type of the token.
    #[serde(flatten)]
    pub typ: TokenType,
}

/// The type of token.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "typ")]
#[non_exhaustive]
pub enum TokenType {
    /// A common token that grants the bearer authorisation for common actions.
    Common,
    /// A consent token that grants the bearer authorisation to perform a specific action.
    Consent {
        /// The action the bearer is authorised to perform.
        act: String,
    },
    /// A token to granted when provisioning a new identity before any credentials have been added.
    Provisioning,
}

/// Algorithms supported by this implementation.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[non_exhaustive]
pub enum Algorithm {
    /// ES256 algorithm.
    ES256,
}

impl Claims {
    /// Encode the JSON representation of the claims as URL base64.
    pub fn encode(&self) -> Result<String, EncodeError> {
        let json = serde_json::to_string(&self)?;
        Ok(Base64UrlUnpadded::encode_string(json.as_bytes()))
    }

    /// Decode the claims from URL base64 encoded JSON.
    pub fn decode(value: &str) -> Result<Self, DecodeError> {
        let bytes = Base64UrlUnpadded::decode_vec(value)?;

        let header = serde_json::from_slice(&bytes)?;

        Ok(header)
    }

    /// Returns if the token is expired.
    pub fn is_expired(&self) -> bool {
        let now = Timestamp::now();
        self.exp < now
    }
}

/// Error variants for decoding claims/headers.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// The decoded JSON string could not be deserialized to the target type.
    #[non_exhaustive]
    JsonDeserialize {
        /// The source of this error.
        source: serde_json::Error,
    },

    /// The Base64 could not be decoded.
    #[non_exhaustive]
    Base64Decode {
        /// The source of this error.
        source: base64ct::Error,
    },
}
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::JsonDeserialize { .. } => write!(f, "decoded JSON is invalid"),
            Self::Base64Decode { .. } => write!(f, "value is invalid base64"),
        }
    }
}
impl Error for DecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::JsonDeserialize { source, .. } => Some(source),
            Self::Base64Decode { source, .. } => Some(source),
        }
    }
}
impl From<serde_json::Error> for DecodeError {
    fn from(source: serde_json::Error) -> Self {
        Self::JsonDeserialize { source }
    }
}
impl From<base64ct::Error> for DecodeError {
    fn from(source: base64ct::Error) -> Self {
        Self::Base64Decode { source }
    }
}

/// Error variants for encoding a header/claims.
#[derive(Debug)]
#[non_exhaustive]
pub enum EncodeError {
    /// The value failed to be serialized to JSON.
    #[non_exhaustive]
    JsonSerialize {
        /// The source of the error.
        source: serde_json::Error,
    },
}
impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::JsonSerialize { .. } => write!(f, "value could not be serialized to JSON"),
        }
    }
}
impl Error for EncodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::JsonSerialize { source, .. } => Some(source),
        }
    }
}
impl From<serde_json::Error> for EncodeError {
    fn from(source: serde_json::Error) -> Self {
        Self::JsonSerialize { source }
    }
}

mod serde_sec {
    use jiff::Timestamp;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(value.as_second())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: i64 = Deserialize::deserialize(deserializer)?;

        Timestamp::from_second(value)
            .map_err(|_| de::Error::custom(format!("{value} does not fit in a `jiff::Timestamp`")))
    }
}
