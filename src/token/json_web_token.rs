//! A decoded JSON web token.
use core::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::token::algorithm::Algorithm;

/// A decoded JSON web token.
#[derive(Debug)]
pub struct JsonWebToken {
    /// The JWT header.
    pub header: Header,
    /// The JWT claims.
    pub claims: Claims,
}

/// The JWT header.
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    /// The expiry of the JSON web token.
    #[serde(with = "serde_msec")]
    pub exp: Timestamp,
    /// The party that issued the JSON web token.
    pub iss: String,
    /// The time when the JSON web token was issued.
    #[serde(with = "serde_msec")]
    pub iat: Timestamp,
    /// The time the JSON web token is valid from.
    #[serde(with = "serde_msec")]
    pub nbf: Timestamp,
    /// The subject of the token.
    pub sub: String,
    /// The audience for the token.
    pub aud: String,
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

    /// Check if the claims are still valid. This checks:
    /// * It is not expired.
    /// * It is not premature.
    /// * It was issued by a trusted issuer.
    /// * It was given by the intended audience.
    pub fn is_valid(&self, trusted_issuers: &[String], audience: &str) -> ClaimsValidationResult {
        let now = Timestamp::now();

        if self.exp < now {
            return ClaimsValidationResult::Expired;
        }

        if self.nbf > now {
            return ClaimsValidationResult::Premature;
        }

        if !trusted_issuers.contains(&self.iss) {
            return ClaimsValidationResult::Untrusted;
        }

        if self.aud != audience {
            return ClaimsValidationResult::WrongAudience;
        }

        ClaimsValidationResult::Valid
    }
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
/// The result of validating the claims.
pub enum ClaimsValidationResult {
    /// The claims are all valid.
    Valid,
    /// The token is expired.
    Expired,
    /// The token is premature.
    Premature,
    /// The token not issued by a trusted issuer.
    Untrusted,
    /// The token was given by the wrong audience.
    WrongAudience,
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

mod serde_msec {
    use jiff::Timestamp;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(value.as_millisecond())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Timestamp, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: i64 = Deserialize::deserialize(deserializer)?;

        Timestamp::from_millisecond(value)
            .map_err(|_| de::Error::custom(format!("{value} does not fit in a `jiff::Timestamp`")))
    }
}
