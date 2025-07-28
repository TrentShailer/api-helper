//! A decoded JSON web token.

use base64ct::{Base64UrlUnpadded, Encoding};
use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A decoded JSON web token.
#[derive(Debug, Clone)]
pub struct JsonWebToken {
    /// The JSON web token header.
    pub header: Header,
    /// The JSON web token claims.
    pub claims: Claims,
    /// The JSON web token signature.
    pub signature: Vec<u8>,
}

impl JsonWebToken {
    /// Serialize the token as a JSON web token string.
    pub fn serialize(&self) -> String {
        let header = self.header.encode();
        let claims = self.claims.encode();
        let signature = Base64UrlUnpadded::encode_string(&self.signature);

        format!("{header}.{claims}.{signature}")
    }

    /// Deserialize the token from a JSON web token string.
    pub fn deserialize(value: &str) -> Option<Self> {
        let mut parts = value.split(".");
        let header = parts.next()?;
        let claims = parts.next()?;
        let signature = parts.next()?;

        let header = serde_json::from_slice(&Base64UrlUnpadded::decode_vec(header).ok()?).ok()?;
        let claims = serde_json::from_slice(&Base64UrlUnpadded::decode_vec(claims).ok()?).ok()?;
        let signature = Base64UrlUnpadded::decode_vec(signature).ok()?;

        Some(Self {
            header,
            claims,
            signature,
        })
    }
}

/// The JSON web token header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// The algorithm used to sign the JSON web token.
    pub alg: Algorithm,
    /// The type of algorithm used to sign the JSON web token.
    pub typ: String,
    /// The ID of the key used to sign the JSON web token.
    pub kid: String,
}

impl Header {
    /// Encode the JSON representation of the header as URL base-64.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(&self).expect("serializing the header should never fail");
        Base64UrlUnpadded::encode_string(&json)
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
    /// Encode the JSON representation of the claims as URL base-64.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(&self).expect("serializing the claims should never fail");
        Base64UrlUnpadded::encode_string(&json)
    }

    /// Returns if the token is expired.
    pub fn is_expired(&self) -> bool {
        let now = Timestamp::now();
        self.exp < now
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
