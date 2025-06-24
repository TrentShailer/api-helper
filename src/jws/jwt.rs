use core::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::jws::algorithm::Algorithm;

#[derive(Debug)]
pub struct Jwt {
    pub header: Header,
    pub claims: Claims,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Header {
    pub alg: Algorithm,
    pub typ: String,
    pub kid: String,
}

impl Header {
    pub fn encode(&self) -> Result<String, EncodeError> {
        let json = serde_json::to_string(&self)?;
        Ok(Base64UrlUnpadded::encode_string(json.as_bytes()))
    }

    pub fn decode(value: &str) -> Result<Self, DecodeError> {
        let bytes = Base64UrlUnpadded::decode_vec(value)?;

        let header = serde_json::from_slice(&bytes)?;

        Ok(header)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    #[serde(with = "serde_msec")]
    pub exp: Timestamp,
    pub iss: String,
    #[serde(with = "serde_msec")]
    pub iat: Timestamp,
    #[serde(with = "serde_msec")]
    pub nbf: Timestamp,
    pub sub: String,
    pub aud: String,
}

impl Claims {
    pub fn encode(&self) -> Result<String, EncodeError> {
        let json = serde_json::to_string(&self)?;
        Ok(Base64UrlUnpadded::encode_string(json.as_bytes()))
    }

    pub fn decode(value: &str) -> Result<Self, DecodeError> {
        let bytes = Base64UrlUnpadded::decode_vec(value)?;

        let header = serde_json::from_slice(&bytes)?;

        Ok(header)
    }

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

#[derive(Debug)]
#[non_exhaustive]
pub enum ClaimsValidationResult {
    Valid,
    Expired,
    Premature,
    Untrusted,
    WrongAudience,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    #[non_exhaustive]
    JsonDeserialize { source: serde_json::Error },

    #[non_exhaustive]
    Base64Decode { source: base64ct::Error },
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

#[derive(Debug)]
#[non_exhaustive]
pub enum EncodeError {
    #[non_exhaustive]
    JsonSerialize { source: serde_json::Error },
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
    use serde::{
        Deserializer, Serializer,
        de::{self, Visitor},
    };

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
        struct I64Visitor;
        impl<'de> Visitor<'de> for I64Visitor {
            type Value = i64;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer between -2^63 and 2^63")
            }

            fn visit_i8<E>(self, value: i8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(i64::from(value))
            }

            fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(i64::from(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(value)
            }

            fn visit_u8<E>(self, value: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(i64::from(value))
            }

            fn visit_u16<E>(self, value: u16) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(i64::from(value))
            }

            fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(i64::from(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                i64::try_from(value)
                    .map_err(|_| E::custom(format!("{value} does not fit in an `i64`")))
            }
        }

        let value = deserializer.deserialize_i64(I64Visitor)?;

        Timestamp::from_millisecond(value)
            .map_err(|_| de::Error::custom(format!("{value} does not fit in a `jiff::Timestamp`")))
    }
}
