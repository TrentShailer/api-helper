use core::{fmt, num::TryFromIntError, time::Duration};

use jsonwebtoken::{Algorithm, EncodingKey, Header, errors::ErrorKind};

use crate::Claims;

#[derive(Clone)]
pub struct JwtEncoder {
    pub kid: String,
    pub encoding_key: EncodingKey,
    pub algorithm: Algorithm,
    pub issuer: String,
    pub expires_in_seconds: u64,
}

impl JwtEncoder {
    pub fn encode(&self, subject: String) -> Result<String, EncodeJwtError> {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());

        let exp = (jiff::Timestamp::now() + Duration::from_secs(self.expires_in_seconds))
            .as_millisecond()
            .try_into()
            .map_err(|source| EncodeJwtError {
                kind: EncodeJwtErrorKind::InvalidTime {
                    source,
                    claim: "exp",
                },
            })?;

        let nbf = (jiff::Timestamp::now() - Duration::from_secs(60 * 15))
            .as_millisecond()
            .try_into()
            .map_err(|source| EncodeJwtError {
                kind: EncodeJwtErrorKind::InvalidTime {
                    source,
                    claim: "nbf",
                },
            })?;

        let iat = jiff::Timestamp::now()
            .as_millisecond()
            .try_into()
            .map_err(|source| EncodeJwtError {
                kind: EncodeJwtErrorKind::InvalidTime {
                    source,
                    claim: "iat",
                },
            })?;

        let claims = Claims {
            exp,
            iss: self.issuer.clone(),
            iat,
            nbf,
            sub: subject,
        };

        jsonwebtoken::encode(&header, &claims, &self.encoding_key).map_err(EncodeJwtError::from)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct EncodeJwtError {
    pub kind: EncodeJwtErrorKind,
}
impl fmt::Display for EncodeJwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to encode JWT")
    }
}
impl core::error::Error for EncodeJwtError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.kind)
    }
}
impl From<jsonwebtoken::errors::Error> for EncodeJwtError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        match value.kind() {
            ErrorKind::InvalidEcdsaKey
            | ErrorKind::InvalidRsaKey(_)
            | ErrorKind::RsaFailedSigning
            | ErrorKind::InvalidKeyFormat
            | ErrorKind::InvalidAlgorithm => Self {
                kind: EncodeJwtErrorKind::InvalidKey { source: value },
            },

            ErrorKind::Json(_) | ErrorKind::Utf8(_) | ErrorKind::Crypto(_) => Self {
                kind: EncodeJwtErrorKind::EncodingError { source: value },
            },
            //
            _ => Self {
                kind: EncodeJwtErrorKind::UnexpectedError { source: value },
            },
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum EncodeJwtErrorKind {
    #[non_exhaustive]
    InvalidKey { source: jsonwebtoken::errors::Error },

    #[non_exhaustive]
    EncodingError { source: jsonwebtoken::errors::Error },

    #[non_exhaustive]
    UnexpectedError { source: jsonwebtoken::errors::Error },

    #[non_exhaustive]
    InvalidTime {
        source: TryFromIntError,
        claim: &'static str,
    },
}
impl fmt::Display for EncodeJwtErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::EncodingError { .. } => write!(f, "failed to encode JWT"),
            Self::InvalidKey { .. } => write!(f, "key used to encode JWT is invalid"),
            Self::UnexpectedError { .. } => write!(f, "unexpected failure"),
            Self::InvalidTime { claim, .. } => write!(f, "claim '{claim}' had invalid time"),
        }
    }
}
impl core::error::Error for EncodeJwtErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            Self::InvalidKey { source }
            | Self::EncodingError { source }
            | Self::UnexpectedError { source } => Some(source),
            Self::InvalidTime { source, .. } => Some(source),
        }
    }
}
