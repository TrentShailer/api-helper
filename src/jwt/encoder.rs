use core::fmt;

use jsonwebtoken::{Algorithm, EncodingKey, Header, errors::ErrorKind};
use serde::Serialize;

pub struct JwtEncoder {
    pub kid: String,
    pub encoding_key: EncodingKey,
    pub algorithm: Algorithm,
}

impl JwtEncoder {
    pub fn encode<T: Serialize>(&self, claims: T) -> Result<String, EncodeJwtError> {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());

        // TODO, add exp, nbf, iss, sub? aud?

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
}
impl fmt::Display for EncodeJwtErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::EncodingError { .. } => write!(f, "failed to encode JWT"),
            Self::InvalidKey { .. } => write!(f, "key used to encode JWT is invalid"),
            Self::UnexpectedError { .. } => write!(f, "unexpected failure"),
        }
    }
}
impl core::error::Error for EncodeJwtErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            EncodeJwtErrorKind::InvalidKey { source }
            | EncodeJwtErrorKind::EncodingError { source }
            | EncodeJwtErrorKind::UnexpectedError { source } => Some(source),
        }
    }
}
