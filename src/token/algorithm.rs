use core::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use openssl::{
    hash::MessageDigest,
    pkey::{HasPrivate, HasPublic, PKey},
    sign::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};

use crate::token::jwt::{Claims, DecodeError, EncodeError, Header, Jwt};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Algorithm {
    ES256,
}

impl Algorithm {
    pub fn sign<T: HasPrivate>(
        &self,
        jwt: &Jwt,
        private_key: &PKey<T>,
    ) -> Result<String, SingingError> {
        let mut signer = match self {
            Self::ES256 => Signer::new(MessageDigest::sha256(), private_key).map_err(|source| {
                SingingError::SignerOperation {
                    source,
                    operation: "create",
                }
            })?,
        };

        let contents = format!(
            "{}.{}",
            jwt.header
                .encode()
                .map_err(|source| SingingError::EncodeHeader { source })?,
            jwt.claims
                .encode()
                .map_err(|source| SingingError::EncodeClaims { source })?,
        );

        signer
            .update(contents.as_bytes())
            .map_err(|source| SingingError::SignerOperation {
                source,
                operation: "update",
            })?;

        let mut signature_buffer = vec![
            0u8;
            signer.len().map_err(|source| {
                SingingError::SignerOperation {
                    source,
                    operation: "length",
                }
            })?
        ];

        let signature_size = signer
            .sign_oneshot(&mut signature_buffer, contents.as_bytes())
            .map_err(|source| SingingError::SignerOperation {
                source,
                operation: "sign",
            })?;

        let signature = Base64UrlUnpadded::encode_string(&signature_buffer[..signature_size]);

        Ok(signature)
    }

    pub fn verify<T: HasPublic>(
        &self,
        token: &str,
        public_key: &PKey<T>,
    ) -> Result<Option<Jwt>, VerifyError> {
        let mut verifier = match self {
            Self::ES256 => {
                Verifier::new(MessageDigest::sha256(), public_key).map_err(|source| {
                    VerifyError::VerifierOperation {
                        source,
                        operation: "create",
                    }
                })?
            }
        };

        let (contents, signature) = token
            .rsplit_once('.')
            .ok_or_else(|| VerifyError::InvalidFormat)?;

        let is_valid = verifier
            .verify_oneshot(signature.as_bytes(), contents.as_bytes())
            .map_err(|source| VerifyError::VerifierOperation {
                source,
                operation: "verify",
            })?;

        if !is_valid {
            return Ok(None);
        }

        let (header, claims) = contents
            .split_once('.')
            .ok_or_else(|| VerifyError::InvalidFormat)?;

        let header =
            Header::decode(header).map_err(|source| VerifyError::DecodeHeader { source })?;
        let claims =
            Claims::decode(claims).map_err(|source| VerifyError::DecodeClaims { source })?;

        Ok(Some(Jwt { header, claims }))
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum SingingError {
    #[non_exhaustive]
    SignerOperation {
        source: openssl::error::ErrorStack,
        operation: &'static str,
    },

    #[non_exhaustive]
    EncodeHeader { source: EncodeError },

    #[non_exhaustive]
    EncodeClaims { source: EncodeError },
}
impl fmt::Display for SingingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::SignerOperation { operation, .. } => {
                write!(f, "OpenSSL signer {operation} operation failed")
            }
            Self::EncodeHeader { .. } => write!(f, "JWT header could not be encoded"),
            Self::EncodeClaims { .. } => write!(f, "JWT claims could not be encoded"),
        }
    }
}
impl Error for SingingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::SignerOperation { source, .. } => Some(source),
            Self::EncodeHeader { source, .. } => Some(source),
            Self::EncodeClaims { source, .. } => Some(source),
        }
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum VerifyError {
    #[non_exhaustive]
    VerifierOperation {
        source: openssl::error::ErrorStack,
        operation: &'static str,
    },

    #[non_exhaustive]
    DecodeHeader { source: DecodeError },

    #[non_exhaustive]
    DecodeClaims { source: DecodeError },

    #[non_exhaustive]
    InvalidFormat,
}
impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::VerifierOperation { operation, .. } => {
                write!(f, "OpenSSL verifier {operation} operation failed")
            }
            Self::DecodeHeader { .. } => write!(f, "JWT header could not be decoded"),
            Self::DecodeClaims { .. } => write!(f, "JWT claims could not be decoded"),
            Self::InvalidFormat { .. } => write!(f, "token is not a valid JWS string"),
        }
    }
}
impl Error for VerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::VerifierOperation { source, .. } => Some(source),
            Self::DecodeHeader { source, .. } => Some(source),
            Self::DecodeClaims { source, .. } => Some(source),
            _ => None,
        }
    }
}
