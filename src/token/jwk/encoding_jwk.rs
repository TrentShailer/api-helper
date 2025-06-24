use core::{error::Error, fmt};

use openssl::pkey::{Id, PKey, Private};

use crate::token::{
    DecodingJwk, Jwk,
    jwk::{JwkParameters, decoding_jwk},
};

pub struct EncodingJwk {
    pub jwk: Jwk,
    pub key: PKey<Private>,
}

impl EncodingJwk {
    pub fn try_from_pem(jwk: Jwk, pem: &[u8]) -> Result<Self, FromPemError> {
        let private_key = PKey::private_key_from_pem(pem)
            .map_err(|source| FromPemError::PemToPrivateKey { source })?;

        // Validate private key for this JWK
        match jwk.parameters {
            JwkParameters::EC { .. } => {
                let id = private_key.id();
                if id != Id::EC {
                    return Err(FromPemError::PemJwkMismatch {
                        kind: MismatchKind::Id {
                            expected: Id::EC,
                            real: id,
                        },
                    });
                }

                let decoding_jwk = DecodingJwk::try_from(jwk.clone())
                    .map_err(|source| FromPemError::InvalidJwk { source })?;

                if !private_key.public_eq(&decoding_jwk.key) {
                    return Err(FromPemError::PemJwkMismatch {
                        kind: MismatchKind::PublicKey,
                    });
                }
            }
        }

        Ok(Self {
            jwk,
            key: private_key,
        })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum FromPemError {
    #[non_exhaustive]
    PemToPrivateKey { source: openssl::error::ErrorStack },

    #[non_exhaustive]
    InvalidJwk { source: decoding_jwk::FromJwkError },

    #[non_exhaustive]
    PemJwkMismatch { kind: MismatchKind },
}
impl fmt::Display for FromPemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::PemToPrivateKey { .. } => {
                write!(f, "PEM could not be converted to a private key")
            }
            Self::InvalidJwk { .. } => write!(f, "JWK is invalid"),
            Self::PemJwkMismatch { .. } => write!(f, "PEM does not match JWK"),
        }
    }
}
impl Error for FromPemError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::PemToPrivateKey { source, .. } => Some(source),
            Self::InvalidJwk { source, .. } => Some(source),
            Self::PemJwkMismatch { kind, .. } => Some(kind),
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum MismatchKind {
    #[non_exhaustive]
    Id { expected: Id, real: Id },

    #[non_exhaustive]
    PublicKey,
}
impl fmt::Display for MismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Id { expected, real, .. } => {
                write!(
                    f,
                    "the `typ` ({expected:?}) does not match the key ({real:?})"
                )
            }
            Self::PublicKey { .. } => {
                write!(f, "the public key from the JWK is not for this private key")
            }
        }
    }
}
impl Error for MismatchKind {}
