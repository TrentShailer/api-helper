//! A JSON web key used to sign a JSON web token.
use core::{error::Error, fmt, time::Duration};

use jiff::Timestamp;
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    sign::Signer,
};
use uuid::Uuid;

use crate::token::{
    Algorithm, JsonWebKey, JsonWebToken, VerifyingJsonWebKey,
    json_web_key::{JsonWebKeyParameters, verifying},
    json_web_token::{Claims, Header, TokenType},
};

/// A JSON web key used to sign a JSON web token.
#[derive(Debug)]
pub struct SigningJsonWebKey {
    /// The JSON web key.
    pub jwk: JsonWebKey,
    /// The private key.
    pub key: PKey<Private>,
}

impl SigningJsonWebKey {
    /// Try create an encoding JSON web key from a JSON web key and a PEM encoded private key.
    pub fn try_from_pem(jwk: JsonWebKey, pem: &[u8]) -> Result<Self, FromPemError> {
        let private_key = PKey::private_key_from_pem(pem)
            .map_err(|source| FromPemError::PemToPrivateKey { source })?;

        // Validate private key for this JSON web key
        match jwk.parameters {
            JsonWebKeyParameters::EC { .. } => {
                let id = private_key.id();
                if id != Id::EC {
                    return Err(FromPemError::PemJwkMismatch {
                        kind: MismatchKind::Id {
                            expected: Id::EC,
                            real: id,
                        },
                    });
                }

                let decoding_jwk = VerifyingJsonWebKey::try_from(jwk.clone())
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

    /// Issue a new token of the given type for a subject.
    pub fn issue(
        &self,
        subject: String,
        token_type: TokenType,
    ) -> Result<JsonWebToken, openssl::error::ErrorStack> {
        let exp = match token_type {
            TokenType::Common => Timestamp::now() + Duration::from_secs(60 * 60 * 24 * 30),
            TokenType::Consent { .. } => Timestamp::now() + Duration::from_secs(60 * 5),
            TokenType::Provisioning => Timestamp::now() + Duration::from_secs(60 * 60 * 4),
        };

        let header = Header {
            alg: self.jwk.alg.clone(),
            typ: "JWT".to_string(),
            kid: self.jwk.kid.clone(),
        };
        let claims = Claims {
            tid: Uuid::new_v4().to_string(),
            exp,
            iat: Timestamp::now(),
            sub: subject,
            typ: token_type,
        };

        let mut signer = match self.jwk.alg {
            Algorithm::ES256 => Signer::new(MessageDigest::sha256(), &self.key)?,
        };

        let contents = format!("{}.{}", header.encode(), claims.encode());

        let mut signature_buffer = vec![0u8; signer.len()?];
        let signature_size = signer.sign_oneshot(&mut signature_buffer, contents.as_bytes())?;

        let token = JsonWebToken {
            header,
            claims,
            signature: signature_buffer[..signature_size].to_vec(),
        };

        Ok(token)
    }
}

/// Error variants for creating an Encoding JSON web key from a PEM file.
#[derive(Debug)]
#[non_exhaustive]
pub enum FromPemError {
    /// The PEM to private key conversion failed.
    #[non_exhaustive]
    PemToPrivateKey {
        /// The source of the failure.
        source: openssl::error::ErrorStack,
    },

    /// The JSON web key is not valid.
    #[non_exhaustive]
    InvalidJwk {
        /// The source of the error.
        source: verifying::FromJwkError,
    },

    /// The PEM is not the private key for the JSON web key.
    #[non_exhaustive]
    PemJwkMismatch {
        /// What was mismatched.
        kind: MismatchKind,
    },
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

/// The properties that can be mismatched between the PEM and the JSON web key.
#[derive(Debug)]
#[non_exhaustive]
pub enum MismatchKind {
    /// The IDs don't match.
    #[non_exhaustive]
    Id {
        /// The expected ID from the JSON web key.
        expected: Id,
        /// The real ID from the PEM file.
        real: Id,
    },

    /// The public key from the JSON web key does not match the PEM private key.
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
