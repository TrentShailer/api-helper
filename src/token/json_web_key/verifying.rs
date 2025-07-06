//! A JWK used to verify a signed token.
use core::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use jiff::Timestamp;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public},
    sign::Verifier,
};

use crate::token::{
    Algorithm, JsonWebKey, JsonWebToken,
    json_web_key::{Curve, JsonWebKeyParameters},
    json_web_token::{Claims, DecodeError, Header},
};

/// A JSON web key used to verify a signed token.
#[derive(Debug)]
pub struct VerifyingJsonWebKey {
    /// The JSON web key.
    pub jwk: JsonWebKey,
    /// The time this JSON web key was retrieved from the JSON web key set.
    pub retrieved: Timestamp,
    /// The public key derived from the JSON web key.
    pub key: PKey<Public>,
}
impl VerifyingJsonWebKey {
    /// Verify a given token.
    pub fn verify(&self, token: &str) -> Result<Option<JsonWebToken>, VerifyError> {
        let mut verifier = match self.jwk.alg {
            Algorithm::ES256 => {
                Verifier::new(MessageDigest::sha256(), &self.key).map_err(|source| {
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

        let signature_bytes = Base64UrlUnpadded::decode_vec(signature)
            .map_err(|source| VerifyError::DecodeSignature { source })?;

        let is_valid = verifier
            .verify_oneshot(&signature_bytes, contents.as_bytes())
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

        Ok(Some(JsonWebToken { header, claims }))
    }
}
impl TryFrom<JsonWebKey> for VerifyingJsonWebKey {
    type Error = FromJwkError;

    fn try_from(jwk: JsonWebKey) -> Result<Self, Self::Error> {
        let key = match &jwk.parameters {
            JsonWebKeyParameters::EC { crv, x, y } => {
                let group = match crv {
                    Curve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
                        .map_err(|source| EcFromJwkError::GetEcGroup { source })?,
                };

                let x = Base64UrlUnpadded::decode_vec(x).map_err(|source| {
                    EcFromJwkError::Base64DecodeCoordinate {
                        source,
                        coordinate: "x",
                    }
                })?;
                let y = Base64UrlUnpadded::decode_vec(y).map_err(|source| {
                    EcFromJwkError::Base64DecodeCoordinate {
                        source,
                        coordinate: "y",
                    }
                })?;

                let x = BigNum::from_slice(&x).map_err(|source| {
                    EcFromJwkError::BigNumFromCoordinate {
                        source,
                        coordinate: "x",
                    }
                })?;
                let y = BigNum::from_slice(&y).map_err(|source| {
                    EcFromJwkError::BigNumFromCoordinate {
                        source,
                        coordinate: "y",
                    }
                })?;

                let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
                    .map_err(|source| EcFromJwkError::CreateEcKey { source })?;

                PKey::from_ec_key(ec_key).map_err(|source| EcFromJwkError::CreatePKey { source })?
            }
        };

        Ok(Self {
            jwk,
            retrieved: Timestamp::now(),
            key,
        })
    }
}

/// Error variants for converting a JSON web key to a decoding key.
#[derive(Debug)]
#[non_exhaustive]
pub enum FromJwkError {
    /// Converting an elliptic curve JSON web key to a decoding key failed.
    Ec {
        /// The source of the failure.
        source: EcFromJwkError,
    },
}
impl fmt::Display for FromJwkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Ec { .. } => {
                write!(
                    f,
                    "could not convert elliptic curve parameters to a public key"
                )
            }
        }
    }
}
impl Error for FromJwkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::Ec { source, .. } => Some(source),
        }
    }
}
impl From<EcFromJwkError> for FromJwkError {
    fn from(source: EcFromJwkError) -> Self {
        Self::Ec { source }
    }
}

/// Error variants for converting an elliptic curve JSON web key to a public key.
#[derive(Debug)]
#[non_exhaustive]
pub enum EcFromJwkError {
    /// Getting the elliptic curve group failed.
    #[non_exhaustive]
    GetEcGroup {
        /// The source of the error.
        source: openssl::error::ErrorStack,
    },

    /// A coordinate failed base64 decoding.
    #[non_exhaustive]
    Base64DecodeCoordinate {
        /// The source of the error.
        source: base64ct::Error,
        /// The coordinate that failed.
        coordinate: &'static str,
    },

    /// Failed to create a BigNum from a coordinate.
    #[non_exhaustive]
    BigNumFromCoordinate {
        /// The source of the error.
        source: openssl::error::ErrorStack,
        /// The coordinate.
        coordinate: &'static str,
    },

    /// Failed to create the elliptic curve key from the coordinates.
    #[non_exhaustive]
    CreateEcKey {
        /// The source of the error.
        source: openssl::error::ErrorStack,
    },

    /// Failed to create the PKey from the EcKey.
    #[non_exhaustive]
    CreatePKey {
        /// The source of the error.
        source: openssl::error::ErrorStack,
    },
}
impl fmt::Display for EcFromJwkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::GetEcGroup { .. } => write!(f, "failed getting elliptic curve group for curve"),
            Self::Base64DecodeCoordinate { coordinate, .. } => {
                write!(f, "coordinate {coordinate} is invalid base64")
            }
            Self::BigNumFromCoordinate { coordinate, .. } => {
                write!(f, "could not convert coordinate {coordinate} to a number")
            }
            Self::CreateEcKey { .. } => write!(f, "failed creating an elliptic curve key"),
            Self::CreatePKey { .. } => write!(
                f,
                "failed converting the elliptic curve key to a public key"
            ),
        }
    }
}
impl Error for EcFromJwkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::GetEcGroup { source, .. } => Some(source),
            Self::Base64DecodeCoordinate { source, .. } => Some(source),
            Self::BigNumFromCoordinate { source, .. } => Some(source),
            Self::CreateEcKey { source, .. } => Some(source),
            Self::CreatePKey { source, .. } => Some(source),
        }
    }
}

/// Error variants for verifying the JWT.
#[non_exhaustive]
#[derive(Debug)]
pub enum VerifyError {
    /// An OpenSSL operation failed.
    #[non_exhaustive]
    VerifierOperation {
        /// The source of this error.
        source: openssl::error::ErrorStack,
        /// The operation that failed.
        operation: &'static str,
    },

    /// Decoding the header failed.
    #[non_exhaustive]
    DecodeHeader {
        /// The source of this error.
        source: DecodeError,
    },

    /// Decoding the claims failed.
    #[non_exhaustive]
    DecodeClaims {
        /// The source of the error.
        source: DecodeError,
    },

    /// Decoding the signature failed.
    #[non_exhaustive]
    DecodeSignature {
        /// The source of the error.
        source: base64ct::Error,
    },

    /// The header string was not in the expected format for JWTs.
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
            Self::DecodeSignature { .. } => write!(f, "JWT signature could not be decoded"),
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
            Self::DecodeSignature { source, .. } => Some(source),
            _ => None,
        }
    }
}
