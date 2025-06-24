use core::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use jiff::Timestamp;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Public},
};

use crate::token::{
    Jwk,
    jwk::{Curve, JwkParameters},
};

pub struct DecodingJwk {
    pub jwk: Jwk,
    pub retrieved: Timestamp,
    pub key: PKey<Public>,
}

impl TryFrom<Jwk> for DecodingJwk {
    type Error = FromJwkError;

    fn try_from(jwk: Jwk) -> Result<Self, Self::Error> {
        let key = match &jwk.parameters {
            JwkParameters::EC { crv, x, y } => {
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

#[derive(Debug)]
#[non_exhaustive]
pub enum FromJwkError {
    Ec { source: EcFromJwkError },
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

#[derive(Debug)]
#[non_exhaustive]
pub enum EcFromJwkError {
    #[non_exhaustive]
    GetEcGroup { source: openssl::error::ErrorStack },

    #[non_exhaustive]
    Base64DecodeCoordinate {
        source: base64ct::Error,
        coordinate: &'static str,
    },

    #[non_exhaustive]
    BigNumFromCoordinate {
        source: openssl::error::ErrorStack,
        coordinate: &'static str,
    },

    #[non_exhaustive]
    CreateEcKey { source: openssl::error::ErrorStack },

    #[non_exhaustive]
    CreatePKey { source: openssl::error::ErrorStack },
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
