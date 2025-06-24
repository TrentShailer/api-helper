mod jwk_cache;
mod jwks;

pub use jwk_cache::JwkCache;
pub use jwks::Jwks;

use base64ct::{Base64UrlUnpadded, Encoding};
use jiff::Timestamp;
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private, Public},
};
use serde::{Deserialize, Serialize};

use crate::jws::algorithm::Algorithm;

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub alg: Algorithm,
    #[serde(rename = "use")]
    pub usage: String,
    #[serde(flatten)]
    pub parameters: JwkParameters,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum JwkParameters {
    EC { crv: Curve, x: String, y: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Curve {
    #[serde(rename = "P-256")]
    P256,
}

pub struct DecodingJwk {
    pub jwk: Jwk,
    pub retrieved: Timestamp,
    pub key: PKey<Public>,
}

pub struct EncodingJwk {
    pub jwk: Jwk,
    pub key: PKey<Private>,
}

impl TryFrom<Jwk> for DecodingJwk {
    type Error = (); // TODO

    fn try_from(jwk: Jwk) -> Result<Self, Self::Error> {
        let key = match &jwk.parameters {
            JwkParameters::EC { crv, x, y } => {
                let group = match crv {
                    Curve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap(),
                };

                let x = Base64UrlUnpadded::decode_vec(x).unwrap();
                let y = Base64UrlUnpadded::decode_vec(y).unwrap();

                let x = BigNum::from_slice(&x).unwrap();
                let y = BigNum::from_slice(&y).unwrap();

                let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
                PKey::from_ec_key(ec_key).unwrap()
            }
        };

        Ok(Self {
            jwk,
            retrieved: Timestamp::now(),
            key,
        })
    }
}
