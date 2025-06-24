pub mod decoding_jwk;
pub mod encoding_jwk;
mod jwk_cache;
mod jwks;

pub use decoding_jwk::DecodingJwk;
pub use encoding_jwk::EncodingJwk;
pub use jwk_cache::JwkCache;
pub use jwks::Jwks;

use serde::{Deserialize, Serialize};

use crate::token::algorithm::Algorithm;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub alg: Algorithm,
    #[serde(rename = "use")]
    pub usage: String,
    #[serde(flatten)]
    pub parameters: JwkParameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kty")]
pub enum JwkParameters {
    EC { crv: Curve, x: String, y: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Curve {
    #[serde(rename = "P-256")]
    P256,
}
