//! A JSON web key used to verify signatures.
mod key_set;
pub mod key_set_cache;
pub mod signing;
pub mod verifying;

pub use key_set::JsonWebKeySet;
pub use key_set_cache::JsonWebKeySetCache;
pub use signing::SigningJsonWebKey;
pub use verifying::VerifyingJsonWebKey;

use serde::{Deserialize, Serialize};

use crate::token::algorithm::Algorithm;

/// A JSON web key used to verify signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// The ID of this key.
    pub kid: String,
    /// The algorithm this key uses.
    pub alg: Algorithm,
    /// The use for this key.
    #[serde(rename = "use")]
    pub usage: String,
    /// The parameters that make up the public key.
    #[serde(flatten)]
    pub parameters: JsonWebKeyParameters,
}

/// The parameters that make up the key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kty")]
#[non_exhaustive]
pub enum JsonWebKeyParameters {
    /// The elliptic curve parameters.
    EC {
        /// The curve type.
        crv: Curve,
        /// The x coordinate.
        x: String,
        /// The y coordinate.
        y: String,
    },
}

/// The curves supported by this implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Curve {
    /// The Prime 256 curve.
    #[serde(rename = "P-256")]
    P256,
}
