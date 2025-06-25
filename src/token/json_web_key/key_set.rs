use serde::{Deserialize, Serialize};

use crate::token::json_web_key::JsonWebKey;

/// A JSON web key set.
#[derive(Debug, Deserialize, Serialize)]
pub struct JsonWebKeySet {
    /// The set of keys.
    pub keys: Vec<JsonWebKey>,
}
