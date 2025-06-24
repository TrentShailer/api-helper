use serde::{Deserialize, Serialize};

use crate::jws::jwk::Jwk;

#[derive(Debug, Deserialize, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}
