use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    pub exp: usize,
    pub iss: String,
    pub iat: usize,
    pub nbf: usize,
    pub sub: String,
}
