use std::collections::HashMap;

use reqwest::Client;

use crate::token::jwk::DecodingJwk;

pub struct JwkCache {
    pub url: String,
    pub client: Client,
    pub cache: HashMap<String, DecodingJwk>,
}
