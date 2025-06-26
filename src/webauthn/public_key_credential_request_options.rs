#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::webauthn::public_key_credential_creation_options::{
    Hint, Transports, Type, UserVerification,
};

/// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    pub allow_credentials: Option<Vec<AllowCredentials>>,
    #[serde(with = "super::serde_url_base64")]
    pub challenge: Vec<u8>,
    pub extensions: Option<Extensions>,
    pub hints: Option<Vec<Hint>>,
    #[serde(rename = "rpId")]
    pub relying_party_id: Option<String>,
    pub timeout: u64,
    pub user_verification: Option<UserVerification>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AllowCredentials {
    #[serde(with = "super::serde_url_base64")]
    pub id: Vec<u8>,
    pub transports: Vec<Transports>,
    pub r#type: Type,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Extensions {}
