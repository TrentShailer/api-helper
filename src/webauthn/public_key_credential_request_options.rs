#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::webauthn::public_key_credential::{Hint, Transports, Type, UserVerification};

/// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<AllowCredentials>>,
    #[serde(with = "crate::maybe_serde_base64")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<Hint>>,
    #[serde(rename = "rpId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relying_party_id: Option<String>,
    pub timeout: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerification>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowCredentials {
    #[serde(with = "crate::serde_base64")]
    pub id: Vec<u8>,
    pub transports: Vec<Transports>,
    pub r#type: Type,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {}
