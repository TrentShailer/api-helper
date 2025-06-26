#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::webauthn::public_key_credential::ClientDataJson;

/// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    #[serde(with = "super::serde_url_base64")]
    pub authenticator_data: Vec<u8>,

    #[serde(rename = "clientDataJSON")]
    pub client_data_json: ClientDataJson,

    /// An assertion signature over `authenticator_data` and `client_data_json`.
    #[serde(with = "super::serde_url_base64")]
    pub signature: Vec<u8>,

    /// Specified as the `user.id` in the options passed to the originating `PublicKeyCredentialCreationOptions`.
    #[serde(with = "super::serde_url_base64")]
    pub user_handle: Vec<u8>,
}
