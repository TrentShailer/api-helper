#![allow(missing_docs)]

use serde::Deserialize;

use crate::webauthn::{
    assertion_response::AuthenticatorData,
    public_key_credential::{Algorithm, ClientDataJson, Transports},
};

/// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    #[serde(with = "super::serde_url_base64")]
    pub attestation_object: Vec<u8>,

    #[serde(rename = "clientDataJSON")]
    pub client_data_json: ClientDataJson,

    #[serde(flatten)]
    pub method_results: MethodResults,
}

#[derive(Debug, Deserialize)]
pub struct MethodResults {
    pub authenticator_data: AuthenticatorData,
    #[serde(with = "super::serde_url_base64")]
    pub public_key: Vec<u8>,
    pub public_key_algorithm: Algorithm,
    pub transports: Vec<Transports>,
}
