#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::webauthn::public_key_credential::{
    Algorithm, AuthenticatorAttachment, Hint, Transports, Type, UserVerification,
};

/// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub attestation: Option<Attestation>,
    pub attestation_formats: Option<String>,
    pub authenticator_selection: Option<AuthenticatorSelection>,
    #[serde(with = "super::serde_url_base64")]
    pub challenge: Vec<u8>,
    pub exclude_credentials: Option<Vec<ExcludeCredentials>>,
    pub extensions: Option<Extensions>,
    #[serde(rename = "pubKeyCredParams")]
    pub public_key_parameters: Vec<PublicKeyParameters>,
    #[serde(rename = "rp")]
    pub relying_party: RelyingParty,
    pub timeout: u64,
    pub user: User,
    pub hints: Option<Vec<Hint>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Attestation {
    None,
    Direct,
    Enterprise,
    Indirect,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[deprecated(note = "Should be true if residentKey is required.")]
    pub require_resident_key: Option<bool>,
    pub resident_key: Option<ResidentKey>,
    pub user_verification: Option<UserVerification>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ResidentKey {
    Discouraged,
    Preferred,
    Required,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExcludeCredentials {
    #[serde(with = "super::serde_url_base64")]
    pub id: Vec<u8>,
    pub transports: Option<Vec<Transports>>,
    pub r#type: Type,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    #[serde(rename = "credProp")]
    pub return_credential_properties: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelyingParty {
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub display_name: String,
    #[serde(with = "super::serde_url_base64")]
    pub id: Vec<u8>,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyParameters {
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,
    pub r#type: Type,
}
