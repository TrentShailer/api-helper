#![allow(missing_docs)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::webauthn::public_key_credential::{
    Algorithm, AuthenticatorAttachment, Hint, Transports, Type, UserVerification,
};

/// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelection>,
    #[serde(with = "crate::maybe_serde_url_base64")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ExcludeCredentials>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    #[serde(rename = "pubKeyCredParams")]
    pub public_key_parameters: Vec<PublicKeyParameters>,
    #[serde(rename = "rp")]
    pub relying_party: RelyingParty,
    pub timeout: u64,
    pub user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[deprecated(note = "Should be true if residentKey is required.")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(with = "crate::serde_url_base64")]
    pub id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Transports>>,
    pub r#type: Type,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    #[serde(rename = "credProp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_credential_properties: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RelyingParty {
    /// The origin's effective domain, or a domain suffix thereof.
    pub id: String,
    /// The name the user will be presented with when creating or validating a WebAuthn operation.
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub display_name: String,
    #[serde(with = "crate::serde_url_base64")]
    pub id: Vec<u8>,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyParameters {
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,
    pub r#type: Type,
}

impl PublicKeyParameters {
    pub const ALL: [Self; 16] = [
        Self::new(Algorithm::ESP256),
        Self::new(Algorithm::ESP384),
        Self::new(Algorithm::ESP512),
        Self::new(Algorithm::ES256K),
        Self::new(Algorithm::ED25519),
        Self::new(Algorithm::ED448),
        Self::new(Algorithm::PS256),
        Self::new(Algorithm::PS384),
        Self::new(Algorithm::PS512),
        Self::new(Algorithm::ES256),
        Self::new(Algorithm::ES384),
        Self::new(Algorithm::ES512),
        Self::new(Algorithm::EdDSA),
        Self::new(Algorithm::RS512),
        Self::new(Algorithm::RS384),
        Self::new(Algorithm::RS256),
    ];

    pub const fn new(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            r#type: Type::PublicKey,
        }
    }
}
