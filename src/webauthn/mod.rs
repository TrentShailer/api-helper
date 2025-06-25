//! Helpers for working with WebAuthN
//!

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub attestation: Option<Attestation>,
    pub attestation_formats: Option<String>,
    pub authenticator_selection: Option<AuthenticatorSelection>,
    /// TODO Base64 encoded challenge.
    pub challenge: Vec<u8>,
    pub exclude_credentials: Option<Vec<ExcludeCredentials>>,
    pub extensions: Option<Extensions>,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub rp: RelyingParty,
    pub timeout: u64,
    pub user: User,
    pub hints: Option<Vec<Hint>>,
}
#[derive(Debug, Deserialize, Serialize)]
pub enum Attestation {
    None,
    Direct,
    Enterprise,
    Indirect,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[deprecated(note = "Should be true if residentKey is required.")]
    pub require_resident_key: Option<bool>,
    pub resident_key: Option<ResidentKey>,
    pub user_verification: Option<UserVerification>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum AuthenticatorAttachment {
    Platform,
    #[serde(rename = "cross-platform")]
    Crossplatform,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ResidentKey {
    Discouraged,
    Preferred,
    Required,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum UserVerification {
    Discouraged,
    Preferred,
    Required,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExcludeCredentials {
    /// TODO Base64 encoded ID.
    pub id: Vec<u8>,
    pub transports: Option<Vec<Transports>>,
    pub r#type: Type,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Transports {
    Ble,
    Hybrid,
    Internal,
    Nfc,
    Usb,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Type {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Extensions {
    pub cred_props: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RelyingParty {
    pub id: Option<String>,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub display_name: String,
    /// TODO Base64 encoded.
    pub id: Vec<u8>,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PubKeyCredParams {
    pub alg: Algorithm,
    pub r#type: Type,
}

#[derive(Debug, Deserialize, Serialize)]
#[repr(i32)]
pub enum Algorithm {
    /// EdDSA using Ed448 curve
    ED448 = -53,
    /// ECDSA using secp256k1 curve and SHA-256
    ES256K = -47,
    /// RSASSA-PSS w/ SHA-512
    PS512 = -39,
    /// RSASSA-PSS w/ SHA-384
    PS384 = -38,
    /// RSASSA-PSS w/ SHA-256
    PS256 = -37,
    /// EdDSA using Ed25519 curve
    ED25519 = -19,
    /// ECDSA using P-256 curve and SHA-256
    ESP256 = -9,
    /// ECDSA using P-384 curve and SHA-384
    ESP384 = -51,
    /// ECDSA using P-521 curve and SHA-512
    ESP512 = -52,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    #[deprecated]
    RS512 = -259,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    #[deprecated]
    RS384 = -258,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    #[deprecated]
    RS256 = -257,
    /// EdDSA
    #[deprecated]
    EdDSA = -8,
    /// ECDSA w/ SHA-512
    #[deprecated]
    ES512 = -36,
    /// ECDSA w/ SHA-384
    #[deprecated]
    ES384 = -35,
    /// ECDSA w/ SHA-256
    #[deprecated]
    ES256 = -7,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Hint {
    #[serde(rename = "security-key")]
    SecurityKey,
    #[serde(rename = "client-device")]
    ClientDevice,
    Hybrid,
}
