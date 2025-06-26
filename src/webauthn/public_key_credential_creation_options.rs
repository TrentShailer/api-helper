#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

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
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub rp: RelyingParty,
    pub timeout: u64,
    pub user: User,
    pub hints: Option<Vec<Hint>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResidentKey {
    Discouraged,
    Preferred,
    Required,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserVerification {
    Discouraged,
    Preferred,
    Required,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExcludeCredentials {
    #[serde(with = "super::serde_url_base64")]
    pub id: Vec<u8>,
    pub transports: Option<Vec<Transports>>,
    pub r#type: Type,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transports {
    Ble,
    Hybrid,
    Internal,
    Nfc,
    Usb,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Type {
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
    #[serde(with = "super::serde_url_base64")]
    pub id: Vec<u8>,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PubKeyCredParams {
    pub alg: Algorithm,
    pub r#type: Type,
}

/// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
#[derive(Debug, Deserialize, Serialize)]
#[repr(i32)]
pub enum Algorithm {
    /// `EdDSA using Ed448 curve`
    ED448 = -53,
    /// `ECDSA using secp256k1 curve and SHA-256`
    ES256K = -47,
    /// `RSASSA-PSS w/ SHA-512`
    PS512 = -39,
    /// `RSASSA-PSS w/ SHA-384`
    PS384 = -38,
    /// `RSASSA-PSS w/ SHA-256`
    PS256 = -37,
    /// `EdDSA using Ed25519 curve`
    ED25519 = -19,
    /// `ECDSA using P-256 curve and SHA-256`
    ESP256 = -9,
    /// `ECDSA using P-384 curve and SHA-384`
    ESP384 = -51,
    /// `ECDSA using P-521 curve and SHA-512`
    ESP512 = -52,
    /// (Not recommended) `RSASSA-PKCS1-v1_5 using SHA-512`
    RS512 = -259,
    /// (Not recommended) `RSASSA-PKCS1-v1_5 using SHA-384`
    RS384 = -258,
    /// (Not recommended) `RSASSA-PKCS1-v1_5 using SHA-256`
    RS256 = -257,
    /// (Deprecated) `EdDSA`
    EdDSA = -8,
    /// (Deprecated) `ECDSA w/ SHA-512`
    ES512 = -36,
    /// (Deprecated) `ECDSA w/ SHA-384`
    ES384 = -35,
    /// (Deprecated) `ECDSA w/ SHA-256`
    ES256 = -7,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hint {
    SecurityKey,
    ClientDevice,
    Hybrid,
}
