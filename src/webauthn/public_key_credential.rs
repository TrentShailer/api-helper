#![allow(missing_docs)]

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize, de};

use crate::webauthn::{
    assertion_response::AssertionResponse, attestation_response::AttestationResponse,
};

/// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredential {
    pub authenticator_attachment: AuthenticatorAttachment,
    /// `base64url` encoded `raw_id`.
    pub id: String,
    #[serde(with = "super::serde_url_base64")]
    pub raw_id: Vec<u8>,
    pub response: Response,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Response {
    AttestationResponse(AttestationResponse),
    AssertionResponse(AssertionResponse),
}

#[derive(Debug, Serialize)]
pub struct ClientDataJson {
    #[serde(with = "super::serde_url_base64")]
    pub challenge: Vec<u8>,
    pub cross_origin: Option<bool>,
    pub origin: String,
    pub top_origin: Option<String>,
    pub r#type: ClientDataType,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ClientDataType {
    #[serde(rename = "webauthn.create")]
    WebAuthNCreate,
    #[serde(rename = "webauthn.get")]
    WebAuthNGet,
}

impl<'de> Deserialize<'de> for ClientDataJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let base64: &str = Deserialize::deserialize(deserializer)?;
        let json_bytes = Base64UrlUnpadded::decode_vec(base64).map_err(de::Error::custom)?;
        let value = serde_json::from_slice(&json_bytes).map_err(de::Error::custom)?;
        Ok(value)
    }
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
pub enum UserVerification {
    Discouraged,
    Preferred,
    Required,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hint {
    SecurityKey,
    ClientDevice,
    Hybrid,
}
