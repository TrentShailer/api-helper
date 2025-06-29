#![allow(missing_docs)]

use base64ct::{Base64UrlUnpadded, Encoding};
use openssl::pkey::Id;
use serde::{Deserialize, Serialize, de};

use crate::webauthn::{
    assertion_response::AssertionResponse, attestation_response::AttestationResponse,
};

/// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredential {
    pub authenticator_attachment: AuthenticatorAttachment,
    pub id: String,
    #[serde(with = "super::serde_url_base64")]
    pub raw_id: Vec<u8>,
    pub response: Response,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AuthenticatorAttachment {
    Platform,
    CrossPlatform,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub enum Response {
    AttestationResponse(AttestationResponse),
    AssertionResponse(AssertionResponse),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDataJson {
    #[serde(with = "super::serde_url_base64")]
    pub challenge: Vec<u8>,
    pub cross_origin: Option<bool>,
    pub origin: String,
    pub top_origin: Option<String>,
    pub r#type: ClientDataType,
    pub raw: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[non_exhaustive]
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
        #[derive(Debug, Deserialize)]
        struct RealData {
            #[serde(with = "super::serde_url_base64")]
            pub challenge: Vec<u8>,
            pub cross_origin: Option<bool>,
            pub origin: String,
            pub top_origin: Option<String>,
            pub r#type: ClientDataType,
        }

        let base64: &str = Deserialize::deserialize(deserializer)?;
        let json_bytes = Base64UrlUnpadded::decode_vec(base64).map_err(de::Error::custom)?;
        let value: RealData = serde_json::from_slice(&json_bytes).map_err(de::Error::custom)?;

        Ok(Self {
            challenge: value.challenge,
            cross_origin: value.cross_origin,
            origin: value.origin,
            top_origin: value.top_origin,
            r#type: value.r#type,
            raw: json_bytes,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Transports {
    Ble,
    Hybrid,
    Internal,
    Nfc,
    Usb,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Type {
    PublicKey,
}
/// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
#[derive(Debug, Deserialize, Serialize)]
#[repr(i32)]
#[non_exhaustive]
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

impl Algorithm {
    pub fn id(&self) -> Id {
        match &self {
            Self::ED448 => Id::ED448,
            Self::ED25519 => Id::ED25519,
            Self::EdDSA => Id::DSA, // TODO

            Self::ES512
            | Self::ES384
            | Self::ES256
            | Self::ES256K
            | Self::ESP256
            | Self::ESP384
            | Self::ESP512 => Id::EC,

            Self::PS512 | Self::PS384 | Self::PS256 => Id::RSA_PSS,
            Self::RS512 | Self::RS384 | Self::RS256 => Id::RSA,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum UserVerification {
    Discouraged,
    Preferred,
    Required,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Hint {
    SecurityKey,
    ClientDevice,
    Hybrid,
}
