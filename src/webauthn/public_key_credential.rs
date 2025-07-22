#![allow(missing_docs)]

use core::{error::Error, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use openssl::pkey::Id;
use serde::{Deserialize, Serialize, de};
use serde_repr::{Deserialize_repr, Serialize_repr};
use ts_sql_helper_lib::FromSql;

use crate::webauthn::{
    assertion_response::AssertionResponse, attestation_response::AttestationResponse,
};

/// https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredential {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub id: String,
    #[serde(with = "crate::serde_url_base64")]
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
    #[serde(with = "crate::serde_url_base64")]
    pub challenge: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_origin: Option<bool>,
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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
            #[serde(with = "crate::serde_url_base64")]
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, FromSql)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Transports {
    Ble,
    Hybrid,
    Internal,
    Nfc,
    Usb,
}
impl fmt::Display for Transports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Ble => f.write_str("ble"),
            Self::Hybrid => f.write_str("hybrid"),
            Self::Internal => f.write_str("internal"),
            Self::Nfc => f.write_str("nfc"),
            Self::Usb => f.write_str("usb"),
        }
    }
}
impl TryFrom<&str> for Transports {
    type Error = TryFromStringError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "ble" => Ok(Self::Ble),
            "hybrid" => Ok(Self::Hybrid),
            "internal" => Ok(Self::Internal),
            "nfc" => Ok(Self::Nfc),
            "usb" => Ok(Self::Usb),
            _ => Err(TryFromStringError(value.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct TryFromStringError(String);
impl fmt::Display for TryFromStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "value `{}` is not a valid Transport", self.0)
    }
}
impl Error for TryFromStringError {}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Type {
    PublicKey,
}
/// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
#[derive(Debug, Clone, Copy, Deserialize_repr, Serialize_repr, FromSql)]
#[repr(i32)]
#[non_exhaustive]
pub enum Algorithm {
    /// `ECDSA using P-256 curve and SHA-256`
    ESP256 = -9,
    /// `ECDSA using P-384 curve and SHA-384`
    ESP384 = -51,
    /// `ECDSA using P-521 curve and SHA-512`
    ESP512 = -52,
    /// `ECDSA using secp256k1 curve and SHA-256`
    ES256K = -47,
    /// `EdDSA using Ed25519 curve`
    ED25519 = -19,
    /// `EdDSA using Ed448 curve`
    ED448 = -53,
    /// `RSASSA-PSS w/ SHA-256`
    PS256 = -37,
    /// `RSASSA-PSS w/ SHA-384`
    PS384 = -38,
    /// `RSASSA-PSS w/ SHA-512`
    PS512 = -39,
    /// (Deprecated) `ECDSA w/ SHA-256`
    ES256 = -7,
    /// (Deprecated) `ECDSA w/ SHA-384`
    ES384 = -35,
    /// (Deprecated) `ECDSA w/ SHA-512`
    ES512 = -36,
    /// (Deprecated) `EdDSA`
    EdDSA = -8,
    /// (Not recommended) `RSASSA-PKCS1-v1_5 using SHA-512`
    RS512 = -259,
    /// (Not recommended) `RSASSA-PKCS1-v1_5 using SHA-384`
    RS384 = -258,
    /// (Not recommended) `RSASSA-PKCS1-v1_5 using SHA-256`
    RS256 = -257,
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

impl TryFrom<i32> for Algorithm {
    type Error = TryFromI32Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -53 => Ok(Self::ED448),
            -47 => Ok(Self::ES256K),
            -39 => Ok(Self::PS512),
            -38 => Ok(Self::PS384),
            -37 => Ok(Self::PS256),
            -19 => Ok(Self::ED25519),
            -9 => Ok(Self::ESP256),
            -51 => Ok(Self::ESP384),
            -52 => Ok(Self::ESP512),
            259 => Ok(Self::RS512),
            258 => Ok(Self::RS384),
            257 => Ok(Self::RS256),
            -8 => Ok(Self::EdDSA),
            -36 => Ok(Self::ES512),
            -35 => Ok(Self::ES384),
            -7 => Ok(Self::ES256),
            _ => Err(TryFromI32Error(value)),
        }
    }
}

#[derive(Debug)]
pub struct TryFromI32Error(i32);
impl fmt::Display for TryFromI32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "value {} is not a valid Algorithm", self.0)
    }
}
impl Error for TryFromI32Error {}

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
