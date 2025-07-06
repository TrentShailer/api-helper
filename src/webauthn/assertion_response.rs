#![allow(missing_docs)]

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, de};

use crate::webauthn::public_key_credential::ClientDataJson;

/// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    pub authenticator_data: AuthenticatorData,

    #[serde(rename = "clientDataJSON")]
    pub client_data_json: ClientDataJson,

    /// An assertion signature over `authenticator_data` and `client_data_json`.
    #[serde(with = "crate::serde_url_base64")]
    pub signature: Vec<u8>,

    /// Specified as the `user.id` in the options passed to the originating `PublicKeyCredentialCreationOptions`.
    #[serde(with = "crate::serde_url_base64")]
    pub user_handle: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthenticatorData {
    pub relying_party_id_hash: [u8; 32],
    pub flags: Flags,
    pub signature_counter: u32,
    pub raw: Vec<u8>,
}

#[repr(transparent)]
#[derive(Debug, Deserialize)]
pub struct Flags(pub u8);
impl Flags {
    pub const USER_PRESENCE: Self = Self(1 << 0);
    pub const USER_VERIFICATION: Self = Self(1 << 2);
    pub const BACKUP_ELIGIBILITY: Self = Self(1 << 3);
    pub const BACKUP_STATE: Self = Self(1 << 4);
    pub const ATTESTED_CREDENTIAL_DATA: Self = Self(1 << 6);
    pub const EXTENSION_DATA: Self = Self(1 << 7);
}

impl<'de> Deserialize<'de> for AuthenticatorData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let base64: &str = Deserialize::deserialize(deserializer)?;
        let bytes = Base64UrlUnpadded::decode_vec(base64).map_err(de::Error::custom)?;
        if bytes.len() < 37 {
            return Err(de::Error::custom(
                "authenticator data must be at least 37 bytes",
            ));
        }

        let mut relying_party_id_hash = [0u8; 32];
        relying_party_id_hash.copy_from_slice(&bytes[0..32]);

        let flags = Flags(bytes[32]);

        let mut signature_counter_bytes = [0u8; 4];
        signature_counter_bytes.copy_from_slice(&bytes[33..37]);
        let signature_counter = u32::from_le_bytes(signature_counter_bytes); // TODO LE or BE

        Ok(Self {
            relying_party_id_hash,
            flags,
            signature_counter,
            raw: bytes,
        })
    }
}
