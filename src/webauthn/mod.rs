//! Helpers for working with WebAuthN
//!

pub mod public_key_credential_creation_options;
pub mod public_key_credential_request_options;

pub(crate) mod serde_url_base64 {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S, V: AsRef<[u8]>>(value: &V, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(value.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: &str = Deserialize::deserialize(deserializer)?;

        Base64UrlUnpadded::decode_vec(value)
            .map_err(|_| de::Error::custom(format!("`{value}` is not valid URL base64")))
    }
}
