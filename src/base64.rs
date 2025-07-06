use base64ct::{Base64UrlUnpadded, Encoding};

/// Serde helper for serializing bytes to and from base 64.
pub mod serde_url_base64 {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serialize some bytes as base 64.
    pub fn serialize<S, V: AsRef<[u8]>>(value: &V, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(value.as_ref()))
    }

    /// Deserialize some bytes from base 64.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: &str = Deserialize::deserialize(deserializer)?;

        Base64UrlUnpadded::decode_vec(value).map_err(de::Error::custom)
    }
}

/// Serde helper for maybe serializing bytes to and from base 64.
pub mod maybe_serde_url_base64 {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de};

    /// Serialize some bytes as base 64.
    pub fn serialize<S, V: AsRef<[u8]>>(value: &Option<V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => {
                serializer.serialize_str(&Base64UrlUnpadded::encode_string(value.as_ref()))
            }
            None => serializer.serialize_none(),
        }
    }

    /// Deserialize some bytes from base 64.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Option<&str> = Deserialize::deserialize(deserializer)?;

        match value {
            Some(value) => Ok(Some(
                Base64UrlUnpadded::decode_vec(value).map_err(de::Error::custom)?,
            )),
            None => Ok(None),
        }
    }
}

/// Extension trait for encoding something as base64.
pub trait EncodeBase64 {
    /// Encode the value has base64.
    fn encode_base64(&self) -> String;
}
/// Extension trait for decoding something from base64.
pub trait DecodeBase64 {
    /// Decode the value from base64.
    fn decode_base64(&self) -> Result<Vec<u8>, base64ct::Error>;
}

impl<V: AsRef<[u8]>> EncodeBase64 for V {
    fn encode_base64(&self) -> String {
        Base64UrlUnpadded::encode_string(self.as_ref())
    }
}

impl<V: AsRef<str>> DecodeBase64 for V {
    fn decode_base64(&self) -> Result<Vec<u8>, base64ct::Error> {
        Base64UrlUnpadded::decode_vec(self.as_ref())
    }
}
