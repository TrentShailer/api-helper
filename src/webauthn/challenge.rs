//! A challenge issued to a client.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use ts_sql_helper_lib::{FromRow, SqlTimestamp};

/// A challenge issued to a client.
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Challenge {
    /// The challenge.
    #[serde(with = "crate::serde_base64")]
    pub challenge: Vec<u8>,
    /// The identity associated with the challenge.
    #[serde(with = "crate::maybe_serde_base64")]
    pub identity_id: Option<Vec<u8>>,
    /// When the challenge was issued.
    pub issued: SqlTimestamp,
    /// When the challenge expires.
    pub expires: SqlTimestamp,
    /// The origin the challenge was issued to.
    pub origin: String,
}

impl Challenge {
    /// Returns if the challenge is valid.
    pub fn is_valid(&self) -> bool {
        let now = Timestamp::now();

        self.expires.0 > now && self.issued.0 < now
    }

    /// Returns if the challenge is for a given origin.
    pub fn is_for_origin(&self, origin: &str) -> bool {
        self.origin == origin
    }

    /// Returns if the challenge is for the given bearer.
    pub fn is_for_bearer(&self, bearer: Option<&[u8]>) -> bool {
        self.identity_id.as_deref() == bearer
    }
}
