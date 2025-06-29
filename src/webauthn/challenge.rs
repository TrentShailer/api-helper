//! A challenge issued to a client.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// A challenge issued to a client.
#[derive(Debug, Serialize, Deserialize)]
pub struct Challenge {
    /// The challenge.
    pub challenge: Vec<u8>,
    /// The identity associated with the challenge.
    pub identity_id: Option<Vec<u8>>,
    /// When the challenge was issued.
    pub issued: Timestamp,
    /// When the challenge expires.
    pub expires: Timestamp,
    /// The origin the challenge was issued to,
    pub origin: String,
}

impl Challenge {
    /// Returns if the challenge is valid.
    pub fn is_valid(&self) -> bool {
        let now = Timestamp::now();

        self.expires > now && self.issued < now
    }

    /// Returns if the challenge is for a given origin.
    pub fn is_for(&self, origin: &str) -> bool {
        self.origin == origin
    }
}
