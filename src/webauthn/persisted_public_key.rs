//! The public key details that the relying party should persist.

use serde::{Deserialize, Serialize};
use ts_sql_helper_lib::{FromRow, SqlTimestamp};

use crate::webauthn::public_key_credential::{Algorithm, Transports};

/// The public key details that the relying party should persist.
#[derive(Debug, Deserialize, Serialize, FromRow)]
pub struct PersistedPublicKey {
    /// The raw ID of the public key.
    #[serde(with = "crate::serde_url_base64")]
    pub raw_id: Vec<u8>,

    /// The ID of the identity associated with this public key.
    #[serde(with = "crate::serde_url_base64")]
    pub identity_id: Vec<u8>,

    /// The user's display name for this public key.
    pub display_name: String,

    /// The public key DER.
    #[serde(with = "crate::serde_url_base64")]
    pub public_key: Vec<u8>,

    /// The public key algorithm.
    pub public_key_algorithm: Algorithm,

    /// The transports for the authenticator used to create this public key.
    pub transports: Vec<Transports>,

    /// The number of times the private key has been used to sign.
    /// This should be monotonic and each value should only appear once if the authenticator supports it.
    /// Otherwise it should always be zero.
    pub signature_counter: i64,

    /// When this public key was created.
    pub created: SqlTimestamp,

    /// When this public key was last used for an assertion.
    pub last_used: Option<SqlTimestamp>,
}
