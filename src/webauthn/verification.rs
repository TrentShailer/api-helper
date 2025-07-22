//! Verify if a public key response is valid and trusted.

use core::{error::Error, fmt};

use openssl::{hash::MessageDigest, pkey::PKey, sha::sha256};

use crate::webauthn::{
    challenge::Challenge,
    persisted_public_key::PersistedPublicKey,
    public_key_credential::{Algorithm, ClientDataType, PublicKeyCredential, Response},
};

/// Methods required to verify a public key credential.
pub trait Verifier: fmt::Debug {
    /// The errors that may be returned.
    type Error: Error + 'static;

    /// Try find the challenge from the persisted data store.
    fn get_challenge(
        &self,
        challenge: &[u8],
    ) -> impl Future<Output = Result<Option<Challenge>, Self::Error>> + Send;

    /// Try get the public key from the persisted data store.
    fn get_public_key(
        &self,
        raw_id: &[u8],
    ) -> impl Future<Output = Result<Option<PersistedPublicKey>, Self::Error>> + Send;

    /// Return the relying party's ID.
    fn relying_party_id(&self) -> &str;
}

impl PublicKeyCredential {
    /// Verify if a public key response is valid and trusted.
    pub async fn verify<V: Verifier>(
        &self,
        verifier: &V,
        bearer: Option<&[u8]>,
    ) -> Result<bool, VerificationError<V>> {
        match &self.response {
            Response::AttestationResponse(_) => self.verify_attestation(verifier, bearer).await,
            Response::AssertionResponse(_) => self.verify_assertion(verifier, bearer).await,
        }
    }

    async fn verify_attestation<V: Verifier>(
        &self,
        verifier: &V,
        bearer: Option<&[u8]>,
    ) -> Result<bool, VerificationError<V>> {
        let Response::AttestationResponse(response) = &self.response else {
            unreachable!(
                "`verify_attestation` MUST only be called when the response is an attestation response."
            )
        };

        // Ensure the response type is correct
        if response.client_data_json.r#type != ClientDataType::WebAuthNCreate {
            log::warn!("credential is not create");
            return Ok(false);
        }

        if bearer.is_none() {
            log::warn!("bearer is none");
            return Ok(false);
        }

        // Verify the challenge exists, is valid, is for the origin, and is associated with an identity.
        if verifier
            .get_challenge(&response.client_data_json.challenge)
            .await
            .map_err(|source| VerificationError::GetChallenge { source })?
            .is_none_or(|challenge| {
                !challenge.is_valid()
                    || !challenge.is_for_origin(&response.client_data_json.origin)
                    || challenge.identity_id.is_none()
                    || !challenge.is_for_bearer(bearer)
            })
        {
            log::warn!(
                "challenge is none, is not valid, is not for this origin, has no identity, or is not for this bearer"
            );

            return Ok(false);
        };

        // Verify the public key is valid
        let key = match PKey::public_key_from_der(&response.method_results.public_key) {
            Ok(key) => key,
            Err(_) => {
                log::warn!("public key is invalid");
                return Ok(false);
            }
        };

        // Ensure the key matches the algorithm
        if key.id() != response.method_results.public_key_algorithm.id() {
            log::warn!("algorithm does not match");
            return Ok(false);
        }

        Ok(true)
    }

    async fn verify_assertion<V: Verifier>(
        &self,
        verifier: &V,
        bearer: Option<&[u8]>,
    ) -> Result<bool, VerificationError<V>> {
        let Response::AssertionResponse(response) = &self.response else {
            unreachable!(
                "`verify_assertion` MUST only be called when the response is an assertion response."
            )
        };

        // Ensure the response type is correct
        if response.client_data_json.r#type != ClientDataType::WebAuthNGet {
            return Ok(false);
        }

        // Check that the Relying Party ID is the one expected for this service.
        let expected_hash = sha256(verifier.relying_party_id().as_bytes());
        if response.authenticator_data.relying_party_id_hash != expected_hash {
            return Ok(false);
        }

        // Verify the challenge exists
        let Some(challenge) = verifier
            .get_challenge(&response.client_data_json.challenge)
            .await
            .map_err(|source| VerificationError::GetChallenge { source })?
        else {
            return Ok(false);
        };

        // Verify the challenge is valid, and is for the origin.
        if !challenge.is_valid()
            || !challenge.is_for_origin(&response.client_data_json.origin)
            || !challenge.is_for_bearer(bearer)
        {
            return Ok(false);
        };

        // If the challenge is associated with an identity, ensure it matches the assertion.
        if let Some(identity_id) = challenge.identity_id
            && let Some(user_handle) = response.user_handle.as_deref()
            && identity_id != user_handle
        {
            return Ok(false);
        }

        // Using the public key that was stored during the registration request to validate the signature by the authenticator.
        let Some(persisted_public_key) = verifier
            .get_public_key(&self.raw_id)
            .await
            .map_err(|source| VerificationError::GetPublicKey { source })?
        else {
            return Ok(false);
        };

        // Ensure key belongs to the asserted ID.
        if let Some(user_handle) = response.user_handle.as_deref()
            && persisted_public_key.identity_id != user_handle
        {
            return Ok(false);
        }

        // Get data to verify against
        let contents = {
            let authenticator_data_length = response.authenticator_data.raw.len();

            let mut data = vec![0u8; authenticator_data_length + 32];

            data[..authenticator_data_length].copy_from_slice(&response.authenticator_data.raw);
            data[authenticator_data_length..]
                .copy_from_slice(sha256(&response.client_data_json.raw).as_slice());

            data
        };

        // Create the public key.
        let key = PKey::public_key_from_der(&persisted_public_key.public_key)
            .map_err(|source| VerificationError::PKeyFromDer { source })?;

        // Create the verifier.
        let mut signature_verifier = {
            let digest = match persisted_public_key.public_key_algorithm {
                Algorithm::ED448 | Algorithm::ED25519 | Algorithm::EdDSA => None,
                Algorithm::ES256K
                | Algorithm::PS256
                | Algorithm::ESP256
                | Algorithm::RS256
                | Algorithm::ES256 => Some(MessageDigest::sha256()),
                Algorithm::PS512 | Algorithm::ESP512 | Algorithm::ES512 | Algorithm::RS512 => {
                    Some(MessageDigest::sha512())
                }
                Algorithm::PS384 | Algorithm::ESP384 | Algorithm::RS384 | Algorithm::ES384 => {
                    Some(MessageDigest::sha384())
                }
            };

            if let Some(digest) = digest {
                openssl::sign::Verifier::new(digest, &key)
                    .map_err(|source| VerificationError::CreateSignatureVerifier { source })?
            } else {
                openssl::sign::Verifier::new_without_digest(&key)
                    .map_err(|source| VerificationError::CreateSignatureVerifier { source })?
            }
        };

        // Verify the signature
        let is_valid = signature_verifier
            .verify_oneshot(&response.signature, &contents)
            .map_err(|source| VerificationError::VerifierError { source })?;

        if !is_valid {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Error variants from verification.
#[derive(Debug)]
#[non_exhaustive]
pub enum VerificationError<V: Verifier> {
    /// The verifier failed to get the challenge.
    #[non_exhaustive]
    GetChallenge {
        /// The source of the error.
        source: V::Error,
    },

    /// The verifier failed to get the public key.
    #[non_exhaustive]
    GetPublicKey {
        /// The source of the error.
        source: V::Error,
    },

    /// Failed to convert the DER bytes to an OpenSSL public key.
    #[non_exhaustive]
    PKeyFromDer {
        /// The source of the error.
        source: openssl::error::ErrorStack,
    },

    /// Failed to create the signature verifier.
    #[non_exhaustive]
    CreateSignatureVerifier {
        /// The source of the error.
        source: openssl::error::ErrorStack,
    },

    /// The verifier failed to check the verification of the signature.
    #[non_exhaustive]
    VerifierError {
        /// The source of the error.
        source: openssl::error::ErrorStack,
    },
}
impl<V: Verifier> fmt::Display for VerificationError<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::GetChallenge { .. } => write!(f, "the verifier failed to fetch the challenge"),
            Self::GetPublicKey { .. } => write!(f, "the verifier failed to fetch the public key"),
            Self::PKeyFromDer { .. } => write!(f, "OpenSSL failed to parse the public key"),
            Self::CreateSignatureVerifier { .. } => {
                write!(f, "OpenSSL failed to create the signature verifier")
            }
            Self::VerifierError { .. } => write!(
                f,
                "OpenSSL failed to check the verification of the signature"
            ),
        }
    }
}
impl<V: Verifier> Error for VerificationError<V> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::GetChallenge { source, .. } => Some(source),
            Self::GetPublicKey { source, .. } => Some(source),
            Self::PKeyFromDer { source, .. } => Some(source),
            Self::CreateSignatureVerifier { source, .. } => Some(source),
            Self::VerifierError { source, .. } => Some(source),
        }
    }
}
