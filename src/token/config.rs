//! Config for setting up JWT issuing and validation.
//!

use core::{error::Error, fmt};
use std::{fs, io, path::PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::token::{
    Algorithm, JsonWebKey, JsonWebKeySetCache, SigningJsonWebKey,
    json_web_key::{Curve, JsonWebKeyParameters, JsonWebKeySet, signing::FromPemError},
};

/// The config for validating tokens.
#[derive(Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenValidationConfig {
    /// The endpoint that serves the key sets used to validate a token.
    jwks_endpoint: String,
    /// The endpoint to check if a token has been revoked.
    /// This will have `/{token.claims.tid}` appended to it.
    pub revocation_endpoint: String,
}
impl Default for TokenValidationConfig {
    fn default() -> Self {
        Self {
            jwks_endpoint: "http://localhost:8081/.well-known/jwks.json".to_string(),
            revocation_endpoint: "http://localhost:8081/revoked-tokens".to_string(),
        }
    }
}
impl TokenValidationConfig {
    /// Create the cache for the JWKS.
    pub fn jwks_cache(&self) -> JsonWebKeySetCache {
        JsonWebKeySetCache::new(self.jwks_endpoint.clone())
    }
}

/// The config for issuing tokens.
#[derive(Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenIssuingConfig {
    /// The path to the JWKS file.
    jwks_file_path: PathBuf,
    /// The key to sign tokens with in JWK form.
    signing_jwk: JsonWebKey,
    /// The path to the signing key PEM file.
    signing_key_path: PathBuf,
}
impl Default for TokenIssuingConfig {
    fn default() -> Self {
        Self {
            jwks_file_path: "path/to/jwks.json".into(),
            signing_jwk: JsonWebKey {
                kid: "kid".to_string(),
                alg: Algorithm::ES256,
                usage: "use".to_string(),
                parameters: JsonWebKeyParameters::EC {
                    crv: Curve::P256,
                    x: "x".to_string(),
                    y: "y".to_string(),
                },
            },
            signing_key_path: "path/to/private.pem".into(),
        }
    }
}
impl TokenIssuingConfig {
    /// Read and parse the JWKS file.
    pub fn jwks(&self) -> io::Result<JsonWebKeySet> {
        let contents = fs::read(&self.jwks_file_path)?;
        serde_json::from_slice(&contents).map_err(io::Error::other)
    }

    /// Read the signing key and build a signer.
    pub fn signing_jwk(&self) -> Result<SigningJsonWebKey, LoadSigningJwkError> {
        let contents = fs::read(&self.signing_key_path)
            .map_err(|source| LoadSigningJwkError::ReadFile { source })?;

        SigningJsonWebKey::try_from_pem(self.signing_jwk.clone(), &contents)
            .map_err(|source| LoadSigningJwkError::FromPem { source })
    }
}
/// Error variants for loading the signing JWK.
#[non_exhaustive]
#[derive(Debug)]
#[allow(missing_docs)]
pub enum LoadSigningJwkError {
    #[non_exhaustive]
    ReadFile { source: io::Error },

    #[non_exhaustive]
    FromPem { source: FromPemError },
}
impl fmt::Display for LoadSigningJwkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::ReadFile { .. } => write!(f, "could not read private key file"),
            Self::FromPem { .. } => write!(f, "could not convert PEM to signing key"),
        }
    }
}
impl Error for LoadSigningJwkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self {
            Self::ReadFile { source } => Some(source),
            Self::FromPem { source } => Some(source),
        }
    }
}
