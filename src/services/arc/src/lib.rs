//! ARC library feasibility adapters. Live RPC and policy integration depend on K01.
//! Each pending issuance owns its client-generated secret until finalization.

use arc::{
    ArcError, ClientSecret, Credential, CredentialRequest, CredentialResponse, IssuerParams,
    Presentation, SecretKey, State, suites::P256,
};
use rand_core::OsRng;
use std::num::NonZeroU32;

pub const UPSTREAM_REVISION: &str = "4f023d349a552d019ee0d8d7f73921da8d035165";
pub const SPECIFICATION: &str = "draft-ietf-privacypass-arc-crypto-01";

/// Client-only pending state. It has no serialization or diagnostic implementation.
pub struct PendingIssuance {
    request: CredentialRequest<P256>,
    secret: ClientSecret<P256>,
}

impl PendingIssuance {
    pub fn begin(request_context: &[u8]) -> Result<Self, ArcError> {
        let (request, secret) = CredentialRequest::new(&mut OsRng, request_context)?;
        Ok(Self { request, secret })
    }

    pub fn request_bytes(&self) -> Vec<u8> {
        self.request.to_bytes()
    }

    pub fn finalize(self, parameters: &[u8], response: &[u8]) -> Result<Wallet, ArcError> {
        let parameters = IssuerParams::<P256>::from_bytes(parameters)?;
        let response = CredentialResponse::<P256>::from_bytes(response)?;
        let credential = Credential::new(&parameters, self.request, self.secret, response)?;
        Ok(Wallet { credential })
    }
}

/// Client-owned finalized credential. K01 will supply authorized contexts and limits.
pub struct Wallet {
    credential: Credential<P256>,
}

impl Wallet {
    pub fn presentation_state(
        &self,
        limit: NonZeroU32,
        presentation_context: &[u8],
    ) -> Result<State<P256>, ArcError> {
        self.credential
            .presentation_state(limit, presentation_context)
    }
}

/// Keyed ARC issuer/verifier used by the isolated feasibility tests.
/// Its key is distinct from the Type2 and TLS keys.
pub struct Issuer {
    key: SecretKey<P256>,
}

impl Issuer {
    pub fn generate() -> Self {
        Self {
            key: SecretKey::new(&mut OsRng),
        }
    }

    pub fn parameters(&self) -> Result<Vec<u8>, ArcError> {
        Ok(self.key.issuer_params()?.to_bytes())
    }

    /// K01 admission must authorize a request before invoking blind issuance.
    /// The upstream issuance API accepts the blinded request with its proof.
    pub fn issue(&self, request: &[u8]) -> Result<Vec<u8>, ArcError> {
        let request = CredentialRequest::<P256>::from_bytes(request)?;
        Ok(CredentialResponse::new(&mut OsRng, &self.key, request)?.to_bytes())
    }

    pub fn verify(
        &self,
        wire: &[u8],
        request_context: &[u8],
        limit: NonZeroU32,
        presentation_context: &[u8],
    ) -> Result<(), ArcError> {
        if wire.len() != Presentation::<P256>::bytes_len(limit) {
            return Err(ArcError::DeserializationFailed);
        }
        let presentation = Presentation::<P256>::from_bytes(wire, limit)?;
        // Local P256 encoding restriction reviewed for the feasibility adapter.
        // Upstream identity encodings can parse and reserialize differently.
        if presentation.to_bytes() != wire {
            return Err(ArcError::DeserializationFailed);
        }
        presentation.verify(&self.key, request_context, limit, presentation_context)
    }
}
