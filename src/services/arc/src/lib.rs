//! P256 ARC adapter. Live RPC and policy integration use accepted K01 contracts.
//! Each pending issuance owns its client-generated secret until finalization.

use arc::{
    ArcError, ClientSecret, Credential, CredentialRequest, CredentialResponse, IssuerParams,
    Presentation, SecretKey, State, suites::P256,
};
use rand_core::OsRng;
use std::num::NonZeroU32;

pub mod wire;

pub const UPSTREAM_REVISION: &str = "4f023d349a552d019ee0d8d7f73921da8d035165";
pub const SPECIFICATION: &str = "draft-ietf-privacypass-arc-crypto-01";
pub const ADAPTER_REVISION: &str = "tf-arc-p256-1";

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
        let parsed_parameters = IssuerParams::<P256>::from_bytes(parameters)?;
        if parsed_parameters.to_bytes() != parameters {
            return Err(ArcError::DeserializationFailed);
        }
        let parsed_response = CredentialResponse::<P256>::from_bytes(response)?;
        if parsed_response.to_bytes() != response {
            return Err(ArcError::DeserializationFailed);
        }
        let credential = Credential::new(
            &parsed_parameters,
            self.request,
            self.secret,
            parsed_response,
        )?;
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
        if limit.get() != 5 {
            return Err(ArcError::VerificationFailed);
        }
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
    pub fn generate() -> Result<Self, ArcError> {
        let issuer = Self {
            key: SecretKey::new(&mut OsRng),
        };
        // Validate fresh public parameters before bootstrap publication.
        issuer.parameters()?;
        Ok(issuer)
    }

    pub fn parameters(&self) -> Result<Vec<u8>, ArcError> {
        let bytes = self.key.issuer_params()?.to_bytes();
        let parsed = IssuerParams::<P256>::from_bytes(&bytes)?;
        if parsed.to_bytes() != bytes {
            return Err(ArcError::DeserializationFailed);
        }
        Ok(bytes)
    }

    /// K01 admission must authorize a request before invoking blind issuance.
    /// The upstream issuance API accepts the blinded request with its proof.
    pub fn issue(&self, request: &[u8]) -> Result<Vec<u8>, ArcError> {
        let parsed = CredentialRequest::<P256>::from_bytes(request)?;
        if parsed.to_bytes() != request {
            return Err(ArcError::DeserializationFailed);
        }
        Ok(CredentialResponse::new(&mut OsRng, &self.key, parsed)?.to_bytes())
    }

    pub fn verify(
        &self,
        wire: &[u8],
        request_context: &[u8],
        limit: NonZeroU32,
        presentation_context: &[u8],
    ) -> Result<(), ArcError> {
        self.verify_and_tag(wire, request_context, limit, presentation_context)
            .map(|_| ())
    }

    /// Return a verified compressed P256 protocol tag from the same parsed object.
    pub fn verify_and_tag(
        &self,
        wire: &[u8],
        request_context: &[u8],
        limit: NonZeroU32,
        presentation_context: &[u8],
    ) -> Result<[u8; 33], ArcError> {
        if limit.get() != 5 {
            return Err(ArcError::VerificationFailed);
        }
        if wire.len() != Presentation::<P256>::bytes_len(limit) {
            return Err(ArcError::DeserializationFailed);
        }
        let presentation = Presentation::<P256>::from_bytes(wire, limit)?;
        // Exact accepted encoding is checked in addition to the vendor point checks.
        if presentation.to_bytes() != wire {
            return Err(ArcError::DeserializationFailed);
        }
        let tag: [u8; 33] = presentation
            .verify_and_tag(&self.key, request_context, limit, presentation_context)?
            .try_into()
            .map_err(|_| ArcError::VerificationFailed)?;
        if !matches!(tag[0], 2 | 3) {
            return Err(ArcError::VerificationFailed);
        }
        Ok(tag)
    }
}
