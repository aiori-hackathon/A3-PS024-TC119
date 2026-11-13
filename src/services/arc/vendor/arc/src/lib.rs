// Copyright (c) 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # ARC: Anonymous Rate-Limited Credentials
//!
//! Anonymous Rate-Limited Credentials (ARC) is a keyed-verification
//! anonymous credentials with support for rate limiting.
//!
//! ARC credentials can be presented from Client to Server up to some fixed
//! number of times. Each presentation is cryptographically bound to
//! Client secrets and application-specific public information, such that
//! each presentation is unlinkable from the others as well as the initial
//! interaction for credential creation.
//!
//! ARC is useful in applications where a Server needs to throttle
//! (or rate-limit) access to clients unlinkably.
//!
//! ### Compatibility
//!
//! API Unstable:
//!
//! - [`crate::VERSION`] = "0.1.0" compliant with [draft-v01].
//!
//! [draft-v01]: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/01/
//!
//! ## Setup
//!
//! Using the [`suites::P256`] suite, the Issuer generates a [`SecretKey`] at random, and publishes the
//! [`IssuerParams`] parameters.
//!
//! ```rust
//! # #[cfg(feature = "suite_p256")]
//! # {
//! # fn main() -> Result<(), arc::ArcError> {
//! use arc::{SecretKey, suites::P256 as S};
//! use rand::rngs::ThreadRng;
//! let csrng = &mut ThreadRng::default();
//! let key = SecretKey::<S>::new(csrng);
//! let params = key.issuer_params()?;
//! # Ok(())
//! # } // main
//! # } // cfg
//! ```
//!
//! ## Credential Issuance
//!
//! Client requests a [`Credential`] to the Issuer.
//! The credential is bound to an arbitrary `REQUEST_CONTEXT`.
//!
//! ```rust
//! # #[cfg(feature = "suite_p256")]
//! # {
//! # fn main() -> Result<(), arc::ArcError> {
//! # use arc::{SecretKey, suites::P256 as S};
//! # use rand::rngs::ThreadRng;
//! # let csrng = &mut ThreadRng::default();
//! # let key = SecretKey::<S>::new(csrng);
//! # let params = key.issuer_params()?;
//! use arc::{Credential, CredentialRequest, CredentialResponse};
//! //   Client (params)                    Issuer (key)
//! //       |                                 |
//! //  [ Request ]                            |
//! const REQUEST_CONTEXT: &[u8] = b"RequestContext";
//! let (request, secrets) = CredentialRequest::new(csrng, REQUEST_CONTEXT)?;
//! //       |                                 |
//! //       |-------  CredentialRequest  ---->|
//! //       |                                 |
//! //       |                           [ Response ]
//! let response = CredentialResponse::new(csrng, &key, request.clone())?;
//! //       |                                 |
//! //       |<------  CredentialResponse  ----|
//! //       |                                 |
//! //  [ Finalize ]                           |
//! let credential = Credential::new(&params, request, secrets, response)?;
//! //       |                                 |
//! //   Credential                         (nothing)
//! # Ok(())
//! # } // main
//! # } // cfg
//! ```
//!
//! ## Credential Presentation
//!
//! The Client uses the [`Credential`] to generate a [`State`] bound to a presentation context.
//! The [`State`] produces at most `N` presentations.
//! The Issuer uses its [`SecretKey`] to verify a given [`Presentation`].
//!
//! ```rust
//! # #[cfg(feature = "suite_p256")]
//! # {
//! # fn main() -> Result<(), arc::ArcError> {
//! # use core::num::NonZero;
//! # use arc::{SecretKey, suites::P256 as S};
//! # use rand::rngs::ThreadRng;
//! # let csrng = &mut ThreadRng::default();
//! # let key = SecretKey::<S>::new(csrng);
//! # let params = key.issuer_params()?;
//! # use arc::{Credential, CredentialRequest, CredentialResponse};
//! # let (request, secrets) = CredentialRequest::new(csrng, REQUEST_CONTEXT)?;
//! # let response = CredentialResponse::new(csrng, &key, request.clone())?;
//! # let credential = Credential::new(&params, request, secrets, response)?;
//! //   Client (credential)               Issuer (key)
//! //       |                                 |
//! const N: NonZero<u32> = NonZero::new(3).expect("non-zero presentation limit");
//! const REQUEST_CONTEXT: &[u8] = b"RequestContext";
//! const PRESENTATION_CONTEXT: &[u8] = b"PresentationContext";
//! let mut state = credential.presentation_state(N, PRESENTATION_CONTEXT)?;
//! //       |                                 |
//! // +---------------------------------------------+
//! // |  LOOP (N times)                             |
//! // |     |                                 |     |
//! // |  [ Present ]                          |     |
//! let presentation = state.present(csrng)?;
//! // |     |                                 |     |
//! // |     |--------  Presentation  -------->|     |
//! // |     |                                 |     |
//! // |     |                            [ Verify ] |
//! let result = presentation.verify(&key, REQUEST_CONTEXT, N, PRESENTATION_CONTEXT);
//! // |     |                                 |     |
//! // |     |<-------  Result(Ok/Err) --------|     |
//! // |     |                                 |     |
//! assert!(result.is_ok());
//! // |                                             |
//! // +---------------------------------------------+
//! # result
//! # } // main
//! # } // cfg
//! ```
//!
//! ## Suites Supported
//!
//! Implementations of the [`Suite`] trait allow specifying the algebraic
//! group to use.
//!
//! The library supports the following groups:
//! - [`suites::P256`] the prime group generated by the NIST P256 curve
//!   as defined in [FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5).
//!   Available with `features = ["suite_p256"]`.
//! - [`suites::Ristretto255`], the Ristretto quotient group as defined
//!   in [RFC-9496](https://doi.org/10.17487/RFC9496).
//!   Available with `features = ["suite_ristretto255"]`.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![warn(missing_docs)]
#![warn(clippy::must_use_candidate)]

#[macro_use]
extern crate alloc;

mod kvac;
mod mac;
mod range;
mod serde;
/// Module containing the Suites supported.
pub mod suites;

pub use kvac::{
    ClientSecret, Credential, CredentialRequest, CredentialResponse, IssuerParams, Presentation,
    SecretKey, State,
};

use group::{GroupEncoding, ff::PrimeField, prime::PrimeGroup};
use sigma_proofs::{MultiScalarMul, errors::Error as SigmaError};
use spongefish::{Codec, Encoding, NargDeserialize};
use zeroize::Zeroize;

/// Current crate version.
///
/// Format `0.X.Y` stands for
///
/// - `X`: matches the ARC draft v-X. For example, `0.1.0` matches draft-v01.
/// - `Y`: improvements or new functionality.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Suite represents ARC-specific parameters related to the prime-order group used.
pub trait Suite: Clone {
    /// Suite identifier.
    const NAME: &str;

    /// Context string.
    const CONTEXT: &[u8];

    /// A struct that represents elements of the group.
    type Elt: PrimeGroup<Scalar = Self::Scalar>
        + NargDeserialize
        + Encoding
        + MultiScalarMul
        + Zeroize;

    /// A struct that represents scalars of the group.
    type Scalar: PrimeField + Codec + Zeroize;

    /// First generator of the group.
    fn gen_g() -> Self::Elt;

    /// Second generator of the group.
    fn gen_h() -> Result<Self::Elt, ArcError>;

    /// Hash a message (with a domain separation tag) into a group element.
    fn hash_to_group(msg: &[u8], dst: &[u8]) -> Result<Self::Elt, ArcError>;

    /// Hash a message (with a domain separation tag) into a group scalar.
    fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Self::Scalar, ArcError>;
}

/// Returns the number of bytes of a serialized group element.
pub(crate) fn elt_bytes_len<S: Suite>() -> usize {
    <S::Elt as GroupEncoding>::Repr::default().as_ref().len()
}

/// Returns the number of bytes of a serialized group scalar.
pub(crate) const fn scalar_bytes_len<S: Suite>() -> usize {
    (<S::Scalar as PrimeField>::NUM_BITS as usize + 7) >> 3
}

/// Error identifiers for runtime errors of the library.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArcError {
    /// Deserialization failed.
    DeserializationFailed,
    /// Context length larger than [`u32::MAX`].
    InvalidContextLength,
    /// Presentation limit exceeded.
    LimitExceeded,
    /// Building proof failed.
    ProofFailed,
    /// Error caused by a dependency.
    UnrecognizedError,
    /// Proof verification failed.
    VerificationFailed,
}

impl core::fmt::Display for ArcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeserializationFailed => write!(f, "deserialization failed"),
            Self::InvalidContextLength => write!(f, "context length larger than u32::MAX"),
            Self::LimitExceeded => write!(f, "presentation limit exceeded"),
            Self::ProofFailed => write!(f, "building proof failed"),
            Self::UnrecognizedError => write!(f, "error caused by a dependency"),
            Self::VerificationFailed => write!(f, "proof verification failed"),
        }
    }
}

impl core::error::Error for ArcError {}

impl ArcError {
    pub(crate) fn from_sigma(value: SigmaError) -> Self {
        match value {
            SigmaError::VerificationFailure => ArcError::VerificationFailed,
            SigmaError::InvalidInstanceWitnessPair => ArcError::ProofFailed,
            SigmaError::UnassignedGroupVar { var_debug: _ } => ArcError::ProofFailed,
            _ => Self::UnrecognizedError,
        }
    }
}
