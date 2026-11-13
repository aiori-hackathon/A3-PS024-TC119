# ARC — Anonymous Rate-Limited Credentials

[![CI](https://github.com/cloudflareresearch/arc/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudflareresearch/arc/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A Rust implementation of **Anonymous Rate-Limited Credentials (ARC)**, a
privacy-preserving protocol that lets a server to throttle or rate-limit access from anonymous clients.

Compliant with [draft-ietf-privacypass-arc-crypto-01](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/01/).

Part of the [Privacy Pass](https://datatracker.ietf.org/wg/privacypass/about/) protocol family.

---

## How it Works?

```ascii
  Client                          Issuer
    |                               |
    |------ CredentialRequest ----->|   Client sends an encrypted, blind request
    |                               |
    |<----- CredentialResponse -----|   Issuer signs without seeing the attributes
    |                               |
[Credential]                        |   Client generates a credential
    |                               |
    |------- nth Presentation ----->|   Client shows a presentation of the credential
    |                               |
    |<------ Ok / Err --------------|   Issuer verifies the presentation
```

---

## Installation

Add this line to the `Cargo.toml` file.

```toml
[dependencies]
arc = { version = "0.1.0", git = "https://github.com/cloudflareresearch/arc/" }
```

### Feature Flags

No default features are selected.

Select the feature that corresponds to the suite instance required.

| Feature | Group | Hash |
|---|---|---|---|
| `suite_p256`         | NIST P-256 (secp256r1) | SHA-256 |
| `suite_ristretto255` | ristretto255           | SHA-512 |

---

## Quick Start

### 1 — Issuer Setup

```rust
use arc::{SecretKey, suites::P256 as S};
use rand::rngs::ThreadRng;

let csrng = &mut ThreadRng::default();
let key = SecretKey::<S>::new(csrng);
let params = key.issuer_params()?;
```

### 2 — Credential Issuance

```rust
use arc::{Credential, CredentialRequest, CredentialResponse};

const REQUEST_CONTEXT: &[u8] = b"example.com/v1";

// Client
let (request, secrets) = CredentialRequest::new(csrng, REQUEST_CONTEXT)?;

// Issuer (receives request over the network)
let response = CredentialResponse::new(csrng, &key, request.clone())?;

// Client (receives response, finalizes)
let credential = Credential::new(&params, request, secrets, response)?;
```

### 3 — Credential Presentation

```rust
let N = core::num::NonZero::new(10)?;
const PRESENTATION_CONTEXT: &[u8] = b"example.com/api/action";

// Client: create a state bound to this context (up to N presentations)
let mut state = credential.presentation_state(N, PRESENTATION_CONTEXT)?;

// Client: produce one unlinkable presentation
let presentation = state.present(csrng)?;

// Issuer: checks presentation for double-spending

// Issuer: verify the presentation
let result = presentation.verify(&key, REQUEST_CONTEXT, N, PRESENTATION_CONTEXT)?;
// Returns Ok(()) if valid and within rate limit.
// Returns Err(Error::VerificationFailed) otherwise.

// Issuer: If presentation is valid, stores the presentation
```

---

## Design

### Cryptographic Building Blocks

| Component | Role |
| --------- | ---- |
| Algebraic MAC (KVAC) | Core [KVAC] credential binding — ties Issuer key to client attributes |
| ElGamal encryption | Blind attribute transmission during issuance |
| Pedersen commitments | Commit to nonce and attributes without revealing them |
| Schnorr Σ-protocols | Zero-knowledge Schnorr proofs via [`sigma-proofs`] + [`spongefish`] |
| Binary range proof | Proves `0 ≤ nonce < N` without revealing the nonce |
| Hash-to-curve | Deterministic hashing to group elements [RFC 9380] |

[KVAC]: https://doi.org/10.1145/2660267.2660328/
[`sigma-proofs`]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/
[`spongefish`]: https://github.com/arkworks-rs/spongefish
[RFC 9380]: https://doi.org/10.17487/RFC9380

---

## Status and Stability

This crate tracks the implementation of the [draft-privacypass-arc-crypto](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/) document.
The API is not yet stable: breaking changes may occur until the specification is finalized.

### `no_std` support

This crate is `#![no_std]` with `extern crate alloc`. All allocations use the
global allocator via `alloc::vec::Vec`.

---

## Security

To report a vulnerability, follow the process in [SECURITY.md](SECURITY.md).

---

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) file.
