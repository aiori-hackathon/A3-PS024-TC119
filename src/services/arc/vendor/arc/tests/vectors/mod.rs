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

use core::num::NonZero;

use arc::{Credential, CredentialRequest, CredentialResponse, SecretKey, Suite};
use rand_core::{
    CryptoRng, Error, RngCore,
    impls::{next_u32_via_fill, next_u64_via_fill},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::serde_as;
use spongefish::{DuplexSpongeInterface as _, instantiations::Shake128};

macro_rules! assert_eq_bytes {
    ($a:expr, $b:expr) => {
        assert_eq!(
            json!(Hex($a.to_vec())).as_str().unwrap(),
            json!(Hex($b.to_vec())).as_str().unwrap()
        )
    };
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct Hex(#[serde_as(as = "serde_with::hex::Hex")] Vec<u8>);

#[derive(Debug, Deserialize)]
struct ServerKeysVector {
    #[serde(flatten)]
    params: IssuerParamsVector,
    #[serde(flatten)]
    private: SecretKeyVector,
}

#[derive(Debug, Deserialize)]
struct IssuerParamsVector {
    #[serde(rename = "X0")]
    x0: Hex,
    #[serde(rename = "X1")]
    x1: Hex,
    #[serde(rename = "X2")]
    x2: Hex,
}

impl IssuerParamsVector {
    fn bytes(self) -> Vec<u8> {
        [self.x0.0, self.x1.0, self.x2.0].concat()
    }
}

#[derive(Debug, Deserialize)]
struct SecretKeyVector {
    x0: Hex,
    x1: Hex,
    x2: Hex,
    xb: Hex,
}

impl SecretKeyVector {
    fn bytes(self) -> Vec<u8> {
        [self.x0.0, self.x1.0, self.x2.0, self.xb.0].concat()
    }
}

#[derive(Debug, Deserialize)]
struct CredentialVector {
    m1: Hex,
    #[serde(rename = "U")]
    u: Hex,
    #[serde(rename = "U_prime")]
    u_prime: Hex,
    #[serde(rename = "X1")]
    x1: Hex,
}

impl CredentialVector {
    fn bytes(self) -> Vec<u8> {
        [self.u.0, self.u_prime.0, self.m1.0, self.x1.0].concat()
    }
}

#[derive(Debug, Deserialize)]
struct CredentialRequestVector {
    #[serde(flatten)]
    client_secrets: ClientSecretVector,
    m1_enc: Hex,
    m2_enc: Hex,
    proof: Hex,
    request_context: Hex,
}

impl CredentialRequestVector {
    fn bytes(self) -> (Vec<u8>, Vec<u8>) {
        (
            [self.m1_enc.0, self.m2_enc.0, self.proof.0].concat(),
            self.client_secrets.bytes(),
        )
    }
}

#[derive(Debug, Deserialize)]
struct ClientSecretVector {
    m1: Hex,
    m2: Hex,
    r1: Hex,
    r2: Hex,
}

impl ClientSecretVector {
    fn bytes(self) -> Vec<u8> {
        [self.m1.0, self.r1.0, self.m2.0, self.r2.0].concat()
    }
}

#[derive(Debug, Deserialize)]
struct CredentialResponseVector {
    #[serde(rename = "enc_U_prime")]
    enc_u_prime: Hex,
    #[serde(rename = "H_aux")]
    h_aux: Hex,
    proof: Hex,
    #[serde(rename = "U")]
    u: Hex,
    #[serde(rename = "X0_aux")]
    x0_aux: Hex,
    #[serde(rename = "X1_aux")]
    x1_aux: Hex,
    #[serde(rename = "X2_aux")]
    x2_aux: Hex,
}

impl CredentialResponseVector {
    fn bytes(self) -> Vec<u8> {
        [
            self.u.0,
            self.enc_u_prime.0,
            self.x0_aux.0,
            self.x1_aux.0,
            self.x2_aux.0,
            self.h_aux.0,
            self.proof.0,
        ]
        .concat()
    }
}

#[derive(Debug, Deserialize)]
struct PresentationVector {
    m1_commit: Hex,
    nonce_commit: Hex,
    presentation_context: Hex,
    proof: Hex,
    tag: Hex,
    #[serde(rename = "U")]
    u: Hex,
    #[serde(rename = "U_prime_commit")]
    u_prime_commit: Hex,
}

impl PresentationVector {
    fn bytes(self) -> Vec<u8> {
        [
            self.u.0,
            self.u_prime_commit.0,
            self.m1_commit.0,
            self.tag.0,
            self.nonce_commit.0,
            self.proof.0,
        ]
        .concat()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct SuiteVector {
    #[serde(rename = "Credential")]
    credential: CredentialVector,
    #[serde(rename = "CredentialRequest")]
    credential_request: CredentialRequestVector,
    #[serde(rename = "CredentialResponse")]
    credential_response: CredentialResponseVector,
    #[serde(rename = "Presentation1")]
    presentation1: PresentationVector,
    #[serde(rename = "Presentation2")]
    presentation2: PresentationVector,
    #[serde(rename = "ServerKey")]
    server_key: ServerKeysVector,
}

struct TestDrng(Shake128);

impl TestDrng {
    fn from_seed(seed_label: &[u8]) -> Self {
        let mut sponge = Shake128::default();
        let mut initial_block = [0u8; 168];
        let domain = b"sigma-proofs/TestDRNG/SHAKE128";
        initial_block[..domain.len()].copy_from_slice(domain);
        sponge.absorb(&initial_block);
        sponge.absorb(&fixed_seed(seed_label));
        Self(sponge)
    }
}

fn fixed_seed(label: &[u8]) -> [u8; 32] {
    if label.len() > 32 {
        panic!("seed label length must be less or equal to 32 bytes")
    }

    let mut seed = [0u8; 32];
    seed[..label.len()].copy_from_slice(label);
    seed
}

impl CryptoRng for TestDrng {}

impl RngCore for TestDrng {
    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.squeeze(dst);
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

pub(crate) fn test_vectors_arc<S: Suite>(v: SuiteVector) {
    const SEED: &[u8] = b"test vector seed";
    let rng = &mut TestDrng::from_seed(SEED);
    let private_key = SecretKey::<S>::new(rng);
    let sk_got = private_key.to_bytes();
    let sk_want = v.server_key.private.bytes();
    assert_eq_bytes!(sk_got, sk_want);

    let issuer_params = private_key.issuer_params().unwrap();
    let ip_got = issuer_params.to_bytes();
    let ip_want = v.server_key.params.bytes();
    assert_eq_bytes!(ip_got, ip_want);

    let request_context = &v.credential_request.request_context.0.clone();
    let (credential_request, client_secrets) = CredentialRequest::<S>::new(rng, request_context)
        .expect("creating CredentialRequest failed");
    let creq_got = credential_request.to_bytes();
    let cs_got = client_secrets.to_bytes();
    let (creq_want, cs_want) = v.credential_request.bytes();
    assert_eq_bytes!(creq_got, creq_want);
    assert_eq_bytes!(cs_got, cs_want);

    let credential_response =
        CredentialResponse::new(rng, &private_key, credential_request.clone())
            .expect("creating CredentialResponse failed");
    let cres_got = credential_response.to_bytes();
    let cres_want = v.credential_response.bytes();
    assert_eq_bytes!(cres_got, cres_want);

    let credential = Credential::new(
        &issuer_params,
        credential_request,
        client_secrets,
        credential_response,
    )
    .expect("creating Credential failed");
    let cred_got = credential.to_bytes();
    let cred_want = v.credential.bytes();
    assert_eq_bytes!(cred_got, cred_want);

    const PRESENTATION_LIMIT: NonZero<u32> = NonZero::new(2).expect("non-zero limit");
    let presentation_context = &v.presentation1.presentation_context.0.clone();

    let mut state = credential
        .presentation_state(PRESENTATION_LIMIT, presentation_context)
        .unwrap();
    let pres1 = state.present(rng).expect("first presentation failed");
    let pres1_result = pres1.verify(
        &private_key,
        request_context,
        PRESENTATION_LIMIT,
        presentation_context,
    );
    assert!(pres1_result.is_ok());

    let p1_got = pres1.to_bytes();
    let p1_want = v.presentation1.bytes();
    assert_eq_bytes!(p1_got, p1_want);

    let pres2 = state.present(rng).expect("second presentation failed");
    let pres2_result = pres2.verify(
        &private_key,
        request_context,
        PRESENTATION_LIMIT,
        presentation_context,
    );
    assert!(pres2_result.is_ok());

    let p2_got = pres2.to_bytes();
    let p2_want = v.presentation2.bytes();
    assert_eq_bytes!(p2_got, p2_want);
}
