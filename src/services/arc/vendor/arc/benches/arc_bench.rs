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
use criterion::{Criterion, criterion_group, criterion_main};
use rand::rngs::ThreadRng;

pub fn suite<S: Suite>(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("{}/suite", S::NAME));

    group.bench_function("gen_g", |b| b.iter(|| S::gen_g()));
    group.bench_function("gen_h", |b| b.iter(|| S::gen_h().is_ok()));
    group.bench_function("hash_to_group ", |b| {
        b.iter(|| S::hash_to_group(b"msg", b"dst").is_ok())
    });
    group.bench_function("hash_to_scalar ", |b| {
        b.iter(|| S::hash_to_scalar(b"msg", b"dst").is_ok())
    });
}

pub fn protocol<S: Suite>(c: &mut Criterion) {
    let prng = &mut ThreadRng::default();
    let key = SecretKey::<S>::new(prng);
    let params = key.issuer_params().expect("bench setup: issuer params");

    const REQUEST_CTX: &[u8] = b"RequestContext";
    let (request, secrets) =
        CredentialRequest::new(prng, REQUEST_CTX).expect("bench setup: request");
    let response =
        CredentialResponse::new(prng, &key, request.clone()).expect("bench setup: response");
    let credential = Credential::new(&params, request.clone(), secrets.clone(), response.clone())
        .expect("bench setup: credential");

    const PRES_LIMIT: NonZero<u32> = NonZero::new(1000).expect("non-zero limit");
    const PRESENTATION_CTX: &[u8] = b"PresentationContext";
    let mut state = credential
        .presentation_state(PRES_LIMIT, PRESENTATION_CTX)
        .expect("bench setup: state");
    let presentation = state.present(prng).expect("bench setup: present");
    presentation
        .verify(&key, REQUEST_CTX, PRES_LIMIT, PRESENTATION_CTX)
        .expect("bench setup: verification");

    let mut group = c.benchmark_group(format!("{}/arc", S::NAME));

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let k0 = SecretKey::<S>::new(prng);
            k0.issuer_params()
        })
    });

    group.bench_function("credential_request", |b| {
        b.iter(|| CredentialRequest::<S>::new(prng, REQUEST_CTX).is_ok())
    });

    group.bench_function("credential_response", |b| {
        b.iter(|| CredentialResponse::new(prng, &key, request.clone()).is_ok())
    });

    group.bench_function("credential", |b| {
        b.iter(|| {
            Credential::new(&params, request.clone(), secrets.clone(), response.clone()).is_ok()
        })
    });

    group.bench_function("present", |b| {
        b.iter(|| {
            let mut state0 = credential
                .presentation_state(PRES_LIMIT, PRESENTATION_CTX)
                .unwrap(); // bench: unwrap acceptable
            state0.present(prng).is_ok()
        })
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            presentation
                .verify(&key, REQUEST_CTX, PRES_LIMIT, PRESENTATION_CTX)
                .is_ok()
        })
    });
}

pub fn run_all<S: Suite>(c: &mut Criterion) {
    suite::<S>(c);
    protocol::<S>(c);
}

fn run_suites(_c: &mut Criterion) {
    #[cfg(feature = "suite_p256")]
    run_all::<arc::suites::P256>(_c);

    #[cfg(feature = "suite_ristretto255")]
    run_all::<arc::suites::Ristretto255>(_c);
}

criterion_group!(benches, run_suites);
criterion_main!(benches);
