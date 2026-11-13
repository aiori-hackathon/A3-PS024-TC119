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

use core::{any::type_name, num::NonZero};

use arc::{
    ClientSecret, Credential, CredentialRequest, CredentialResponse, Presentation, SecretKey,
    State, Suite,
};
use rand::rngs::ThreadRng;

#[macro_export]
macro_rules! all_arc_tests {
    ($suite:ty) => {
        #[test]
        fn happy_path() {
            $crate::protocol::happy_path::<$suite>();
        }
        #[test]
        fn multiple_presentations() {
            $crate::protocol::multiple_presentations::<$suite>();
        }
    };
}

macro_rules! test_serialization {
    ($T:ty, $val:expr $(, $context:expr)?) => {
        let a_bytes = $val.to_bytes();
        let b = <$T>::from_bytes(&a_bytes $(, $context)? )
            .expect(&format!("deserialization of {} failed", type_name::<$T>()));
        let b_bytes = b.to_bytes();
        assert_eq!(a_bytes, b_bytes);
    };
}

pub(crate) fn happy_path<S: Suite>() {
    let req_context = b"RequestContext";
    let csrng = &mut ThreadRng::default();
    let key = SecretKey::<S>::new(csrng);
    test_serialization!(SecretKey::<S>, &key);

    let params = key.issuer_params().unwrap();
    test_serialization!(SecretKey::<S>, &key);

    let (request, secrets) = CredentialRequest::new(csrng, req_context).unwrap();
    test_serialization!(CredentialRequest::<S>, &request);
    test_serialization!(ClientSecret::<S>, &secrets);

    let response = CredentialResponse::new(csrng, &key, request.clone()).unwrap();
    test_serialization!(CredentialResponse::<S>, &response);

    let credential = Credential::new(&params, request, secrets, response).unwrap();
    test_serialization!(Credential::<S>, &credential);

    let pres_limit = NonZero::new(3).expect("non-zero limit");
    let pres_context = b"PresentationContext";

    let mut state = credential
        .presentation_state(pres_limit, pres_context)
        .unwrap();
    test_serialization!(State::<S>, &state);

    assert_eq!(state.used_presentations(), 0);
    assert_eq!(state.remaining_presentations(), pres_limit.get());

    for _ in 0..pres_limit.get() {
        let presentation = state.present(csrng).unwrap();
        test_serialization!(Presentation::<S>, &presentation, pres_limit);

        let result_verify = presentation.verify(&key, req_context, pres_limit, pres_context);
        assert!(result_verify.is_ok());
    }

    assert_eq!(state.used_presentations(), pres_limit.get());
    assert_eq!(state.remaining_presentations(), 0);

    let result = state.present(csrng);
    assert!(result.is_err());
}

pub(crate) fn multiple_presentations<S: Suite>() {
    let request_ctx = b"RequestContext";
    let csrng = &mut ThreadRng::default();
    let key = SecretKey::<S>::new(csrng);
    let params = key.issuer_params().unwrap();

    let (request, secrets) = CredentialRequest::new(csrng, request_ctx).unwrap();
    let response = CredentialResponse::new(csrng, &key, request.clone()).unwrap();
    let credential = Credential::new(&params, request, secrets, response).unwrap();

    let photos_limit = 11.try_into().unwrap();
    let photos_ctx = "photos.example.com".as_bytes();
    let mut state_photos = credential
        .presentation_state(photos_limit, photos_ctx)
        .unwrap();
    let photos1 = state_photos.present(csrng).unwrap();

    let movies_limit = 10.try_into().unwrap();
    let movies_ctx = "movies.example.com".as_bytes();
    let mut state_movies = credential
        .presentation_state(movies_limit, movies_ctx)
        .unwrap();

    let mut result = photos1.verify(&key, request_ctx, photos_limit, photos_ctx);
    assert!(result.is_ok());

    // Check mismatching of verification parameters.
    let key2 = SecretKey::<S>::new(csrng);
    result = photos1.verify(&key2, request_ctx, photos_limit, photos_ctx);
    assert!(result.is_err(), "wrong key");

    result = photos1.verify(&key, b"bad request context", photos_limit, photos_ctx);
    assert!(result.is_err(), "wrong request context");

    result = photos1.verify(&key, request_ctx, movies_limit, photos_ctx);
    assert!(result.is_err(), "wrong presentation limit");

    result = photos1.verify(&key, request_ctx, photos_limit, b"bad presentation context");
    assert!(result.is_err(), "wrong presentation context");

    // Check mismatching of presentation parameters.
    let movies1 = state_movies.present(csrng).unwrap();
    result = movies1.verify(&key, request_ctx, movies_limit, movies_ctx);
    assert!(result.is_ok());

    let movies2 = state_photos.present(csrng).unwrap();
    result = movies2.verify(&key, request_ctx, movies_limit, movies_ctx);
    assert!(result.is_err(), "must fail as generated with a wrong state");

    // Single presentation.
    let single_ctx = "single.example.com".as_bytes();
    const ONE: NonZero<u32> = NonZero::<u32>::MIN;
    let mut state_single = credential.presentation_state(ONE, single_ctx).unwrap();
    let single_presentation = state_single.present(csrng).unwrap();
    result = single_presentation.verify(&key, request_ctx, ONE, single_ctx);
    assert!(result.is_ok());
}
