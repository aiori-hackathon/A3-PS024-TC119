//! Targeted regressions for the locally corrected P256 element boundary.
use arc::{Credential, CredentialRequest, CredentialResponse, IssuerParams, Presentation, State};
use rand_core::OsRng;
use std::num::NonZeroU32;
use tokenforge_arc::{Issuer, PendingIssuance};

fn five() -> NonZeroU32 {
    NonZeroU32::new(5).unwrap()
}

fn with_identity(wire: &[u8], offset: usize) -> Vec<u8> {
    let mut changed = wire.to_vec();
    changed[offset..offset + 33].fill(0);
    changed
}

#[test]
fn original_identity_forgery_is_rejected_by_corrected_decoding() {
    use arc_unpatched::{Credential as OriginalCredential, SecretKey, suites::P256};

    // Reproduce the original defect with fresh in-memory test material only.
    let key = SecretKey::<P256>::new(&mut OsRng);
    let parameters = key.issuer_params().unwrap().to_bytes();
    let mut forged = vec![0; 66];
    let mut chosen_scalar = [0; 32];
    chosen_scalar[31] = 1;
    forged.extend(chosen_scalar);
    forged.extend(&parameters[33..66]);
    let credential = OriginalCredential::<P256>::from_bytes(&forged).unwrap();
    assert!(Credential::<arc::suites::P256>::from_bytes(&forged).is_err());

    let mut state = credential.presentation_state(five(), b"resource").unwrap();
    let presentation = state.present(&mut OsRng).unwrap();
    assert!(
        presentation
            .verify(&key, b"unissued", five(), b"resource")
            .is_ok()
    );
    let mut wire = presentation.to_bytes();
    wire.splice(1..1, [0; 32]);
    let parsed = arc_unpatched::Presentation::<P256>::from_bytes(&wire, five()).unwrap();
    assert!(
        parsed
            .verify(&key, b"unissued", five(), b"resource")
            .is_ok()
    );
    assert!(Presentation::<arc::suites::P256>::from_bytes(&wire, five()).is_err());
}

#[test]
fn all_external_group_positions_reject_identity() {
    type P256 = arc::suites::P256;
    let issuer = Issuer::generate().unwrap();
    let parameters = issuer.parameters().unwrap();
    for offset in [0, 33, 66] {
        assert!(IssuerParams::<P256>::from_bytes(&with_identity(&parameters, offset)).is_err());
    }
    let pending = PendingIssuance::begin(b"request").unwrap();
    let request = pending.request_bytes();
    for offset in [0, 33] {
        assert!(CredentialRequest::<P256>::from_bytes(&with_identity(&request, offset)).is_err());
    }
    let response = issuer.issue(&request).unwrap();
    for offset in [0, 33, 66, 99, 132, 165] {
        assert!(CredentialResponse::<P256>::from_bytes(&with_identity(&response, offset)).is_err());
    }
    let wallet = pending.finalize(&parameters, &response).unwrap();
    let mut state = wallet.presentation_state(five(), b"resource").unwrap();
    let state_wire = state.to_bytes();
    for offset in [0, 33, 98, 131] {
        assert!(State::<P256>::from_bytes(&with_identity(&state_wire, offset)).is_err());
    }
    let wire = state.present(&mut OsRng).unwrap().to_bytes();
    for offset in (0..8).map(|index| index * 33) {
        let changed = with_identity(&wire, offset);
        assert!(Presentation::<P256>::from_bytes(&changed, five()).is_err());
        assert!(
            issuer
                .verify_and_tag(&changed, b"request", five(), b"resource")
                .is_err()
        );
    }
}

#[test]
fn unsupported_limits_and_malformed_parameters_are_rejected() {
    let issuer = Issuer::generate().unwrap();
    let pending = PendingIssuance::begin(b"request").unwrap();
    let response = issuer.issue(&pending.request_bytes()).unwrap();
    assert!(pending.finalize(&[0; 99], &response).is_err());
    let pending = PendingIssuance::begin(b"request").unwrap();
    let response = issuer.issue(&pending.request_bytes()).unwrap();
    let wallet = pending
        .finalize(&issuer.parameters().unwrap(), &response)
        .unwrap();
    assert!(
        wallet
            .presentation_state(NonZeroU32::new(1).unwrap(), b"resource")
            .is_err()
    );
}
