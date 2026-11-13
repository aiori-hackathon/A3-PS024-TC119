use arc::{ArcError, Presentation};
use rand_core::OsRng;
use std::num::NonZeroU32;
use tokenforge_arc::{Issuer, PendingIssuance, Wallet};

const REQUEST_CONTEXT: &[u8] = b"feasibility/current-admission-domain";
const PRESENTATION_CONTEXT: &[u8] = b"feasibility/research-resource";

fn five() -> NonZeroU32 {
    NonZeroU32::new(5).unwrap()
}

fn issued_wallet(issuer: &Issuer) -> Wallet {
    let client = PendingIssuance::begin(REQUEST_CONTEXT).unwrap();
    let response = issuer.issue(&client.request_bytes()).unwrap();
    client
        .finalize(&issuer.parameters().unwrap(), &response)
        .unwrap()
}

#[test]
fn blind_issuance_produces_five_verifiable_presentations() {
    let issuer = Issuer::generate();
    let client = issued_wallet(&issuer);
    let mut state = client
        .presentation_state(five(), PRESENTATION_CONTEXT)
        .unwrap();

    for _ in 0..5 {
        let wire = state.present(&mut OsRng).unwrap().to_bytes();
        issuer
            .verify(&wire, REQUEST_CONTEXT, five(), PRESENTATION_CONTEXT)
            .unwrap();
    }
    assert!(matches!(
        state.present(&mut OsRng),
        Err(ArcError::LimitExceeded)
    ));
}

#[test]
fn wrong_key_context_limit_and_modified_proof_are_rejected() {
    let issuer = Issuer::generate();
    let other_issuer = Issuer::generate();
    let client = issued_wallet(&issuer);
    let mut state = client
        .presentation_state(five(), PRESENTATION_CONTEXT)
        .unwrap();
    let wire = state.present(&mut OsRng).unwrap().to_bytes();

    assert!(
        other_issuer
            .verify(&wire, REQUEST_CONTEXT, five(), PRESENTATION_CONTEXT)
            .is_err()
    );
    assert!(
        issuer
            .verify(
                &wire,
                b"other-request-context",
                five(),
                PRESENTATION_CONTEXT
            )
            .is_err()
    );
    assert!(
        issuer
            .verify(&wire, REQUEST_CONTEXT, five(), b"other-resource")
            .is_err()
    );
    assert!(
        issuer
            .verify(
                &wire,
                REQUEST_CONTEXT,
                NonZeroU32::new(6).unwrap(),
                PRESENTATION_CONTEXT
            )
            .is_err()
    );

    let mut changed = wire;
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        issuer
            .verify(&changed, REQUEST_CONTEXT, five(), PRESENTATION_CONTEXT)
            .is_err()
    );
}

#[test]
fn exact_serialization_rejects_truncation_trailing_bytes_and_empty_requests() {
    let issuer = Issuer::generate();
    assert!(issuer.issue(&[]).is_err());
    let pending = PendingIssuance::begin(REQUEST_CONTEXT).unwrap();
    let mut request = pending.request_bytes();
    request.push(0);
    assert!(issuer.issue(&request).is_err());

    let client = issued_wallet(&issuer);
    let mut state = client
        .presentation_state(five(), PRESENTATION_CONTEXT)
        .unwrap();
    let mut wire = state.present(&mut OsRng).unwrap().to_bytes();
    assert!(
        Presentation::<arc::suites::P256>::from_bytes(&wire[..wire.len() - 1], five()).is_err()
    );
    wire.push(0);
    assert!(
        issuer
            .verify(&wire, REQUEST_CONTEXT, five(), PRESENTATION_CONTEXT)
            .is_err()
    );
}

#[test]
fn copied_wallets_generate_different_proofs_for_the_same_slot() {
    let issuer = Issuer::generate();
    let client = issued_wallet(&issuer);
    let mut first = client
        .presentation_state(five(), PRESENTATION_CONTEXT)
        .unwrap();
    let mut copied = client
        .presentation_state(five(), PRESENTATION_CONTEXT)
        .unwrap();
    for _ in 0..5 {
        let a = first.present(&mut OsRng).unwrap().to_bytes();
        let b = copied.present(&mut OsRng).unwrap().to_bytes();
        assert!(a != b, "fresh randomness changes presentation bytes");
        issuer
            .verify(&a, REQUEST_CONTEXT, five(), PRESENTATION_CONTEXT)
            .unwrap();
        issuer
            .verify(&b, REQUEST_CONTEXT, five(), PRESENTATION_CONTEXT)
            .unwrap();
        // Pinned P256 serialization observation for K01 review. The upstream
        // public API currently has no method returning a verified tag.
        assert!(
            a[99..132] == b[99..132],
            "same slot retains its protocol tag"
        );
    }
}
