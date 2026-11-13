//! TokenForge regressions for the corrected input boundary and verified-tag API.
use super::*;
use crate::suites::P256;
use p256::{ProjectivePoint, Scalar};
use rand::rngs::ThreadRng;

fn five() -> Result<NonZero<u32>, ArcError> {
    NonZero::new(5).ok_or(ArcError::VerificationFailed)
}

fn issued_presentation() -> Result<(SecretKey<P256>, Vec<u8>), ArcError> {
    let rng = &mut ThreadRng::default();
    let key = SecretKey::<P256>::new(rng);
    let (request, secret) = CredentialRequest::<P256>::new(rng, b"request")?;
    let response = CredentialResponse::new(rng, &key, request.clone())?;
    let credential = Credential::new(&key.issuer_params()?, request, secret, response)?;
    let mut state = credential.presentation_state(five()?, b"resource")?;
    Ok((key, state.present(rng)?.to_bytes()))
}

#[test]
fn in_memory_identity_forgery_returns_no_verified_tag() -> Result<(), ArcError> {
    let key = SecretKey::<P256>::new(&mut ThreadRng::default());
    let credential = Credential::<P256> {
        u: ProjectivePoint::IDENTITY,
        u_prime: ProjectivePoint::IDENTITY,
        m1: Scalar::ONE,
        x1: key.issuer_params()?.mac_params.x[0],
    };
    let mut state = credential.presentation_state(five()?, b"resource")?;
    let presentation = state.present(&mut ThreadRng::default())?;
    assert!(
        presentation
            .verify(&key, b"unissued", five()?, b"resource")
            .is_err()
    );
    assert!(
        presentation
            .verify_and_tag(&key, b"unissued", five()?, b"resource")
            .is_err()
    );
    Ok(())
}

#[test]
fn every_in_memory_presentation_point_is_checked() -> Result<(), ArcError> {
    let (key, wire) = issued_presentation()?;
    for index in 0..8 {
        let mut presentation = Presentation::<P256>::from_bytes(&wire, five()?)?;
        let point = [
            &mut presentation.inner.u,
            &mut presentation.inner.u_prime_commit,
            &mut presentation.inner.m1_commit,
            &mut presentation.inner.tag,
            &mut presentation.inner.nonce_commit,
        ]
        .into_iter()
        .chain(&mut presentation.inner.d)
        .nth(index)
        .ok_or(ArcError::VerificationFailed)?;
        *point = ProjectivePoint::IDENTITY;
        assert!(
            presentation
                .verify_and_tag(&key, b"request", five()?, b"resource")
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn malformed_in_memory_range_shape_is_rejected() -> Result<(), ArcError> {
    let (key, wire) = issued_presentation()?;
    let mut presentation = Presentation::<P256>::from_bytes(&wire, five()?)?;
    presentation.inner.d.pop();
    assert!(
        presentation
            .verify_and_tag(&key, b"request", five()?, b"resource")
            .is_err()
    );
    Ok(())
}
