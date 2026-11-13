use rand_core::OsRng;
use std::num::NonZeroU32;
use tokenforge_arc::{Issuer, PendingIssuance};

fn run() -> Result<(), arc::ArcError> {
    // Fixed feasibility fixtures. Production policy must come from K01.
    let request_context = b"tokenforge-feasibility/request";
    let presentation_context = b"tokenforge-feasibility/research-resource";
    let limit = NonZeroU32::new(5).ok_or(arc::ArcError::LimitExceeded)?;
    let issuer = Issuer::generate()?;
    let parameters = issuer.parameters()?;
    let pending = PendingIssuance::begin(request_context)?;
    let request = pending.request_bytes();
    let response = issuer.issue(&request)?;
    let wallet = pending.finalize(&parameters, &response)?;
    let mut state = wallet.presentation_state(limit, presentation_context)?;
    let mut presentation_bytes = 0;

    for _ in 0..limit.get() {
        let wire = state.present(&mut OsRng)?.to_bytes();
        issuer.verify(&wire, request_context, limit, presentation_context)?;
        presentation_bytes = wire.len();
    }

    if !matches!(state.present(&mut OsRng), Err(arc::ArcError::LimitExceeded)) {
        return Err(arc::ArcError::VerificationFailed);
    }

    // Counts and lengths only. Credential material never enters output.
    println!(
        "{{\"check\":\"arc-library-roundtrip\",\"ok\":true,\"suite\":\"P256\",\"verified\":5,\"request_bytes\":{},\"response_bytes\":{},\"presentation_bytes\":{},\"verified_tag_api_available\":true,\"integration_ready\":false}}",
        request.len(),
        response.len(),
        presentation_bytes
    );
    Ok(())
}

fn main() {
    if run().is_err() {
        eprintln!("{{\"check\":\"arc-library-roundtrip\",\"ok\":false}}");
        std::process::exit(1);
    }
}
