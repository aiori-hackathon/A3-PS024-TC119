use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::io::{self, BufReader, Write};
use std::num::NonZeroU32;
use tokenforge_arc::{PendingIssuance, Wallet, wire::*};

struct Helper {
    started: bool,
    policy: Option<Value>,
    parameters: Vec<u8>,
    pending: Option<(String, PendingIssuance)>,
    wallet: Option<(String, Wallet)>,
    next_slot: u64,
}
fn handle() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Helper {
    fn command(&mut self, command: &Value) -> Result<Value> {
        match text(command, "operation")? {
            "create-request" => {
                exact_keys(command, &["operation", "policy", "issuer_params_b64url"])?;
                if self.started {
                    return Err("unavailable");
                }
                validate_policy(&command["policy"])?;
                window(&command["policy"])?;
                let parameters = decoded(
                    text(command, "issuer_params_b64url")?,
                    spec_number("arc_issuer_params_bytes") as usize,
                )?;
                if parameters.len() != spec_number("arc_issuer_params_bytes") as usize
                    || digest(&parameters) != text(&command["policy"], "arc_key_id")?
                {
                    return Err("wrong-policy");
                }
                // Validate all three public group elements before creating client state.
                let parsed = arc::IssuerParams::<arc::suites::P256>::from_bytes(&parameters)
                    .map_err(|_| "invalid-input")?;
                if parsed.to_bytes() != parameters {
                    return Err("invalid-input");
                }
                self.started = true;
                let pending =
                    PendingIssuance::begin(&context(&command["policy"], "arc_request_context"))
                        .map_err(|_| "unavailable")?;
                let id = handle();
                let blinded = encoded(&pending.request_bytes());
                self.pending = Some((id.clone(), pending));
                self.policy = Some(command["policy"].clone());
                self.parameters = parameters;
                Ok(json!({"status":"created","pending_handle":id,"blinded_request_b64url":blinded}))
            }
            "finalize-credential" => {
                exact_keys(
                    command,
                    &["operation", "pending_handle", "credential_response_b64url"],
                )?;
                if self
                    .pending
                    .as_ref()
                    .is_none_or(|(id, _)| Some(id.as_str()) != command["pending_handle"].as_str())
                {
                    return Err("invalid-input");
                }
                // Taking ownership makes uncertain/failed finalization terminal.
                let (_, pending) = self.pending.take().unwrap();
                window(self.policy.as_ref().ok_or("unavailable")?)?;
                let response = decoded(
                    text(command, "credential_response_b64url")?,
                    spec_number("arc_blob_max_bytes") as usize,
                )?;
                let wallet = pending
                    .finalize(&self.parameters, &response)
                    .map_err(|_| "invalid-proof")?;
                let id = handle();
                self.wallet = Some((id.clone(), wallet));
                Ok(json!({"status":"finalized","wallet_handle":id}))
            }
            "present" => {
                if command.get("slot").is_some() {
                    exact_keys(command, &["operation", "wallet_handle", "slot"])?;
                } else {
                    exact_keys(command, &["operation", "wallet_handle"])?;
                }
                let (id, wallet) = self.wallet.as_ref().ok_or("unavailable")?;
                if Some(id.as_str()) != command["wallet_handle"].as_str() {
                    return Err("invalid-input");
                }
                let policy = self.policy.as_ref().unwrap();
                window(policy)?;
                let slot = match command.get("slot") {
                    Some(v) => v.as_u64().ok_or("invalid-input")?,
                    None => self.next_slot,
                };
                let quota = spec_number("quota");
                if slot >= quota {
                    return Err("exhausted");
                }
                // Reconstructing a selected slot models a copied/rolled-back wallet while
                // retaining every secret inside this owning client process.
                let mut state = wallet
                    .presentation_state(
                        NonZeroU32::new(quota as u32).unwrap(),
                        &context(policy, "arc_presentation_context"),
                    )
                    .map_err(|_| "unavailable")?;
                let mut proof = Vec::new();
                for _ in 0..=slot {
                    proof = state
                        .present(&mut OsRng)
                        .map_err(|_| "unavailable")?
                        .to_bytes();
                }
                if command.get("slot").is_none() {
                    self.next_slot += 1;
                }
                Ok(json!({"status":"presented","presentation_b64url":encoded(&proof)}))
            }
            _ => Err("invalid-input"),
        }
    }
}
fn run() -> io::Result<()> {
    let mut helper = Helper {
        started: false,
        policy: None,
        parameters: Vec::new(),
        pending: None,
        wallet: None,
        next_slot: 0,
    };
    let mut input = BufReader::new(io::stdin().lock());
    while let Some(command) = read_frame(&mut input)? {
        let value = helper
            .command(&command)
            .unwrap_or_else(|code| json!({"status":"refused","code":code}));
        let mut output = io::stdout().lock();
        output.write_all(&frame(&value).map_err(|_| io::ErrorKind::InvalidData)?)?;
        output.flush()?;
    }
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("ARC helper stopped");
        std::process::exit(1);
    }
}
