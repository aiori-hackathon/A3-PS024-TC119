use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroU32;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokenforge_arc::{Issuer, wire::*};

const REVISION: &str = env!("TF_ARC_SOURCE_REVISION");
fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn lease_ms() -> u64 {
    BASELINE["gateway_common"]["controller_lease_ms"]
        .as_u64()
        .unwrap()
}
struct Runtime {
    issuer: Issuer,
    bootstrap: Value,
    policy: Option<Value>,
    grants: HashSet<String>,
    enabled: bool,
    fenced: bool,
    sequence: Option<u64>,
    lease_deadline: Instant,
    last_wall: u64,
}
impl Runtime {
    fn live(&mut self) -> Result<()> {
        let now = now_ms();
        if now < self.last_wall || (self.enabled && Instant::now() >= self.lease_deadline) {
            self.fenced = true;
            self.enabled = false;
        }
        self.last_wall = now;
        if self.fenced || !self.enabled {
            return Err("unavailable");
        }
        window(self.policy.as_ref().ok_or("unavailable")?)
    }
    fn renew(&mut self, command: &Value, enabling: bool) -> Result<Value> {
        exact_keys(command, &["operation", "lease_sequence"])?;
        let sequence = command["lease_sequence"].as_u64().ok_or("invalid-input")?;
        let now = now_ms();
        if self.fenced || self.policy.is_none() || (enabling && self.sequence.is_some()) {
            return Err("unavailable");
        }
        if !enabling {
            self.live()?;
        }
        if Some(sequence) != self.sequence.map(|n| n.checked_add(1)).unwrap_or(Some(0)) {
            eprintln!(
                "{}",
                json!({"event":"arc-renewal-refused","reason":"sequence","expected_sequence":self.sequence.and_then(|n|n.checked_add(1)).or(Some(0)),"received_sequence":sequence,"service_receive_ms":now})
            );
            return Err("invalid-input");
        }
        window(self.policy.as_ref().unwrap())?;
        let accepted = Instant::now();
        let wall = now_ms();
        if wall < self.last_wall || (self.enabled && accepted >= self.lease_deadline) {
            self.fenced = true;
            self.enabled = false;
            eprintln!(
                "{}",
                json!({"event":"arc-renewal-refused","reason":"expired-or-regressed","received_sequence":sequence,"service_receive_ms":wall})
            );
            return Err("unavailable");
        }
        self.sequence = Some(sequence);
        self.lease_deadline = accepted + Duration::from_millis(lease_ms());
        self.last_wall = wall;
        self.enabled = true;
        Ok(json!({"status":if enabling {"enabled"} else {"renewed"}}))
    }
    fn finish_cryptography(&mut self, result: Value) -> Result<Value> {
        self.live()?;
        Ok(result)
    }
    fn control(&mut self, command: &Value) -> Result<Value> {
        match text(command, "operation")? {
            "install-policy" => {
                exact_keys(command, &["operation", "policy"])?;
                if self.fenced || self.policy.is_some() {
                    return Err("unavailable");
                }
                let policy = &command["policy"];
                validate_policy(policy)?;
                for key in ["run_id", "arc_key_id", "arc_implementation_revision"] {
                    if policy[key] != self.bootstrap[key] {
                        return Err("wrong-policy");
                    }
                }
                self.policy = Some(policy.clone());
                Ok(json!({"status":"installed","policy_digest":policy_digest(policy)}))
            }
            "enable" => self.renew(command, true),
            "heartbeat" => self.renew(command, false),
            "fence" => {
                exact_keys(command, &["operation"])?;
                self.fenced = true;
                self.enabled = false;
                Ok(json!({"status":"fenced"}))
            }
            "status" => {
                exact_keys(command, &["operation"])?;
                let _ = self.live();
                Ok(
                    json!({"status":if self.fenced {"fenced"} else if self.enabled {"enabled"} else if self.policy.is_some() {"installed"} else {"bootstrapped"}}),
                )
            }
            _ => Err("invalid-input"),
        }
    }
    fn execute(&mut self, request: &Value, operation: &str) -> Result<Value> {
        let policy = self.policy.clone().ok_or("unavailable")?;
        if request["run_id"] != policy["run_id"]
            || request["policy_digest"] != policy_digest(&policy)
            || request["service_incarnation"] != self.bootstrap["service_incarnation"]
        {
            return Err("wrong-policy");
        }
        self.live()?;
        let limit = NonZeroU32::new(policy["quota"].as_u64().ok_or("wrong-policy")? as u32).ok_or("wrong-policy")?;
        if operation == "issue" {
            let grant = text(request, "grant_id")?.to_owned();
            if self.grants.contains(&grant) {
                return Err("grant-used");
            }
            if self.grants.len() >= spec_number("admitted_entitlements") as usize {
                return Err("unavailable");
            }
            // Reservation is terminal even if proof checking/signing fails.
            self.grants.insert(grant);
            let blinded = decoded(
                text(request, "blinded_request_b64url")?,
                spec_number("arc_blob_max_bytes") as usize,
            )?;
            let response = self.issuer.issue(&blinded).map_err(|_| "invalid-proof")?;
            self.finish_cryptography(
                json!({"status":"issued","credential_response_b64url":encoded(&response)}),
            )
        } else {
            let proof = decoded(
                text(request, "presentation_b64url")?,
                spec_number("arc_blob_max_bytes") as usize,
            )?;
            let tag = self
                .issuer
                .verify_and_tag(
                    &proof,
                    &context(&policy, "arc_request_context"),
                    limit,
                    &context(&policy, "arc_presentation_context"),
                )
                .map_err(|_| "invalid-proof")?;
            self.finish_cryptography(json!({"status":"verified","spend_tag_b64url":encoded(&tag)}))
        }
    }
}
struct DeadlineReader<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl Read for DeadlineReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(io::ErrorKind::TimedOut)?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}
fn connection(mut stream: TcpStream, runtime: &Arc<Mutex<Runtime>>, key: &[u8], operation: &str) {
    let timeout = Duration::from_millis(spec_number("arc_rpc_timeout_ms"));
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
    {
        return;
    }
    let deadline = Instant::now() + timeout;
    let mut reader = BufReader::new(DeadlineReader {
        stream: &mut stream,
        deadline,
    });
    let frame_value = match read_frame(&mut reader) {
        Ok(Some(v)) => v,
        _ => return,
    };
    if !reader.buffer().is_empty() {
        return;
    }
    drop(reader);
    if exact_keys(&frame_value, &["body", "mac"]).is_err() {
        return;
    }
    let request = &frame_value["body"];
    if validate_request(request).is_err() || request["operation"] != operation {
        return;
    }
    let Ok(provided) = text(&frame_value, "mac") else {
        return;
    };
    if !check_mac(key, "request", operation, request, provided) || Instant::now() >= deadline {
        return;
    }
    let mut reply = request.clone();
    let object = reply.as_object_mut().unwrap();
    object.remove("grant_id");
    object.remove("blinded_request_b64url");
    object.remove("presentation_b64url");
    object.insert("request_digest".into(), json!(digest(&canonical(request))));
    let outcome = runtime
        .lock()
        .map_err(|_| "unavailable")
        .and_then(|mut state| {
            if Instant::now() >= deadline {
                return Err("unavailable");
            }
            state.execute(request, operation)
        });
    let result = outcome.unwrap_or_else(|code| json!({"status":"refused","code":code}));
    reply
        .as_object_mut()
        .unwrap()
        .extend(result.as_object().unwrap().clone());
    let response = json!({"mac":mac(key,"response",operation,&reply),"body":reply});
    if let Some(remaining) = deadline.checked_duration_since(Instant::now())
        && let Ok(bytes) = frame(&response)
    {
        let _ = stream.set_write_timeout(Some(remaining));
        let _ = stream.write_all(&bytes);
    }
}
fn listen(
    listener: TcpListener,
    runtime: Arc<Mutex<Runtime>>,
    key: Vec<u8>,
    operation: &'static str,
) {
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if active.fetch_add(1, Ordering::AcqRel) >= 4 {
                active.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let state = Arc::clone(&runtime);
            let key = key.clone();
            let active = Arc::clone(&active);
            std::thread::spawn(move || {
                connection(stream, &state, &key, operation);
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
}
fn output(value: &Value) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(&frame(value).map_err(|_| io::ErrorKind::InvalidData)?)?;
    stdout.flush()
}
fn startup(command: Value) -> Result<Arc<Mutex<Runtime>>> {
    exact_keys(
        &command,
        &[
            "operation",
            "run_id",
            "implementation_revision",
            "issue_listen",
            "verify_listen",
            "issue_key",
            "verify_key",
        ],
    )?;
    if command["operation"] != "bootstrap"
        || text(&command, "implementation_revision")? != REVISION
        || !hex_string(text(&command, "run_id")?, 32)
    {
        return Err("invalid-input");
    }
    let mut keys = Vec::new();
    for name in ["issue_key", "verify_key"] {
        let value = text(&command, name)?;
        if !hex_string(value, 64) {
            return Err("invalid-input");
        }
        keys.push(
            (0..64)
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>(),
        );
    }
    if keys[0] == keys[1] {
        return Err("invalid-input");
    }
    let issue = TcpListener::bind(text(&command, "issue_listen")?).map_err(|_| "unavailable")?;
    let verify = TcpListener::bind(text(&command, "verify_listen")?).map_err(|_| "unavailable")?;
    let issuer = Issuer::generate().map_err(|_| "unavailable")?;
    let parameters = issuer.parameters().map_err(|_| "unavailable")?;
    if parameters.len() != spec_number("arc_issuer_params_bytes") as usize {
        return Err("unavailable");
    }
    let bootstrap = json!({"contract_version":version(),"run_id":command["run_id"],"service_incarnation":random_id(),
        "arc_implementation_revision":REVISION,"issuer_params_b64url":encoded(&parameters),"arc_key_id":digest(&parameters)});
    let runtime = Arc::new(Mutex::new(Runtime {
        issuer,
        bootstrap: bootstrap.clone(),
        policy: None,
        grants: HashSet::new(),
        enabled: false,
        fenced: false,
        sequence: None,
        lease_deadline: Instant::now(),
        last_wall: now_ms(),
    }));
    listen(issue, Arc::clone(&runtime), keys.remove(0), "issue");
    listen(verify, Arc::clone(&runtime), keys.remove(0), "verify");
    output(&bootstrap).map_err(|_| "unavailable")?;
    Ok(runtime)
}
fn run() -> io::Result<()> {
    let mut input = BufReader::new(io::stdin().lock());
    let initial = read_frame(&mut input)?.ok_or(io::ErrorKind::UnexpectedEof)?;
    let runtime = startup(initial).map_err(|_| io::ErrorKind::InvalidData)?;
    while let Some(command) = read_frame(&mut input)? {
        let reply = runtime
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .control(&command)
            .unwrap_or_else(|code| json!({"status":"refused","code":code}));
        output(&reply)?;
    }
    runtime.lock().map_err(|_| io::ErrorKind::Other)?.fenced = true;
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("ARC service stopped");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    use tokenforge_arc::PendingIssuance;

    fn installed() -> Runtime {
        let issuer = Issuer::generate().unwrap();
        let parameters = issuer.parameters().unwrap();
        let bootstrap = json!({"run_id":"a".repeat(32),"arc_key_id":digest(&parameters),"arc_implementation_revision":REVISION});
        let mut state = Runtime {
            issuer,
            bootstrap: bootstrap.clone(),
            policy: None,
            grants: HashSet::new(),
            enabled: false,
            fenced: false,
            sequence: None,
            lease_deadline: Instant::now(),
            last_wall: now_ms(),
        };
        let mut policy: Value = serde_json::from_str(include_str!(
            "../../../contracts/fixtures/regional-golden.json"
        ))
        .unwrap();
        policy = policy["arc_policy"].clone();
        policy["window_start_ms"] = json!(now_ms() - 10);
        policy["window_end_ms"] =
            json!(policy["window_start_ms"].as_u64().unwrap() + spec_number("window_ms"));
        policy["arc_key_id"] = bootstrap["arc_key_id"].clone();
        policy["arc_implementation_revision"] = bootstrap["arc_implementation_revision"].clone();
        state
            .control(&json!({"operation":"install-policy","policy":policy}))
            .unwrap();
        state
    }

    #[test]
    fn renewal_is_receiver_owned_strictly_sequenced_and_terminal() {
        let mut state = installed();
        let before = Instant::now();
        assert_eq!(
            state
                .control(&json!({"operation":"enable","lease_sequence":0}))
                .unwrap()["status"],
            "enabled"
        );
        assert!(state.lease_deadline >= before + Duration::from_millis(lease_ms()));
        let deadline = state.lease_deadline;
        assert!(
            state
                .control(&json!({"operation":"heartbeat","lease_sequence":0}))
                .is_err()
        );
        assert!(
            state
                .control(&json!({"operation":"heartbeat","lease_sequence":2}))
                .is_err()
        );
        assert_eq!(state.lease_deadline, deadline);
        assert_eq!(
            state
                .control(&json!({"operation":"heartbeat","lease_sequence":1}))
                .unwrap()["status"],
            "renewed"
        );
        state.lease_deadline = Instant::now() - Duration::from_millis(1);
        assert!(
            state
                .control(&json!({"operation":"heartbeat","lease_sequence":2}))
                .is_err()
        );
        assert!(state.fenced);
        assert!(
            state
                .control(&json!({"operation":"enable","lease_sequence":0}))
                .is_err()
        );
    }

    #[test]
    fn window_end_and_post_crypto_expiry_still_refuse() {
        let mut state = installed();
        state
            .control(&json!({"operation":"enable","lease_sequence":0}))
            .unwrap();
        let request = PendingIssuance::begin(b"lease-check").unwrap();
        let response = state.issuer.issue(&request.request_bytes()).unwrap();
        state.lease_deadline = Instant::now() - Duration::from_millis(1);
        assert!(
            state
                .finish_cryptography(
                    json!({"status":"issued","credential_response_b64url":encoded(&response)})
                )
                .is_err()
        );
        assert!(state.fenced);

        let mut state = installed();
        let end = now_ms() - 1;
        state.policy.as_mut().unwrap()["window_start_ms"] = json!(end - spec_number("window_ms"));
        state.policy.as_mut().unwrap()["window_end_ms"] = json!(end);
        assert_eq!(
            state
                .control(&json!({"operation":"enable","lease_sequence":0}))
                .unwrap_err(),
            "window-closed"
        );
        assert!(!state.enabled);
    }
}
