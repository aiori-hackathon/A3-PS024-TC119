use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;
use tokenforge_arc::wire::*;

fn golden() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/fixtures/regional-golden.json"
    ))
    .unwrap()
}
struct Process {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Process {
    fn start(binary: &str) -> Self {
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take().unwrap(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
        }
    }
    fn call(&mut self, value: Value) -> Value {
        self.input.write_all(&frame(&value).unwrap()).unwrap();
        self.input.flush().unwrap();
        read_frame(&mut self.output).unwrap().unwrap()
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
fn rpc(address: &str, key: &[u8], request: &Value) -> Option<Value> {
    let operation = text(request, "operation").unwrap();
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .write_all(
            &frame(&json!({"body":request,"mac":mac(key,"request",operation,request)})).unwrap(),
        )
        .unwrap();
    // The write side intentionally remains open throughout response reading.
    let reply = read_frame(&mut BufReader::new(socket)).ok().flatten()?;
    assert!(check_mac(
        key,
        "response",
        operation,
        &reply["body"],
        text(&reply, "mac").unwrap()
    ));
    assert_eq!(reply["body"]["request_digest"], digest(&canonical(request)));
    Some(reply["body"].clone())
}
fn binding(policy: &Value, bootstrap: &Value, operation: &str) -> Value {
    json!({"contract_version":version(),"run_id":policy["run_id"],"policy_digest":policy_digest(policy),"service_incarnation":bootstrap["service_incarnation"],"request_id":"1".repeat(32),"operation":operation})
}
#[test]
fn frozen_python_node_bytes_and_macs_match_rust() {
    let fixture = golden();
    let policy = &fixture["arc_policy"];
    validate_policy(policy).unwrap();
    assert_eq!(policy_digest(policy), fixture["arc_policy_digest"]);
    let key = Sha256::digest(b"TokenForge-public-fixture-verify-key");
    let request = &fixture["arc_request"];
    validate_request(request).unwrap();
    let request_mac = mac(&key, "request", "verify", request);
    assert_eq!(request_mac, fixture["arc_request_mac"]);
    assert_eq!(
        mac(&key, "response", "verify", &fixture["arc_response"]),
        fixture["arc_reply_mac"]
    );
    assert_eq!(
        String::from_utf8(frame(&json!({"body":request,"mac":request_mac})).unwrap()).unwrap(),
        fixture["arc_request_frame"]
    );
    assert!(!check_mac(
        &key,
        "response",
        "verify",
        request,
        &request_mac
    ));
}
#[test]
fn raw_frames_reject_duplicate_keys_noncanonical_numbers_and_unicode() {
    for bytes in [
        b"{\"a\":1,\"a\":1}\n".as_slice(),
        b"{\"a\":1.0}\n",
        b"{\"a\":-0}\n",
        b"{\"a\":\"\\u0061\"}\n",
        b"{\"a\":\"\\n\"}\n",
        b"{\"a\":1} \n",
        b"{}\n{}\n",
    ] {
        let mut reader = BufReader::new(bytes);
        if bytes == b"{}\n{}\n" {
            assert!(read_frame(&mut reader).unwrap().is_some());
            assert!(read_frame(&mut reader).unwrap().is_some());
        } else {
            assert!(read_frame(&mut reader).is_err());
        }
    }
    assert!(
        read_frame(&mut BufReader::new(
            vec![b'a'; spec_number("rpc_frame_max_bytes") as usize + 1].as_slice()
        ))
        .is_err()
    );
}
#[test]
fn real_process_blind_issue_helper_verify_grants_channels_and_fence() {
    let mut service = Process::start(env!("CARGO_BIN_EXE_arc-service"));
    let issue = address();
    let verify = address();
    let issue_key = [7u8; 32];
    let verify_key = [8u8; 32];
    let bootstrap=service.call(json!({"operation":"bootstrap","run_id":"a".repeat(32),"implementation_revision":env!("TF_ARC_SOURCE_REVISION"),
        "issue_listen":issue,"verify_listen":verify,"issue_key":"07".repeat(32),"verify_key":"08".repeat(32)}));
    assert_eq!(
        decoded(text(&bootstrap, "issuer_params_b64url").unwrap(), 99)
            .unwrap()
            .len(),
        99
    );
    let mut policy = golden()["arc_policy"].clone();
    let now = now_ms();
    policy["window_start_ms"] = json!(now - 10);
    policy["window_end_ms"] = json!(now - 10 + spec_number("window_ms"));
    policy["arc_key_id"] = bootstrap["arc_key_id"].clone();
    policy["arc_implementation_revision"] = bootstrap["arc_implementation_revision"].clone();
    assert_eq!(
        service.call(json!({"operation":"install-policy","policy":policy}))["status"],
        "installed"
    );
    assert_eq!(
        service.call(
            json!({"operation":"enable","lease_sequence":0,"lease_expires_ms":now_ms()+2900})
        )["status"],
        "enabled"
    );
    let mut helper = Process::start(env!("CARGO_BIN_EXE_arc-client-helper"));
    let created=helper.call(json!({"operation":"create-request","policy":policy,"issuer_params_b64url":bootstrap["issuer_params_b64url"]}));
    assert_eq!(created["status"], "created");
    let mut request = binding(&policy, &bootstrap, "issue");
    request["grant_id"] = json!("2".repeat(32));
    request["blinded_request_b64url"] = created["blinded_request_b64url"].clone();
    assert!(rpc(&issue, &verify_key, &request).is_none());
    assert!(rpc(&verify, &verify_key, &request).is_none());
    let issued = rpc(&issue, &issue_key, &request).unwrap();
    assert_eq!(issued["status"], "issued");
    assert_eq!(
        rpc(&issue, &issue_key, &request).unwrap()["code"],
        "grant-used"
    );
    let finalized=helper.call(json!({"operation":"finalize-credential","pending_handle":created["pending_handle"],"credential_response_b64url":issued["credential_response_b64url"]}));
    assert_eq!(finalized["status"], "finalized");
    assert_eq!(helper.call(json!({"operation":"finalize-credential","pending_handle":created["pending_handle"],"credential_response_b64url":issued["credential_response_b64url"]}))["status"],"refused");
    let first = helper
        .call(json!({"operation":"present","wallet_handle":finalized["wallet_handle"],"slot":0}));
    let copied = helper
        .call(json!({"operation":"present","wallet_handle":finalized["wallet_handle"],"slot":0}));
    assert_eq!(first["status"], "presented");
    assert_ne!(first["presentation_b64url"], copied["presentation_b64url"]);
    let mut check = binding(&policy, &bootstrap, "verify");
    check["presentation_b64url"] = first["presentation_b64url"].clone();
    let verified = rpc(&verify, &verify_key, &check).unwrap();
    assert_eq!(verified["status"], "verified");
    check["presentation_b64url"] = copied["presentation_b64url"].clone();
    assert_eq!(
        rpc(&verify, &verify_key, &check).unwrap()["spend_tag_b64url"],
        verified["spend_tag_b64url"]
    );
    check["policy_digest"] = json!("f".repeat(64));
    assert_eq!(
        rpc(&verify, &verify_key, &check).unwrap()["code"],
        "wrong-policy"
    );
    assert_eq!(
        service.call(
            json!({"operation":"heartbeat","lease_sequence":1,"lease_expires_ms":now_ms()+2900})
        )["status"],
        "renewed"
    );
    request["grant_id"] = json!("3".repeat(32));
    let a = request.clone();
    let b = request.clone();
    let endpoint = issue.clone();
    let first = std::thread::spawn(move || rpc(&endpoint, &issue_key, &a).unwrap());
    let second = rpc(&issue, &issue_key, &b).unwrap();
    let first = first.join().unwrap();
    assert_eq!(
        [first, second]
            .iter()
            .filter(|v| v["status"] == "issued")
            .count(),
        1
    );
    for number in 4..=6 {
        request["grant_id"] = json!(format!("{number:032x}"));
        request["blinded_request_b64url"] = json!("AQ");
        assert_eq!(
            rpc(&issue, &issue_key, &request).unwrap()["code"],
            "invalid-proof"
        );
        assert_eq!(
            rpc(&issue, &issue_key, &request).unwrap()["code"],
            "grant-used"
        );
    }
    request["grant_id"] = json!("7".repeat(32));
    assert_eq!(
        rpc(&issue, &issue_key, &request).unwrap()["code"],
        "unavailable"
    );
    check["policy_digest"] = json!(policy_digest(&policy));
    check["presentation_b64url"] = json!("AQ");
    assert_eq!(
        rpc(&verify, &verify_key, &check).unwrap()["code"],
        "invalid-proof"
    );
    assert_eq!(
        service.call(json!({"operation":"fence"}))["status"],
        "fenced"
    );
    check["policy_digest"] = json!(policy_digest(&policy));
    assert_eq!(
        rpc(&verify, &verify_key, &check).unwrap()["code"],
        "unavailable"
    );
    assert_eq!(
        service.call(
            json!({"operation":"enable","lease_sequence":2,"lease_expires_ms":now_ms()+2900})
        )["status"],
        "refused"
    );
}

#[test]
fn expired_control_lease_permanently_fences_generation() {
    let mut service = Process::start(env!("CARGO_BIN_EXE_arc-service"));
    let bootstrap=service.call(json!({"operation":"bootstrap","run_id":"a".repeat(32),"implementation_revision":env!("TF_ARC_SOURCE_REVISION"),"issue_listen":address(),"verify_listen":address(),"issue_key":"09".repeat(32),"verify_key":"0a".repeat(32)}));
    let mut policy = golden()["arc_policy"].clone();
    let now = now_ms();
    policy["window_start_ms"] = json!(now - 10);
    policy["window_end_ms"] = json!(now - 10 + spec_number("window_ms"));
    policy["arc_key_id"] = bootstrap["arc_key_id"].clone();
    policy["arc_implementation_revision"] = bootstrap["arc_implementation_revision"].clone();
    assert_eq!(
        service.call(json!({"operation":"install-policy","policy":policy}))["status"],
        "installed"
    );
    assert_eq!(
        service
            .call(json!({"operation":"enable","lease_sequence":0,"lease_expires_ms":now_ms()+50}))
            ["status"],
        "enabled"
    );
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        service.call(json!({"operation":"status"}))["status"],
        "fenced"
    );
    assert_eq!(
        service.call(
            json!({"operation":"heartbeat","lease_sequence":1,"lease_expires_ms":now_ms()+2900})
        )["status"],
        "refused"
    );
}
