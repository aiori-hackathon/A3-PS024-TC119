//! Frozen shared JSON schemas and encodings, loaded directly from contracts.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, &'static str>;
pub static SPEC: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../contracts/lib/regional-v1.json")).unwrap()
});
pub static BASELINE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../contracts/protocol-v1.json")).unwrap()
});
static POLICY: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../contracts/schemas/regional-policy-v1.json"
    ))
    .unwrap()
});
static REQUEST: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../contracts/schemas/regional-arc-request-v1.json"
    ))
    .unwrap()
});

pub fn spec_number(key: &str) -> u64 {
    SPEC[key].as_u64().unwrap()
}
pub fn version() -> &'static str {
    SPEC["contract_version"].as_str().unwrap()
}
pub fn canonical(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn encoded(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decoded(value: &str, max: usize) -> Result<Vec<u8>> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err("invalid-input");
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| "invalid-input")?;
    if bytes.is_empty() || bytes.len() > max || encoded(&bytes) != value {
        return Err("invalid-input");
    }
    Ok(bytes)
}
pub fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().ok_or("invalid-input")
}
pub fn exact_keys(v: &Value, keys: &[&str]) -> Result<()> {
    let object = v.as_object().ok_or("invalid-input")?;
    if object.len() != keys.len() || keys.iter().any(|k| !object.contains_key(*k)) {
        return Err("invalid-input");
    }
    Ok(())
}
pub fn hex_string(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn schema_matches(schema: &Value, value: &Value) -> bool {
    if let Some(options) = schema["oneOf"].as_array() {
        return options.iter().filter(|s| schema_matches(s, value)).count() == 1;
    }
    if let Some(c) = schema.get("const")
        && c != value
    {
        return false;
    }
    if let Some(options) = schema["enum"].as_array()
        && !options.contains(value)
    {
        return false;
    }
    match schema["type"].as_str() {
        Some("object") => {
            let Some(object) = value.as_object() else {
                return false;
            };
            let Some(properties) = schema["properties"].as_object() else {
                return false;
            };
            if schema["required"].as_array().is_some_and(|keys| {
                keys.iter()
                    .any(|key| !object.contains_key(key.as_str().unwrap()))
            }) {
                return false;
            }
            if schema["additionalProperties"] == false
                && object.keys().any(|k| !properties.contains_key(k))
            {
                return false;
            }
            object
                .iter()
                .all(|(key, item)| properties.get(key).is_some_and(|s| schema_matches(s, item)))
        }
        Some("string") => {
            let Some(s) = value.as_str() else {
                return false;
            };
            s.is_ascii()
                && schema["minLength"]
                    .as_u64()
                    .is_none_or(|n| s.len() as u64 >= n)
                && schema["maxLength"]
                    .as_u64()
                    .is_none_or(|n| s.len() as u64 <= n)
                && schema["pattern"]
                    .as_str()
                    .is_none_or(|p| regex::Regex::new(p).unwrap().is_match(s))
        }
        Some("integer") => value.as_u64().is_some_and(|n| {
            n <= 9_007_199_254_740_991
                && schema["minimum"].as_u64().is_none_or(|m| n >= m)
                && schema["maximum"].as_u64().is_none_or(|m| n <= m)
        }),
        None => true,
        _ => false,
    }
}
pub fn validate_policy(policy: &Value) -> Result<()> {
    if !schema_matches(&POLICY, policy) || policy["profile"] != "arc" {
        return Err("wrong-policy");
    }
    let start = policy["window_start_ms"].as_u64().ok_or("wrong-policy")?;
    let end = policy["window_end_ms"].as_u64().ok_or("wrong-policy")?;
    if end.checked_sub(start) != Some(spec_number("window_ms"))
        || end > 9_007_199_254_740_991 - BASELINE["guard_ms"].as_u64().unwrap()
    {
        return Err("wrong-policy");
    }
    Ok(())
}
pub fn validate_request(request: &Value) -> Result<()> {
    if !schema_matches(&REQUEST, request) {
        return Err("invalid-input");
    }
    let field = if request["operation"] == "issue" {
        "blinded_request_b64url"
    } else {
        "presentation_b64url"
    };
    decoded(
        text(request, field)?,
        spec_number("arc_blob_max_bytes") as usize,
    )?;
    Ok(())
}
pub fn domain_bytes(domain: &str, fields: &[Value]) -> Vec<u8> {
    let mut values = vec![SPEC["domains"][domain].clone()];
    values.extend_from_slice(fields);
    canonical(&Value::Array(values))
}
pub fn policy_digest(policy: &Value) -> String {
    digest(&domain_bytes("policy", std::slice::from_ref(policy)))
}
pub fn context(policy: &Value, kind: &str) -> Vec<u8> {
    Sha256::digest(domain_bytes(kind, &[json!(policy_digest(policy))])).to_vec()
}
pub fn mac(key: &[u8], direction: &str, operation: &str, body: &Value) -> String {
    let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
    h.update(&domain_bytes(
        "arc_rpc",
        &[json!(direction), json!(operation), body.clone()],
    ));
    h.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn check_mac(
    key: &[u8],
    direction: &str,
    operation: &str,
    body: &Value,
    provided: &str,
) -> bool {
    if !hex_string(provided, 64) {
        return false;
    }
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&provided[i..i + 2], 16).unwrap())
        .collect();
    let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
    h.update(&domain_bytes(
        "arc_rpc",
        &[json!(direction), json!(operation), body.clone()],
    ));
    h.verify_slice(&bytes).is_ok()
}
pub fn frame(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = canonical(value);
    bytes.push(b'\n');
    if bytes.len() > spec_number("rpc_frame_max_bytes") as usize {
        return Err("invalid-input");
    }
    Ok(bytes)
}
/// Returns upon newline without requiring peer EOF. Allocations remain frame bounded.
pub fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Value>> {
    let max = spec_number("rpc_frame_max_bytes") as usize;
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::InvalidData.into())
            };
        }
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if bytes.len() + count > max {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let complete = available[count - 1] == b'\n';
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if complete {
            break;
        }
    }
    let value: Value = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if !canonical_value(&value, 0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if frame(&value).map_err(|_| io::ErrorKind::InvalidData)? != bytes {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(value))
}
fn canonical_value(value: &Value, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    let ascii = |s: &str| s.bytes().all(|b| (b' '..=b'~').contains(&b));
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(n) => n.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991),
        Value::String(s) => ascii(s),
        Value::Array(items) => items.iter().all(|v| canonical_value(v, depth + 1)),
        Value::Object(items) => items
            .iter()
            .all(|(k, v)| !k.is_empty() && ascii(k) && canonical_value(v, depth + 1)),
    }
}
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn window(policy: &Value) -> Result<()> {
    let now = now_ms();
    if now < policy["window_start_ms"].as_u64().unwrap()
        || now >= policy["window_end_ms"].as_u64().unwrap()
    {
        return Err("window-closed");
    }
    Ok(())
}
