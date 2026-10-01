//! Drives the C ABI as the app does. Needs `circuits/target/*.json` (`nargo compile --workspace`).

use std::sync::Once;

use serde_json::{Value, json};
use zkemv::{zkemv_call, zkemv_free};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn call(method: &str, input: &Value, blob: &[u8]) -> Result<Vec<u8>, String> {
    let input = if input.is_null() { Vec::new() } else { input.to_string().into_bytes() };
    // SAFETY: each pointer is valid for its length for the call.
    let result = unsafe { zkemv_call(method.as_ptr(), method.len(), input.as_ptr(), input.len(), blob.as_ptr(), blob.len()) };
    let data = if result.data.len == 0 {
        Vec::new()
    } else {
        // SAFETY: the library returned `len` readable bytes at `ptr`.
        unsafe { std::slice::from_raw_parts(result.data.ptr, result.data.len) }.to_vec()
    };
    // SAFETY: returned by `zkemv_call`, freed once.
    unsafe { zkemv_free(result.data) };
    if result.status == 0 {
        Ok(data)
    } else {
        Err(String::from_utf8(data).unwrap())
    }
}

fn call_json(method: &str, input: &Value, blob: &[u8]) -> Result<Value, String> {
    call(method, input, blob).map(|out| serde_json::from_slice(&out).unwrap())
}

fn setup() {
    static KEYS: Once = Once::new();
    KEYS.call_once(|| {
        for package in ["visa_fdda", "mastercard_dda"] {
            let path = format!("{ROOT}/circuits/target/{package}.json");
            let circuit = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}; run `nargo compile --workspace` in circuits/"));
            let (pk, vk) = emv::prepare(&circuit).unwrap();
            assert_eq!(
                call_json("load_proving_key", &Value::Null, &pk.to_bytes().unwrap()).unwrap(),
                json!({ "scheme": package })
            );
            assert_eq!(
                call_json("load_verifying_key", &Value::Null, &vk.to_bytes().unwrap()).unwrap(),
                json!({ "scheme": package })
            );
        }
        let table = std::fs::read(format!("{ROOT}/data/certificate-authority-public-keys.json")).unwrap();
        call_json("load_ca_table", &Value::Null, &table).unwrap();
    });
}

fn issue_visa() -> Value {
    call_json(
        "issue",
        &json!({ "scheme": "visa_fdda", "origin": "zkemv.test", "scope": "verifier", "year": 2026, "month": 9, "amount": "000000000100", "currency": "0356" }),
        &[],
    )
    .unwrap()
}

#[test]
fn self_test_proves_and_verifies_each_scheme() {
    setup();
    for scheme in ["visa_fdda", "mastercard_dda"] {
        let run = || call_json("self_test", &json!({ "scheme": scheme, "origin": "zkemv.test", "year": 2026, "month": 9 }), &[]).unwrap();
        let (first, second) = (run(), run());
        assert_eq!(first["scheme"], scheme);
        assert!(first["proof_bytes"].as_u64().unwrap() > 0);
        assert!(first["prove_ms"].as_f64().unwrap() > 0.0);
        assert!(first["nullifier"].is_string());
        assert_eq!(first["nullifier"], second["nullifier"], "one card, one verifier scope");
    }
}

#[test]
fn receive_returns_what_the_tap_sends() {
    setup();
    let issued = issue_visa();
    let received = call_json("receive", &json!({ "challenge": issued["challenge"], "origin": "zkemv.test" }), &[]).unwrap();
    assert_eq!(received["scheme"], "visa_fdda");
    assert_eq!(received["nonce"].as_str().unwrap().len(), 8);
    assert_eq!(received["amount"], "000000000100");
    assert_eq!(received["currency"], "0356");
    assert_eq!((received["year"].as_u64(), received["month"].as_u64()), (Some(2026), Some(9)));
}

#[test]
fn forget_drops_the_issued_challenge() {
    setup();
    let id = issue_visa()["id"].clone();
    call_json("forget", &json!({ "id": id }), &[]).unwrap();
    let err = call_json("verify", &json!({ "id": id, "rid": "a000000003", "index": 9 }), &[]).unwrap_err();
    assert!(err.contains("no issued challenge"), "{err}");
}

#[test]
fn prove_rejects_a_ca_key_outside_the_table() {
    setup();
    let issued = issue_visa();
    let card = json!({ "scheme": "visa_fdda", "issuer_cert": "", "issuer_exponent": 3, "icc_cert": "", "icc_exponent": 3, "static_data": "", "sdad": "", "card_auth_data": "" });
    // `EE` is the test CA: only the self-test trusts it.
    let request = json!({ "challenge": issued["challenge"], "origin": "zkemv.test", "rid": "a000000003", "index": 0xEE, "card": card });
    let err = call("prove", &request, &[]).unwrap_err();
    assert!(err.starts_with("CA key"), "{err}");
}

#[test]
fn check_ca_accepts_only_keys_in_the_table() {
    setup();
    let challenge = issue_visa()["challenge"].clone();
    let check = |index: u8| {
        call_json(
            "check_ca",
            &json!({ "challenge": challenge, "origin": "zkemv.test", "rid": "a000000003", "index": index }),
            &[],
        )
    };
    check(0x09).unwrap();
    assert!(check(0xEE).unwrap_err().starts_with("CA key"));
}

#[test]
fn rejects_malformed_calls() {
    for (method, input, expected) in [
        ("nope", Value::Null, "unknown method"),
        ("issue", Value::Null, "malformed request"),
        (
            "issue",
            json!({ "scheme": "visa_fdda", "origin": "o", "scope": "verifier", "year": 2026, "month": 9 }),
            "needs amount and currency",
        ),
        (
            "issue",
            json!({ "scheme": "mastercard_dda", "origin": "o", "scope": "verifier", "year": 2026, "month": 13 }),
            "not a month",
        ),
        ("receive", json!({ "challenge": "ff", "origin": "o" }), "malformed challenge"),
    ] {
        let err = call(method, &input, &[]).unwrap_err();
        assert!(err.contains(expected), "{method}: {err}");
    }
    assert!(call("load_proving_key", &Value::Null, b"not a key").is_err());
}
