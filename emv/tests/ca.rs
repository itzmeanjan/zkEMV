use emv::{CaTable, Challenge, Error, Issued, Scheme, Scope, Transaction, YearMonth};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};

const VISA: [u8; 5] = Scheme::VisaFdda.rid();
const MASTERCARD: [u8; 5] = Scheme::MastercardDda.rid();

fn challenge(scheme: Scheme, year: u16, month: u8) -> Challenge<Issued> {
    let today = YearMonth::new(year, month).unwrap();
    match scheme {
        Scheme::VisaFdda => Challenge::visa_fdda(
            "verifier.example",
            Scope::Verifier,
            today,
            Transaction {
                amount: [0; 6],
                currency: [0x08, 0x40],
            },
        ),
        Scheme::MastercardDda => Challenge::mastercard_dda("verifier.example", Scope::Verifier, today),
    }
    .unwrap()
}

fn now(scheme: Scheme) -> Challenge<Issued> {
    challenge(scheme, 2026, 9)
}

/// The repository's table: 182 keys from third-party lists.
fn data_table() -> CaTable {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../data/certificate-authority-public-keys.json");
    CaTable::from_json(&std::fs::read(path).unwrap()).unwrap()
}

/// A key entry of the table format, with its checksum.
fn key(rid: [u8; 5], index: u8, exponent: &[u8], modulus: &[u8], expires: Option<&str>) -> Value {
    let checksum = Sha1::new()
        .chain_update(rid)
        .chain_update([index])
        .chain_update(modulus)
        .chain_update(exponent)
        .finalize();
    json!({
        "rid": const_hex::encode_upper(rid),
        "index": const_hex::encode_upper([index]),
        "exponent": const_hex::encode_upper(exponent),
        "modulus": const_hex::encode_upper(modulus),
        "checksum": const_hex::encode_upper(checksum),
        "expires": expires,
    })
}

fn table(keys: &[Value]) -> emv::Result<CaTable> {
    CaTable::from_json(json!({ "keys": keys }).to_string().as_bytes())
}

fn modulus(first: u8) -> Vec<u8> {
    [vec![first], vec![0x5A; 247]].concat()
}

/// Every key in the table is trusted, test keys too: Visa `94` and Mastercard `EF` fit the
/// circuits. Visa `08` is 1408 bits, too narrow.
#[test]
fn lookup_trusts_every_key_of_the_circuits_width() {
    let data = data_table();
    for (scheme, index) in [
        (Scheme::VisaFdda, 0x09),
        (Scheme::VisaFdda, 0x94),
        (Scheme::MastercardDda, 0x06),
        (Scheme::MastercardDda, 0xEF),
    ] {
        let ca = data.lookup(&now(scheme), scheme.rid(), index).unwrap();
        assert_eq!((ca.scheme(), ca.modulus().len()), (scheme, 248));
    }
    let err = data.lookup(&now(Scheme::VisaFdda), VISA, 0x08).unwrap_err();
    assert!(matches!(err, Error::CaKey(_)), "{err}");
}

#[test]
fn rid_must_be_the_challenges_scheme() {
    let data = data_table();
    for (scheme, rid, index) in [(Scheme::MastercardDda, VISA, 0x09), (Scheme::VisaFdda, MASTERCARD, 0x06)] {
        let err = data.lookup(&now(scheme), rid, index).unwrap_err();
        assert!(matches!(err, Error::CaKey(_)), "{err}");
    }
}

/// Mastercard `06` is listed at 1984 and 2048 bits; `F5` is 1984 bits with exponent 65537.
#[test]
fn lookup_takes_only_the_circuits_width_and_exponent_3() {
    let data = data_table();
    let ca = data.lookup(&now(Scheme::MastercardDda), MASTERCARD, 0x06).unwrap();
    assert_eq!(ca.modulus().len(), 248);
    let err = data.lookup(&now(Scheme::MastercardDda), MASTERCARD, 0xF5).unwrap_err();
    assert!(matches!(err, Error::CaKey(_)), "{err}");

    // 248 bytes, but fewer than 1984 bits.
    for short in [modulus(0x7F), vec![0; 248]] {
        let table = table(&[key(VISA, 0x01, &[3], &short, None)]).unwrap();
        let err = table.lookup(&now(Scheme::VisaFdda), VISA, 0x01).unwrap_err();
        assert!(matches!(err, Error::CaKey(_)), "{err}");
    }
}

#[test]
fn keys_are_valid_through_their_expiry_month() {
    // Both expire 2028-12-31 in `data/`.
    let data = data_table();
    for (scheme, index) in [(Scheme::VisaFdda, 0x09), (Scheme::MastercardDda, 0x06)] {
        data.lookup(&challenge(scheme, 2028, 12), scheme.rid(), index).unwrap();
        let err = data.lookup(&challenge(scheme, 2029, 1), scheme.rid(), index).unwrap_err();
        assert!(matches!(err, Error::CaKey(_)), "{err}");
    }

    let table = table(&[
        key(VISA, 0x01, &[3], &modulus(0x80), Some("2026-09-15")),
        key(VISA, 0x02, &[3], &modulus(0x80), None),
    ])
    .unwrap();
    table.lookup(&challenge(Scheme::VisaFdda, 2026, 9), VISA, 0x01).unwrap();
    assert!(table.lookup(&challenge(Scheme::VisaFdda, 2026, 10), VISA, 0x01).is_err());
    table.lookup(&challenge(Scheme::VisaFdda, 2099, 12), VISA, 0x02).unwrap();
}

#[test]
fn malformed_tables_are_errors() {
    let good = key(VISA, 0x01, &[3], &modulus(0x80), None);
    let with = |field: &str, value: Value| {
        let mut k = good.clone();
        k[field] = value;
        k
    };
    let mut bad_checksum = good.clone();
    bad_checksum["modulus"] = json!(const_hex::encode_upper(modulus(0x81)));

    let invalid: Vec<Vec<u8>> = [
        b"not json".to_vec(),
        br#"{"tables": []}"#.to_vec(),
        json!({ "keys": [with("modulus", json!("XYZ"))] }).to_string().into_bytes(),
        json!({ "keys": [with("rid", json!("A0000000"))] }).to_string().into_bytes(),
        json!({ "keys": [with("index", json!("0102"))] }).to_string().into_bytes(),
        json!({ "keys": [with("checksum", Value::Null)] }).to_string().into_bytes(),
        json!({ "keys": [bad_checksum] }).to_string().into_bytes(),
        json!({ "keys": [with("expires", json!("2028-13-31"))] }).to_string().into_bytes(),
        json!({ "keys": [with("expires", json!("2028-12"))] }).to_string().into_bytes(),
        json!({ "keys": [with("expires", json!("28-12-31"))] }).to_string().into_bytes(),
        json!({ "keys": [with("expires", json!(2028))] }).to_string().into_bytes(),
        // Two 1984-bit keys under one RID and index: a lookup would be ambiguous.
        json!({ "keys": [good.clone(), key(VISA, 0x01, &[3], &modulus(0x81), None)] })
            .to_string()
            .into_bytes(),
    ]
    .into();
    for json in invalid {
        let err = CaTable::from_json(&json).unwrap_err();
        assert!(matches!(err, Error::CaTable(_)), "{}: {err}", String::from_utf8_lossy(&json));
    }

    // The same RID and index at another width, as Mastercard `06`, is fine.
    table(&[good, key(VISA, 0x01, &[3], &[0x80; 256], None)]).unwrap();
}
