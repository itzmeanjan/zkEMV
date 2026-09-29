use emv::{CaKey, CaTable, Card, Challenge, Issued, MastercardDda, Received, Scheme, Transaction, VisaFdda, YearMonth};
use num_bigint::BigUint;
use serde_json::Value;
use sha1::{Digest, Sha1};

/// `ZKEMV_CIRCUITS` overrides the build-time path, e.g. when the bench runs on another device.
fn circuits() -> String {
    std::env::var("ZKEMV_CIRCUITS").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../circuits").to_owned())
}

/// Zero USD, as a verifier asks when no money moves.
const TRANSACTION: Transaction = Transaction {
    amount: [0; 6],
    currency: [0x08, 0x40],
};

pub(crate) fn today() -> YearMonth {
    YearMonth::new(2026, 9).unwrap()
}

pub(crate) fn issue(scheme: Scheme, today: YearMonth) -> Challenge<Issued> {
    match scheme {
        Scheme::VisaFdda => Challenge::visa_fdda(today, TRANSACTION),
        Scheme::MastercardDda => Challenge::mastercard_dda(today),
    }
    .unwrap()
}

/// The challenge as the prover reads it.
pub(crate) fn receive(challenge: &Challenge<Issued>) -> Challenge<Received> {
    Challenge::from_bytes(&challenge.to_bytes()).unwrap()
}

pub(crate) fn package(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::VisaFdda => "visa_fdda",
        Scheme::MastercardDda => "mastercard_dda",
    }
}

pub(crate) fn compiled(scheme: Scheme) -> Vec<u8> {
    let path = format!("{}/target/{}.json", circuits(), package(scheme));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}; run `nargo compile --workspace` in circuits/"))
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    const_hex::decode(v.as_str().unwrap()).unwrap()
}

/// The test CA key from `fixtures/test-ca-keys.json`. Its private key is public, via
/// `gen_synthetic.py`'s seed, so only tests may trust it.
pub(crate) fn test_ca_table() -> CaTable {
    let path = format!("{}/fixtures/test-ca-keys.json", circuits());
    CaTable::from_json(&std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

/// The CA key the synthetic tap names, and its card data, as if tapped with `challenge`.
pub(crate) fn tap(challenge: &Challenge<Received>) -> (CaKey, Card) {
    let scheme = challenge.scheme();
    let circuits = circuits();
    let doc = read_json(&format!("{circuits}/fixtures/{}.json", package(scheme)));
    let tag = |t: &str| -> Vec<u8> {
        let el = doc["elements"].as_array().unwrap().iter().find(|e| e["tag"] == t);
        unhex(&el.unwrap_or_else(|| panic!("no tag {t}"))["value"])
    };

    let rid = unhex(&doc["selectedAid"])[..5].try_into().unwrap();
    let ca = test_ca_table().lookup(challenge, rid, tag("8F")[0]).unwrap();

    let terminal_data = match challenge.transaction() {
        Some(t) => [&challenge.nonce()[..], &t.amount, &t.currency, &tag("9F69")].concat(),
        None => challenge.nonce().to_vec(),
    };
    let sdad = resign(&doc["testIccKey"], &tag("9F4B"), &terminal_data);
    let card = match scheme {
        Scheme::VisaFdda => Card::VisaFdda(VisaFdda {
            issuer_cert: tag("90"),
            issuer_exponent: tag("9F32")[0],
            icc_cert: tag("9F46"),
            icc_exponent: tag("9F47")[0],
            sdad,
            card_auth_data: tag("9F69"),
        }),
        Scheme::MastercardDda => Card::MastercardDda(MastercardDda {
            issuer_cert: tag("90"),
            issuer_remainder: tag("92"),
            issuer_exponent: tag("9F32")[0],
            icc_cert: tag("9F46"),
            icc_exponent: tag("9F47")[0],
            static_data: static_data(&doc, &tag("9F4A"), &tag("82")),
            sdad,
        }),
    };
    (ca, card)
}

/// `verify_emv_reference.static_data_to_authenticate`, for records shorter than 256 bytes.
fn static_data(doc: &Value, tag_list: &[u8], aip: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in doc["afl"].as_array().unwrap() {
        let (sfi, first, count) = (
            entry["sfi"].as_u64().unwrap(),
            entry["first"].as_u64().unwrap(),
            entry["odaRecords"].as_u64().unwrap(),
        );
        for rec in first..first + count {
            let label = format!("sfi={sfi} rec={rec}");
            let exchange = doc["exchanges"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"].as_str().unwrap().contains(&label))
                .unwrap();
            let response = unhex(&exchange["response"]);
            let record = &response[..response.len() - 2];
            assert_eq!(record[0], 0x70);
            let (len, at) = match record[1] {
                0x81 => (usize::from(record[2]), 3),
                len if len < 0x80 => (usize::from(len), 2),
                _ => unimplemented!("record length form"),
            };
            out.extend(&record[at..at + len]);
        }
    }
    if tag_list == [0x82] {
        out.extend(aip);
    }
    out
}

/// Re-signs a Book 2 table 17 SDAD for other terminal data: keeps its recovered header and
/// dynamic data, replaces its SHA-1.
fn resign(icc_key: &Value, sdad: &[u8], terminal_data: &[u8]) -> Vec<u8> {
    let n = BigUint::from_bytes_be(&unhex(&icc_key["modulus"]));
    let d = BigUint::from_bytes_be(&unhex(&icc_key["privateExponent"]));
    let mut m = be_bytes(&BigUint::from_bytes_be(sdad).modpow(&BigUint::from(3u8), &n), sdad.len());
    let hash_at = m.len() - 21;
    let digest = Sha1::new().chain_update(&m[1..hash_at]).chain_update(terminal_data).finalize();
    m[hash_at..hash_at + 20].copy_from_slice(&digest);
    be_bytes(&BigUint::from_bytes_be(&m).modpow(&d, &n), sdad.len())
}

fn be_bytes(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    [vec![0; len - bytes.len()], bytes].concat()
}
