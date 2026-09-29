use emv::{Card, MastercardDda, Scheme, Statement, Transaction, VisaFdda};
use serde_json::Value;

/// `ZKEMV_CIRCUITS` overrides the build-time path, e.g. when the bench runs on another device.
fn circuits() -> String {
    std::env::var("ZKEMV_CIRCUITS").unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../circuits").to_owned())
}
const TODAY: u16 = 2609;

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

fn byte_array<const N: usize>(v: &Value) -> [u8; N] {
    let bytes: Vec<u8> = v.as_array().unwrap().iter().map(|b| u8::try_from(b.as_u64().unwrap()).unwrap()).collect();
    bytes.try_into().unwrap()
}

pub(crate) fn tap(scheme: Scheme) -> (Statement, Card) {
    let circuits = circuits();
    let doc = read_json(&format!("{circuits}/fixtures/{}.json", package(scheme)));
    let tag = |t: &str| -> Vec<u8> {
        let el = doc["elements"].as_array().unwrap().iter().find(|e| e["tag"] == t);
        unhex(&el.unwrap_or_else(|| panic!("no tag {t}"))["value"])
    };

    let rid = &doc["selectedAid"].as_str().unwrap()[..10];
    let index = const_hex::encode_upper(tag("8F"));
    let ca_keys = read_json(&format!("{circuits}/fixtures/test-ca-keys.json"));
    let ca = ca_keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["rid"] == rid && k["index"] == index.as_str())
        .unwrap();

    let terminal = &doc["terminal"];
    let statement = Statement {
        ca_modulus: unhex(&ca["modulus"]),
        nonce: byte_array(&terminal["unpredictableNumber"]),
        today: TODAY,
        transaction: (scheme == Scheme::VisaFdda).then(|| Transaction {
            amount: byte_array(&terminal["amountAuthorised"]),
            currency: byte_array(&terminal["currencyCode"]),
        }),
    };
    let card = match scheme {
        Scheme::VisaFdda => Card::VisaFdda(VisaFdda {
            issuer_cert: tag("90"),
            issuer_exponent: tag("9F32")[0],
            icc_cert: tag("9F46"),
            icc_exponent: tag("9F47")[0],
            sdad: tag("9F4B"),
            card_auth_data: tag("9F69"),
        }),
        Scheme::MastercardDda => Card::MastercardDda(MastercardDda {
            issuer_cert: tag("90"),
            issuer_remainder: tag("92"),
            issuer_exponent: tag("9F32")[0],
            icc_cert: tag("9F46"),
            icc_exponent: tag("9F47")[0],
            static_data: static_data(&doc, &tag("9F4A"), &tag("82")),
            sdad: tag("9F4B"),
        }),
    };
    (statement, card)
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
