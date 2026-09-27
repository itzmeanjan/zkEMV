use std::sync::OnceLock;

use emv::{
    Card, Error, MastercardDda, Proof, ProvingKey, Scheme, Statement, Transaction, VerifyingKey,
    VisaFastDda, prepare,
};
use provekit_common::{FieldElement, NoirProof, file};
use serde_json::Value;

const CIRCUITS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../circuits");
const TODAY: u16 = 2609;

fn package(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::VisaFastDda => "visa_fast_dda",
        Scheme::MastercardDda => "mastercard_dda",
    }
}

fn read_json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    const_hex::decode(v.as_str().unwrap()).unwrap()
}

fn byte_array<const N: usize>(v: &Value) -> [u8; N] {
    let bytes: Vec<u8> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    bytes.try_into().unwrap()
}

/// Keys go through a bytes round trip, so every test also covers key serialization.
fn keys(scheme: Scheme) -> &'static (ProvingKey, VerifyingKey) {
    static VISA: OnceLock<(ProvingKey, VerifyingKey)> = OnceLock::new();
    static MASTERCARD: OnceLock<(ProvingKey, VerifyingKey)> = OnceLock::new();
    let cell = match scheme {
        Scheme::VisaFastDda => &VISA,
        Scheme::MastercardDda => &MASTERCARD,
    };
    cell.get_or_init(|| {
        let path = format!("{CIRCUITS}/target/{}.json", package(scheme));
        let compiled = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("{path}: {e}; run `nargo compile --workspace` in circuits/")
        });
        let (pk, vk) = prepare(&compiled).unwrap();
        let pk = ProvingKey::from_bytes(&pk.to_bytes().unwrap()).unwrap();
        let vk = VerifyingKey::from_bytes(&vk.to_bytes().unwrap()).unwrap();
        assert_eq!((pk.scheme(), vk.scheme()), (scheme, scheme));
        (pk, vk)
    })
}

fn tap(scheme: Scheme) -> (Statement, Card) {
    let doc = read_json(&format!("{CIRCUITS}/fixtures/{}.json", package(scheme)));
    let tag = |t: &str| -> Vec<u8> {
        let el = doc["elements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["tag"] == t);
        unhex(&el.unwrap_or_else(|| panic!("no tag {t}"))["value"])
    };

    let rid = &doc["selectedAid"].as_str().unwrap()[..10];
    let index = const_hex::encode_upper(tag("8F"));
    let ca_keys = read_json(&format!("{CIRCUITS}/fixtures/test-ca-keys.json"));
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
        transaction: (scheme == Scheme::VisaFastDda).then(|| Transaction {
            amount: byte_array(&terminal["amountAuthorised"]),
            currency: byte_array(&terminal["currencyCode"]),
        }),
    };
    let card = match scheme {
        Scheme::VisaFastDda => Card::VisaFastDda(VisaFastDda {
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
                0x81 => (record[2] as usize, 3),
                len if len < 0x80 => (len as usize, 2),
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

fn proof(scheme: Scheme) -> &'static Proof {
    static VISA: OnceLock<Proof> = OnceLock::new();
    static MASTERCARD: OnceLock<Proof> = OnceLock::new();
    let cell = match scheme {
        Scheme::VisaFastDda => &VISA,
        Scheme::MastercardDda => &MASTERCARD,
    };
    cell.get_or_init(|| {
        let (statement, card) = tap(scheme);
        let proof = keys(scheme).0.prove(&statement, &card).unwrap();
        Proof::from_bytes(&proof.to_bytes().unwrap()).unwrap()
    })
}

#[test]
fn visa_proves_and_verifies() {
    let (statement, _) = tap(Scheme::VisaFastDda);
    keys(Scheme::VisaFastDda)
        .1
        .verify(&statement, proof(Scheme::VisaFastDda))
        .unwrap();
}

#[test]
fn mastercard_proves_and_verifies() {
    let (statement, _) = tap(Scheme::MastercardDda);
    keys(Scheme::MastercardDda)
        .1
        .verify(&statement, proof(Scheme::MastercardDda))
        .unwrap();
}

#[test]
fn other_nonce_is_rejected() {
    for scheme in [Scheme::VisaFastDda, Scheme::MastercardDda] {
        let (mut statement, _) = tap(scheme);
        statement.nonce[0] ^= 1;
        assert!(matches!(
            keys(scheme).1.verify(&statement, proof(scheme)),
            Err(Error::StatementMismatch)
        ));
    }
}

#[test]
fn other_ca_key_is_rejected() {
    let (mut statement, _) = tap(Scheme::MastercardDda);
    statement.ca_modulus[100] ^= 1;
    assert!(matches!(
        keys(Scheme::MastercardDda)
            .1
            .verify(&statement, proof(Scheme::MastercardDda)),
        Err(Error::StatementMismatch)
    ));
}

#[test]
fn other_amount_or_date_is_rejected() {
    let (statement, _) = tap(Scheme::VisaFastDda);
    let mut amount = statement.clone();
    amount.transaction.as_mut().unwrap().amount[5] ^= 1;
    let mut today = statement.clone();
    today.today += 1;
    for s in [amount, today] {
        assert!(matches!(
            keys(Scheme::VisaFastDda)
                .1
                .verify(&s, proof(Scheme::VisaFastDda)),
            Err(Error::StatementMismatch)
        ));
    }
}

#[test]
fn proof_is_rejected_by_other_schemes_key() {
    let (statement, _) = tap(Scheme::VisaFastDda);
    assert!(
        keys(Scheme::MastercardDda)
            .1
            .verify(&statement, proof(Scheme::VisaFastDda))
            .is_err()
    );
}

/// Rewriting the public inputs a proof carries, to match another statement, must break
/// the proof itself: ProveKit binds them into the transcript.
#[test]
fn forged_public_inputs_are_rejected() {
    let (mut statement, _) = tap(Scheme::MastercardDda);
    let nonce_at = 17;
    let mut forged: NoirProof =
        file::deserialize(&proof(Scheme::MastercardDda).to_bytes().unwrap()).unwrap();
    statement.nonce[0] ^= 1;
    forged.public_inputs.0[nonce_at] = FieldElement::from(statement.nonce[0]);
    let forged = Proof::from_bytes(&file::serialize(&forged).unwrap()).unwrap();

    let err = keys(Scheme::MastercardDda)
        .1
        .verify(&statement, &forged)
        .unwrap_err();
    assert!(matches!(err, Error::ProveKit(_)), "{err}");
}

#[test]
fn card_of_other_scheme_is_refused() {
    let (statement, card) = tap(Scheme::MastercardDda);
    let err = keys(Scheme::VisaFastDda)
        .0
        .prove(&statement, &card)
        .unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }));
}

#[test]
fn tampered_card_cannot_be_proved() {
    let (statement, mut card) = tap(Scheme::VisaFastDda);
    let Card::VisaFastDda(c) = &mut card else {
        unreachable!()
    };
    c.sdad[64] ^= 1;
    assert!(
        keys(Scheme::VisaFastDda)
            .0
            .prove(&statement, &card)
            .is_err()
    );
}

#[test]
fn transaction_must_match_scheme() {
    let (mut statement, card) = tap(Scheme::VisaFastDda);
    statement.transaction = None;
    assert!(matches!(
        keys(Scheme::VisaFastDda).0.prove(&statement, &card),
        Err(Error::Statement(_))
    ));
}

#[test]
fn zero_ca_modulus_is_an_error() {
    let (mut statement, card) = tap(Scheme::MastercardDda);
    statement.ca_modulus = vec![0; statement.ca_modulus.len()];
    let err = keys(Scheme::MastercardDda)
        .0
        .prove(&statement, &card)
        .unwrap_err();
    assert!(matches!(err, Error::Card(_)), "{err}");
}

#[test]
fn malformed_bytes_are_errors() {
    for bytes in [
        &[][..],
        &[0; 64][..],
        &proof(Scheme::VisaFastDda).to_bytes().unwrap()[..100],
    ] {
        assert!(ProvingKey::from_bytes(bytes).is_err());
        assert!(VerifyingKey::from_bytes(bytes).is_err());
        assert!(Proof::from_bytes(bytes).is_err());
    }
}

#[test]
fn wrong_length_card_fields_are_errors() {
    let (statement, card) = tap(Scheme::MastercardDda);
    let Card::MastercardDda(c) = card else {
        unreachable!()
    };
    let mutations: [fn(&mut MastercardDda); 5] = [
        |c| c.issuer_cert.truncate(10),
        |c| c.icc_cert.clear(),
        |c| c.issuer_remainder.clear(),
        |c| c.sdad.truncate(100),
        |c| c.static_data = vec![0; 300],
    ];
    for mutate in mutations {
        let mut c = c.clone();
        mutate(&mut c);
        assert!(
            keys(Scheme::MastercardDda)
                .0
                .prove(&statement, &Card::MastercardDda(c))
                .is_err()
        );
    }
}
