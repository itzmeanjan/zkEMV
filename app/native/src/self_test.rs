//! Proves and verifies a synthetic tap from `circuits/fixtures/` with the loaded keys, to
//! time both on the device without a card. The tap's SDAD is re-signed for a fresh
//! challenge with the fixture's test ICC key, as `emv/tests/common/mock.rs` does. Its CA
//! is the test CA, whose private key is public, so the table is used here only. The challenge
//! asks for no BIN attributes: the synthetic PANs are in no real BIN table.

use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use emv::{CaTable, Card, Challenge, MastercardDda, Proof, Received, Scheme, VisaFdda};
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};

use crate::api::{IssueRequest, SchemeName, ScopeRequest, issue_challenge, proving_key, verified_json, verifying_key};

const VISA_FDDA: &[u8] = include_bytes!("../../../circuits/fixtures/visa_fdda.json");
const MASTERCARD_DDA: &[u8] = include_bytes!("../../../circuits/fixtures/mastercard_dda.json");
const TEST_CA_KEYS: &[u8] = include_bytes!("../../../circuits/fixtures/test-ca-keys.json");

#[derive(Debug, Deserialize)]
pub(crate) struct Request {
    scheme: SchemeName,
    origin: String,
    year: u16,
    month: u8,
}

pub(crate) fn run(r: &Request) -> Result<Value> {
    let scheme = Scheme::from(r.scheme);
    let doc: Value = serde_json::from_slice(match scheme {
        Scheme::VisaFdda => VISA_FDDA,
        Scheme::MastercardDda => MASTERCARD_DDA,
    })?;
    let visa = scheme == Scheme::VisaFdda;
    let issued = issue_challenge(&IssueRequest {
        scheme: r.scheme,
        origin: r.origin.clone(),
        scope: ScopeRequest::Verifier,
        year: r.year,
        month: r.month,
        amount_authorised: visa.then_some([0, 0, 0, 0, 1, 0]),
        currency_code: visa.then_some([0x03, 0x56]),
        disclose: Vec::new(),
    })?;
    let received = Challenge::from_bytes(&issued.to_bytes(), &r.origin)?;

    let table = CaTable::from_json(TEST_CA_KEYS)?;
    let rid = unhex(doc.get("selectedAid").context("no selectedAid")?)?
        .get(..5)
        .context("short AID")?
        .try_into()?;
    let index = *tag(&doc, "8F")?.first().context("empty 8F")?;
    let card = tap(&doc, &received)?;
    let (pk, vk) = (proving_key(scheme)?, verifying_key(scheme)?);

    let start = Instant::now();
    let proof = pk.prove(&received, &table.lookup(&received, rid, index)?, &card, None)?;
    let prove = start.elapsed();
    let bytes = proof.to_bytes()?;

    let start = Instant::now();
    let ca = table.lookup(&issued, rid, index)?;
    let verified = vk.verify(issued, &ca, &Proof::from_bytes(&bytes)?)?;
    let verify = start.elapsed();

    let mut out = json!({
        "scheme": r.scheme,
        "prove_ms": prove.as_secs_f64() * 1e3,
        "verify_ms": verify.as_secs_f64() * 1e3,
        "proof_bytes": bytes.len(),
    });
    if let (Some(out), Value::Object(verified)) = (out.as_object_mut(), verified_json(&verified)) {
        out.extend(verified);
    }
    Ok(out)
}

fn unhex(v: &Value) -> Result<Vec<u8>> {
    Ok(const_hex::decode(v.as_str().context("not a hex string")?)?)
}

fn tag(doc: &Value, t: &str) -> Result<Vec<u8>> {
    opt_tag(doc, t)?.ok_or_else(|| anyhow!("no tag {t}"))
}

fn opt_tag(doc: &Value, t: &str) -> Result<Option<Vec<u8>>> {
    let elements = doc["elements"].as_array().context("no elements")?;
    elements.iter().find(|e| e["tag"] == t).map(|e| unhex(&e["value"])).transpose()
}

fn tap(doc: &Value, challenge: &Challenge<Received>) -> Result<Card> {
    let terminal_data = match challenge.transaction() {
        Some(t) => [&challenge.nonce()[..], &t.amount_authorised, &t.currency_code, &tag(doc, "9F69")?].concat(),
        None => challenge.nonce().to_vec(),
    };
    let sdad = resign(&doc["testIccKey"], &tag(doc, "9F4B")?, &terminal_data)?;
    let exponent = |t| tag(doc, t)?.first().copied().context("empty exponent");
    Ok(match challenge.scheme() {
        Scheme::VisaFdda => Card::VisaFdda(VisaFdda {
            issuer_pubkey_cert: tag(doc, "90")?,
            issuer_pubkey_exponent: exponent("9F32")?,
            icc_pubkey_cert: tag(doc, "9F46")?,
            icc_pubkey_exponent: exponent("9F47")?,
            static_data_to_authenticate: static_data(doc, &opt_tag(doc, "9F4A")?.unwrap_or_default(), &tag(doc, "82")?)?,
            signed_dynamic_app_data: sdad,
            card_auth_related_data: tag(doc, "9F69")?,
        }),
        Scheme::MastercardDda => Card::MastercardDda(MastercardDda {
            issuer_pubkey_cert: tag(doc, "90")?,
            issuer_pubkey_remainder: tag(doc, "92")?,
            issuer_pubkey_exponent: exponent("9F32")?,
            icc_pubkey_cert: tag(doc, "9F46")?,
            icc_pubkey_exponent: exponent("9F47")?,
            static_data_to_authenticate: static_data(doc, &tag(doc, "9F4A")?, &tag(doc, "82")?)?,
            signed_dynamic_app_data: sdad,
        }),
    })
}

/// The template `70` values of the AFL's ODA records, then the AIP if `9F4A` is `82`.
fn static_data(doc: &Value, tag_list: &[u8], aip: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for entry in doc["afl"].as_array().context("no AFL")? {
        let field = |k: &str| entry[k].as_u64().ok_or_else(|| anyhow!("AFL entry without {k}"));
        let (sfi, first, count) = (field("sfi")?, field("first")?, field("odaRecords")?);
        for rec in first..first.saturating_add(count) {
            let label = format!("sfi={sfi} rec={rec}");
            let exchange = doc["exchanges"]
                .as_array()
                .context("no exchanges")?
                .iter()
                .find(|e| e["label"].as_str().is_some_and(|l| l.contains(&label)))
                .ok_or_else(|| anyhow!("no record {label}"))?;
            let response = unhex(&exchange["response"])?;
            let record = response.get(..response.len().saturating_sub(2)).context("short response")?;
            let (len, at): (usize, usize) = match record {
                [0x70, 0x81, len, ..] => (usize::from(*len), 3),
                [0x70, len, ..] if *len < 0x80 => (usize::from(*len), 2),
                _ => bail!("record {label} is not a short template 70"),
            };
            out.extend(record.get(at..at.saturating_add(len)).context("truncated record")?);
        }
    }
    if tag_list == [0x82] {
        out.extend(aip);
    }
    Ok(out)
}

/// Re-signs a Book 2 table 17 SDAD for other terminal data: keeps its recovered header and
/// dynamic data, replaces its SHA-1.
fn resign(icc_key: &Value, sdad: &[u8], terminal_data: &[u8]) -> Result<Vec<u8>> {
    let n = BigUint::from_bytes_be(&unhex(&icc_key["modulus"])?);
    let d = BigUint::from_bytes_be(&unhex(&icc_key["privateExponent"])?);
    let mut m = be_bytes(&BigUint::from_bytes_be(sdad).modpow(&BigUint::from(3u8), &n), sdad.len())?;
    let hash_at = m.len().checked_sub(21).context("short SDAD")?;
    let digest = Sha1::new()
        .chain_update(m.get(1..hash_at).context("short SDAD")?)
        .chain_update(terminal_data)
        .finalize();
    m.get_mut(hash_at..hash_at.saturating_add(20)).context("short SDAD")?.copy_from_slice(&digest);
    be_bytes(&BigUint::from_bytes_be(&m).modpow(&d, &n), sdad.len())
}

fn be_bytes(n: &BigUint, len: usize) -> Result<Vec<u8>> {
    let bytes = n.to_bytes_be();
    let pad = len.checked_sub(bytes.len()).context("value wider than the modulus")?;
    Ok([vec![0; pad], bytes].concat())
}
