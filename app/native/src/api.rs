//! The methods behind `zkemv_call`. Requests are JSON with byte strings in hex; binary inputs
//! and outputs (keys, proofs) travel as raw bytes.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result, anyhow, bail};
use emv::{CaTable, Card, Challenge, Issued, MastercardDda, Proof, ProvingKey, Scheme, Scope, Transaction, VerifyingKey, VisaFdda, YearMonth};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Default)]
struct State {
    proving: HashMap<Scheme, Arc<ProvingKey>>,
    verifying: HashMap<Scheme, Arc<VerifyingKey>>,
    ca: Option<Arc<CaTable>>,
    issued: HashMap<u64, Challenge<Issued>>,
    next_id: u64,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(Mutex::default);

// A panic while holding the lock leaves the maps consistent: every write is a single insert.
fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs `method` on a JSON `input` and a binary `blob`. Returns bytes: JSON, or a proof for `prove`.
pub(crate) fn call(method: &str, input: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let json = |v: serde_json::Value| Ok(v.to_string().into_bytes());
    match method {
        "load_proving_key" => json(load_proving_key(blob)?),
        "load_verifying_key" => json(load_verifying_key(blob)?),
        "load_ca_table" => json(load_ca_table(blob)?),
        "issue" => json(issue(&parse(input)?)?),
        "forget" => json(forget(&parse(input)?)),
        "receive" => json(receive(&parse(input)?)?),
        "check_ca" => json(check_ca(&parse(input)?)?),
        "prove" => prove(parse(input)?),
        "verify" => json(verify(&parse(input)?, blob)?),
        #[cfg(feature = "self-test")]
        "self_test" => json(crate::self_test::run(&parse(input)?)?),
        _ => bail!("unknown method {method}"),
    }
}

fn parse<'a, T: Deserialize<'a>>(input: &'a [u8]) -> Result<T> {
    serde_json::from_slice(input).context("malformed request")
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SchemeName {
    VisaFdda,
    MastercardDda,
}

impl From<SchemeName> for Scheme {
    fn from(s: SchemeName) -> Self {
        match s {
            SchemeName::VisaFdda => Self::VisaFdda,
            SchemeName::MastercardDda => Self::MastercardDda,
        }
    }
}

impl From<Scheme> for SchemeName {
    fn from(s: Scheme) -> Self {
        match s {
            Scheme::VisaFdda => Self::VisaFdda,
            Scheme::MastercardDda => Self::MastercardDda,
        }
    }
}

fn load_proving_key(bytes: &[u8]) -> Result<serde_json::Value> {
    let key = ProvingKey::from_bytes(bytes)?;
    let scheme = key.scheme();
    state().proving.insert(scheme, Arc::new(key));
    Ok(json!({ "scheme": SchemeName::from(scheme) }))
}

fn load_verifying_key(bytes: &[u8]) -> Result<serde_json::Value> {
    let key = VerifyingKey::from_bytes(bytes)?;
    let scheme = key.scheme();
    state().verifying.insert(scheme, Arc::new(key));
    Ok(json!({ "scheme": SchemeName::from(scheme) }))
}

fn load_ca_table(json: &[u8]) -> Result<serde_json::Value> {
    let table = CaTable::from_json(json)?;
    state().ca = Some(Arc::new(table));
    Ok(json!({}))
}

pub(crate) fn proving_key(scheme: Scheme) -> Result<Arc<ProvingKey>> {
    state()
        .proving
        .get(&scheme)
        .cloned()
        .ok_or_else(|| anyhow!("no proving key loaded for {scheme:?}"))
}

pub(crate) fn verifying_key(scheme: Scheme) -> Result<Arc<VerifyingKey>> {
    state()
        .verifying
        .get(&scheme)
        .cloned()
        .ok_or_else(|| anyhow!("no verifying key loaded for {scheme:?}"))
}

fn ca_table() -> Result<Arc<CaTable>> {
    state().ca.clone().ok_or_else(|| anyhow!("no CA table loaded"))
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScopeRequest {
    Unlinkable,
    Verifier,
    Event(#[serde(with = "hex_array")] [u8; 32]),
}

impl From<ScopeRequest> for Scope {
    fn from(s: ScopeRequest) -> Self {
        match s {
            ScopeRequest::Unlinkable => Self::Unlinkable,
            ScopeRequest::Verifier => Self::Verifier,
            ScopeRequest::Event(event) => Self::Event(event),
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct IssueRequest {
    pub(crate) scheme: SchemeName,
    pub(crate) origin: String,
    pub(crate) scope: ScopeRequest,
    pub(crate) year: u16,
    pub(crate) month: u8,
    /// Visa only: `9F02`, 6 bytes.
    #[serde(default, with = "hex_opt")]
    pub(crate) amount: Option<[u8; 6]>,
    /// Visa only: `5F2A`, 2 bytes.
    #[serde(default, with = "hex_opt")]
    pub(crate) currency: Option<[u8; 2]>,
}

pub(crate) fn issue_challenge(r: &IssueRequest) -> Result<Challenge<Issued>> {
    let today = YearMonth::new(r.year, r.month)?;
    let scope = r.scope.into();
    Ok(match (Scheme::from(r.scheme), r.amount, r.currency) {
        (Scheme::VisaFdda, Some(amount), Some(currency)) => Challenge::visa_fdda(&r.origin, scope, today, Transaction { amount, currency })?,
        (Scheme::VisaFdda, _, _) => bail!("visa_fdda needs amount and currency"),
        (Scheme::MastercardDda, None, None) => Challenge::mastercard_dda(&r.origin, scope, today)?,
        (Scheme::MastercardDda, _, _) => bail!("mastercard_dda takes no amount or currency"),
    })
}

/// The app as verifier: keeps the challenge until `verify` or `forget` takes it by id.
fn issue(r: &IssueRequest) -> Result<serde_json::Value> {
    let challenge = issue_challenge(r)?;
    let bytes = const_hex::encode(challenge.to_bytes());
    let mut state = state();
    let id = state.next_id;
    state.next_id = id.wrapping_add(1);
    state.issued.insert(id, challenge);
    Ok(json!({ "id": id, "challenge": bytes }))
}

#[derive(Debug, Deserialize)]
struct IdRequest {
    id: u64,
}

fn forget(r: &IdRequest) -> serde_json::Value {
    state().issued.remove(&r.id);
    json!({})
}

#[derive(Debug, Deserialize)]
struct ReceiveRequest {
    #[serde(with = "const_hex")]
    challenge: Vec<u8>,
    origin: String,
}

/// The prover's view of a challenge: what the tap must send the card.
fn receive(r: &ReceiveRequest) -> Result<serde_json::Value> {
    let c = Challenge::from_bytes(&r.challenge, &r.origin)?;
    let transaction = c.transaction();
    Ok(json!({
        "scheme": SchemeName::from(c.scheme()),
        "nonce": const_hex::encode(c.nonce()),
        "year": c.today().year(),
        "month": c.today().month(),
        "amount": transaction.map(|t| const_hex::encode(t.amount)),
        "currency": transaction.map(|t| const_hex::encode(t.currency)),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case")]
enum CardRequest {
    VisaFdda {
        #[serde(with = "const_hex")]
        issuer_cert: Vec<u8>,
        issuer_exponent: u8,
        #[serde(with = "const_hex")]
        icc_cert: Vec<u8>,
        icc_exponent: u8,
        #[serde(with = "const_hex")]
        static_data: Vec<u8>,
        #[serde(with = "const_hex")]
        sdad: Vec<u8>,
        #[serde(with = "const_hex")]
        card_auth_data: Vec<u8>,
    },
    MastercardDda {
        #[serde(with = "const_hex")]
        issuer_cert: Vec<u8>,
        #[serde(with = "const_hex")]
        issuer_remainder: Vec<u8>,
        issuer_exponent: u8,
        #[serde(with = "const_hex")]
        icc_cert: Vec<u8>,
        icc_exponent: u8,
        #[serde(with = "const_hex")]
        static_data: Vec<u8>,
        #[serde(with = "const_hex")]
        sdad: Vec<u8>,
    },
}

impl From<CardRequest> for Card {
    fn from(c: CardRequest) -> Self {
        match c {
            CardRequest::VisaFdda {
                issuer_cert,
                issuer_exponent,
                icc_cert,
                icc_exponent,
                static_data,
                sdad,
                card_auth_data,
            } => Self::VisaFdda(VisaFdda {
                issuer_cert,
                issuer_exponent,
                icc_cert,
                icc_exponent,
                static_data,
                sdad,
                card_auth_data,
            }),
            CardRequest::MastercardDda {
                issuer_cert,
                issuer_remainder,
                issuer_exponent,
                icc_cert,
                icc_exponent,
                static_data,
                sdad,
            } => Self::MastercardDda(MastercardDda {
                issuer_cert,
                issuer_remainder,
                issuer_exponent,
                icc_cert,
                icc_exponent,
                static_data,
                sdad,
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct CheckCaRequest {
    #[serde(with = "const_hex")]
    challenge: Vec<u8>,
    origin: String,
    #[serde(with = "hex_array")]
    rid: [u8; 5],
    index: u8,
}

/// Whether the loaded CA table holds a key that can prove `challenge` for the card's RID and `8F`.
fn check_ca(r: &CheckCaRequest) -> Result<serde_json::Value> {
    let challenge = Challenge::from_bytes(&r.challenge, &r.origin)?;
    ca_table()?.lookup(&challenge, r.rid, r.index)?;
    Ok(json!({}))
}

#[derive(Debug, Deserialize)]
struct ProveRequest {
    #[serde(with = "const_hex")]
    challenge: Vec<u8>,
    origin: String,
    #[serde(with = "hex_array")]
    rid: [u8; 5],
    /// `8F`: the CA key index the card names.
    index: u8,
    card: CardRequest,
}

/// Returns the proof's bytes. Blocking and CPU-bound.
fn prove(r: ProveRequest) -> Result<Vec<u8>> {
    let challenge = Challenge::from_bytes(&r.challenge, &r.origin)?;
    let ca = ca_table()?.lookup(&challenge, r.rid, r.index)?;
    let card = Card::from(r.card);
    Ok(proving_key(challenge.scheme())?.prove(&challenge, &ca, &card)?.to_bytes()?)
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    id: u64,
    #[serde(with = "hex_array")]
    rid: [u8; 5],
    index: u8,
}

/// Verifies `proof` against the issued challenge `id`, which it consumes.
fn verify(r: &VerifyRequest, proof: &[u8]) -> Result<serde_json::Value> {
    let challenge = state().issued.remove(&r.id).ok_or_else(|| anyhow!("no issued challenge {}", r.id))?;
    let ca = ca_table()?.lookup(&challenge, r.rid, r.index)?;
    let nullifier = verifying_key(challenge.scheme())?.verify(challenge, &ca, &Proof::from_bytes(proof)?)?;
    Ok(json!({ "nullifier": nullifier.map(|n| const_hex::encode(n.to_bytes())) }))
}

mod hex_array {
    use serde::{Deserialize, Deserializer, de::Error};

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let s = <&str>::deserialize(d)?;
        const_hex::decode_to_array(s).map_err(Error::custom)
    }
}

mod hex_opt {
    use serde::{Deserialize, Deserializer, de::Error};

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<Option<[u8; N]>, D::Error> {
        Option::<&str>::deserialize(d)?
            .map(const_hex::decode_to_array)
            .transpose()
            .map_err(Error::custom)
    }
}
