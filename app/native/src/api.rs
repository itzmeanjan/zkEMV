//! The methods behind `zkemv_call`. Requests are JSON with byte strings in hex; binary inputs
//! and outputs (keys, proofs) travel as raw bytes.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result, anyhow, bail};
use emv::{
    BinTable, CaTable, Card, CardType, Challenge, Disclosed, Disclosure, Issued, MastercardDda, Proof, ProvingKey, Scheme, Scope, Transaction, VerifyingKey,
    VisaFdda, YearMonth,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Default)]
struct State {
    proving: HashMap<Scheme, Arc<ProvingKey>>,
    verifying: HashMap<Scheme, Arc<VerifyingKey>>,
    ca: Option<Arc<CaTable>>,
    bins: Option<Arc<BinTable>>,
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
        "load_bin_table" => json(load_bin_table(blob)?),
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

fn load_bin_table(json: &[u8]) -> Result<serde_json::Value> {
    let table = BinTable::from_json(json)?;
    let root = const_hex::encode(table.root().to_bytes());
    state().bins = Some(Arc::new(table));
    Ok(json!({ "root": root }))
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

pub(crate) fn bin_table() -> Result<Arc<BinTable>> {
    state().bins.clone().ok_or_else(|| anyhow!("no BIN table loaded"))
}

/// A BIN table attribute, as named in requests and responses.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AttributeName {
    Country,
    CardType,
    Brand,
    Commercial,
}

impl AttributeName {
    const ALL: [Self; 4] = [Self::Country, Self::CardType, Self::Brand, Self::Commercial];

    fn flag(self) -> Disclosure {
        match self {
            Self::Country => Disclosure::COUNTRY,
            Self::CardType => Disclosure::CARD_TYPE,
            Self::Brand => Disclosure::BRAND,
            Self::Commercial => Disclosure::COMMERCIAL,
        }
    }
}

fn disclosure_of(names: &[AttributeName]) -> Disclosure {
    names.iter().fold(Disclosure::NONE, |d, name| d | name.flag())
}

fn names_of(disclosure: Disclosure) -> Vec<AttributeName> {
    AttributeName::ALL.into_iter().filter(|n| disclosure.contains(n.flag())).collect()
}

/// `null` for each attribute the challenge didn't ask for. The brand is named by `bins`.
fn disclosed_json(d: Disclosed, bins: Option<&BinTable>) -> serde_json::Value {
    let card_type = d.card_type.map(|t| match t {
        CardType::Credit => "credit",
        CardType::Debit => "debit",
        CardType::Prepaid => "prepaid",
    });
    let brand = d.brand.and_then(|code| bins?.brand(code));
    json!({ "country": d.country, "card_type": card_type, "brand": brand, "commercial": d.commercial })
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
    pub(crate) amount_authorised: Option<[u8; 6]>,
    /// Visa only: `5F2A`, 2 bytes.
    #[serde(default, with = "hex_opt")]
    pub(crate) currency_code: Option<[u8; 2]>,
    /// BIN table attributes to ask for, under the loaded BIN table's root. None if absent.
    #[serde(default)]
    pub(crate) disclose: Vec<AttributeName>,
}

pub(crate) fn issue_challenge(r: &IssueRequest) -> Result<Challenge<Issued>> {
    let today = YearMonth::new(r.year, r.month)?;
    let scope = r.scope.into();
    let challenge = match (Scheme::from(r.scheme), r.amount_authorised, r.currency_code) {
        (Scheme::VisaFdda, Some(amount_authorised), Some(currency_code)) => Challenge::visa_fdda(
            &r.origin,
            scope,
            today,
            Transaction {
                amount_authorised,
                currency_code,
            },
        )?,
        (Scheme::VisaFdda, _, _) => bail!("visa_fdda needs amount_authorised and currency_code"),
        (Scheme::MastercardDda, None, None) => Challenge::mastercard_dda(&r.origin, scope, today)?,
        (Scheme::MastercardDda, _, _) => bail!("mastercard_dda takes no amount_authorised or currency_code"),
    };
    let disclosure = disclosure_of(&r.disclose);
    Ok(if disclosure.is_empty() {
        challenge
    } else {
        challenge.disclose(bin_table()?.root(), disclosure)
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
        "amount_authorised": transaction.map(|t| const_hex::encode(t.amount_authorised)),
        "currency_code": transaction.map(|t| const_hex::encode(t.currency_code)),
        "disclose": names_of(c.disclosure()),
    }))
}

/// The card's TLV values, named as `emv`'s [`VisaFdda`] and [`MastercardDda`] fields.
#[derive(Debug, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case")]
enum CardRequest {
    VisaFdda {
        #[serde(with = "const_hex")]
        issuer_pubkey_cert: Vec<u8>,
        issuer_pubkey_exponent: u8,
        #[serde(with = "const_hex")]
        icc_pubkey_cert: Vec<u8>,
        icc_pubkey_exponent: u8,
        #[serde(with = "const_hex")]
        static_data_to_authenticate: Vec<u8>,
        #[serde(with = "const_hex")]
        signed_dynamic_app_data: Vec<u8>,
        #[serde(with = "const_hex")]
        card_auth_related_data: Vec<u8>,
    },
    MastercardDda {
        #[serde(with = "const_hex")]
        issuer_pubkey_cert: Vec<u8>,
        #[serde(with = "const_hex")]
        issuer_pubkey_remainder: Vec<u8>,
        issuer_pubkey_exponent: u8,
        #[serde(with = "const_hex")]
        icc_pubkey_cert: Vec<u8>,
        icc_pubkey_exponent: u8,
        #[serde(with = "const_hex")]
        static_data_to_authenticate: Vec<u8>,
        #[serde(with = "const_hex")]
        signed_dynamic_app_data: Vec<u8>,
    },
}

impl From<CardRequest> for Card {
    fn from(c: CardRequest) -> Self {
        match c {
            CardRequest::VisaFdda {
                issuer_pubkey_cert,
                issuer_pubkey_exponent,
                icc_pubkey_cert,
                icc_pubkey_exponent,
                static_data_to_authenticate,
                signed_dynamic_app_data,
                card_auth_related_data,
            } => Self::VisaFdda(VisaFdda {
                issuer_pubkey_cert,
                issuer_pubkey_exponent,
                icc_pubkey_cert,
                icc_pubkey_exponent,
                static_data_to_authenticate,
                signed_dynamic_app_data,
                card_auth_related_data,
            }),
            CardRequest::MastercardDda {
                issuer_pubkey_cert,
                issuer_pubkey_remainder,
                issuer_pubkey_exponent,
                icc_pubkey_cert,
                icc_pubkey_exponent,
                static_data_to_authenticate,
                signed_dynamic_app_data,
            } => Self::MastercardDda(MastercardDda {
                issuer_pubkey_cert,
                issuer_pubkey_remainder,
                issuer_pubkey_exponent,
                icc_pubkey_cert,
                icc_pubkey_exponent,
                static_data_to_authenticate,
                signed_dynamic_app_data,
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

/// Returns the proof's bytes. Blocking and CPU-bound. Needs the BIN table if the challenge
/// asks for BIN attributes.
fn prove(r: ProveRequest) -> Result<Vec<u8>> {
    let challenge = Challenge::from_bytes(&r.challenge, &r.origin)?;
    let ca = ca_table()?.lookup(&challenge, r.rid, r.index)?;
    let card = Card::from(r.card);
    let bins = state().bins.clone();
    Ok(proving_key(challenge.scheme())?.prove(&challenge, &ca, &card, bins.as_deref())?.to_bytes()?)
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
    let verified = verifying_key(challenge.scheme())?.verify(challenge, &ca, &Proof::from_bytes(proof)?)?;
    Ok(verified_json(&verified))
}

pub(crate) fn verified_json(v: &emv::Verified) -> serde_json::Value {
    let bins = state().bins.clone();
    json!({
        "nullifier": v.nullifier.map(|n| const_hex::encode(n.to_bytes())),
        "bin": disclosed_json(v.bin, bins.as_deref()),
    })
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
