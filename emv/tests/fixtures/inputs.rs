//! A circuit's inputs from its synthetic tap, as the circuit's test vectors.

use emv::{BinTable, PAN_PREFIX_DIGIT_COUNT, Scheme};
use num_bigint::BigUint;
use serde_json::Value as Json;

use crate::{
    layout::BITS_PER_BYTE,
    merkle,
    synthetic::{Kind, SyntheticTap},
};

/// Pinned, so the generated files don't change every month.
const TODAY_YYMM: u32 = 2609;
/// Any field element; the emv crate derives real ones.
const SCOPE: u32 = 0x5_C09E;
/// The circuits' `DISCLOSE_BIT_LEN`: one bit per BIN attribute.
const DISCLOSE_BIT_LEN: u32 = 4;
const DISCLOSE_ALL: u32 = (1 << DISCLOSE_BIT_LEN) - 1;
/// The circuits' `LIMB_BIT_LEN`.
const LIMB_BIT_LEN: usize = 120;

#[derive(Clone)]
enum Value {
    Bool(bool),
    Int(BigUint),
    Ints(Vec<BigUint>),
    BoundedVec(Vec<BigUint>, usize),
    Struct(&'static str, Vec<(&'static str, Value)>),
}

/// `main`'s parameters, and the ICC modulus the tap certifies, for the circuit tests.
pub(crate) struct Inputs {
    params: Vec<(&'static str, Value)>,
    icc_modulus: Vec<u8>,
}

impl Inputs {
    /// `static_data_capacity` is the circuit's `STATIC_DATA_MAX_BYTE_LEN`.
    pub(crate) fn new(kind: &Kind, synthetic: &SyntheticTap, ca_modulus: &[u8], bin_table: &str, static_data_capacity: usize) -> Self {
        let tap: Json = serde_json::from_str(&synthetic.json).unwrap();
        let bins: Json = serde_json::from_str(bin_table).unwrap();
        let terminal = &tap["terminal"];
        let [nonce, amount, currency] = ["nonce", "amountAuthorised", "currencyCode"].map(|k| bytes_of(&terminal[k]));

        let root = BinTable::from_json(bin_table.as_bytes()).unwrap().root();
        let prefix: u64 = synthetic.pan[..PAN_PREFIX_DIGIT_COUNT].parse().unwrap();
        let range = bins["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| (r["low"].as_u64().unwrap()..=r["high"].as_u64().unwrap()).contains(&prefix))
            .unwrap_or_else(|| panic!("fixtures/bin-table.json: no range holds PAN prefix {prefix}"));
        let siblings = merkle::path(&bins, merkle::slot_of(range));

        let mut params = vec![
            (
                "trust_anchors",
                Value::Struct(
                    "TrustAnchors",
                    vec![
                        ("ca_modulus", Value::Ints(limbs(ca_modulus))),
                        ("bin_root", Value::Int(BigUint::from_bytes_be(&root.to_bytes()))),
                    ],
                ),
            ),
            (
                "challenge",
                Value::Struct(
                    "Challenge",
                    vec![
                        ("nonce", bytes(&nonce)),
                        ("today_yymm", int(TODAY_YYMM)),
                        ("scope", int(SCOPE)),
                        ("disclosure", int(DISCLOSE_ALL)),
                    ],
                ),
            ),
        ];

        let issuer = [("issuer_pubkey_cert", bytes(&tag(&tap, "90")))];
        let icc = [
            ("issuer_pubkey_exponent", int(tag(&tap, "9F32")[0])),
            ("icc_pubkey_cert", bytes(&tag(&tap, "9F46"))),
            ("icc_pubkey_exponent", int(tag(&tap, "9F47")[0])),
        ];
        let sdad = ("signed_dynamic_app_data", bytes(&tag(&tap, "9F4B")));
        let card = match kind.scheme {
            Scheme::VisaFdda => {
                params.push((
                    "transaction",
                    Value::Struct("Transaction", vec![("amount_authorised", bytes(&amount)), ("currency_code", bytes(&currency))]),
                ));
                [&issuer[..], &icc, &[sdad, ("card_auth_related_data", bytes(&tag(&tap, "9F69")))]].concat()
            }
            Scheme::MastercardDda => {
                let static_data = &synthetic.static_data;
                assert!(
                    static_data.len() <= static_data_capacity,
                    "{}: static data exceeds the circuit's bound",
                    kind.package
                );
                let mut storage: Vec<BigUint> = static_data.iter().map(|&b| BigUint::from(b)).collect();
                storage.resize(static_data_capacity, BigUint::ZERO);
                [
                    &issuer[..],
                    &[("issuer_pubkey_remainder", bytes(&tag(&tap, "92")))],
                    &icc,
                    &[("static_data_to_authenticate", Value::BoundedVec(storage, static_data.len())), sdad],
                ]
                .concat()
            }
        };
        params.push(("card", Value::Struct("Card", card)));

        params.push((
            "bin_membership",
            Value::Struct(
                "BinMembership",
                vec![
                    ("low", Value::Int(range["low"].as_u64().unwrap().into())),
                    ("high", Value::Int(range["high"].as_u64().unwrap().into())),
                    ("country", Value::Int(range["country"].as_u64().unwrap().into())),
                    ("card_type", Value::Int(merkle::card_type_code(range).into())),
                    ("brand", Value::Int(merkle::brand_code(&bins, range).into())),
                    ("commercial", Value::Bool(range["commercial"].as_bool().unwrap())),
                    ("slot", Value::Int(merkle::slot_of(range).into())),
                    ("siblings", Value::Ints(siblings)),
                ],
            ),
        ));

        Self {
            params,
            icc_modulus: synthetic.icc_modulus.clone(),
        }
    }

    /// A global per parameter, named after it. `nargo fmt` lays it out.
    pub(crate) fn to_noir(&self) -> String {
        let mut emv_types: Vec<&str> = self
            .params
            .iter()
            .filter(|(name, _)| *name != "card")
            .map(|(_, value)| match value {
                Value::Struct(ty, _) => *ty,
                _ => unreachable!("parameters are structs"),
            })
            .collect();
        emv_types.sort_unstable();
        let icc_modulus = bytes(&self.icc_modulus);

        let mut lines = vec![
            "// Generated by the `emv` crate's fixture generator from the synthetic taps.".to_owned(),
            "use crate::Card;".to_owned(),
            format!("use emv::{{{}}};", emv_types.join(", ")),
            String::new(),
            format!("pub global ICC_MODULUS: [u8; {}] = {};", self.icc_modulus.len(), icc_modulus.noir()),
        ];
        for (name, value) in &self.params {
            let Value::Struct(ty, _) = value else {
                unreachable!("parameters are structs")
            };
            lines.push(format!("\npub global {}: {ty} = {};", name.to_uppercase(), value.noir()));
        }
        lines.join("\n") + "\n"
    }
}

impl Value {
    fn noir(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::Int(n) => format!("{n:#x}"),
            Self::Ints(v) => format!("[{}]", v.iter().map(|n| format!("{n:#x}")).collect::<Vec<_>>().join(", ")),
            Self::BoundedVec(storage, len) => format!("BoundedVec::from_parts({}, {len})", Self::Ints(storage.clone()).noir()),
            Self::Struct(ty, fields) => {
                let fields: Vec<String> = fields.iter().map(|(name, value)| format!("{name}: {}", value.noir())).collect();
                format!("{ty} {{ {} }}", fields.join(", "))
            }
        }
    }
}

/// 120-bit little-endian limbs.
fn limbs(modulus: &[u8]) -> Vec<BigUint> {
    let n = BigUint::from_bytes_be(modulus);
    let mask = (BigUint::from(1_u8) << LIMB_BIT_LEN) - 1_u8;
    (0..(modulus.len() * BITS_PER_BYTE).div_ceil(LIMB_BIT_LEN))
        .map(|i| (&n >> (LIMB_BIT_LEN * i)) & &mask)
        .collect()
}

/// A TLV value; empty if the tap has no such tag.
fn tag(tap: &Json, name: &str) -> Vec<u8> {
    tap["elements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["tag"] == name)
        .map(|e| const_hex::decode(e["value"].as_str().unwrap()).unwrap())
        .unwrap_or_default()
}

fn bytes_of(json: &Json) -> Vec<u8> {
    json.as_array().unwrap().iter().map(|b| u8::try_from(b.as_u64().unwrap()).unwrap()).collect()
}

fn bytes(b: &[u8]) -> Value {
    Value::Ints(b.iter().map(|&x| BigUint::from(x)).collect())
}

fn int(n: impl Into<BigUint>) -> Value {
    Value::Int(n.into())
}
