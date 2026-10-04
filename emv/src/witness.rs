use acir::AcirField;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use noirc_abi::{Abi, AbiType, InputMap, input_parser::InputValue};
use num_bigint::BigUint;
use num_integer::Integer;
use provekit_common::{FieldElement, NoirElement, utils::noir_to_native};

use crate::{Card, Error, Result, bin_table::Membership, challenge::Fields};

/// The circuits' `LIMB_BIT_LEN`.
const LIMB_BIT_LEN: usize = 120;
const LIMB_BASE: u128 = 1 << LIMB_BIT_LEN;

pub(crate) fn public_input_map(challenge: &Fields, ca_modulus: &[u8], scope: Fr) -> Result<InputMap> {
    let scheme = challenge.scheme;
    expect_len("ca_modulus", ca_modulus, scheme.ca_pubkey_byte_len())?;
    let ca = BigUint::from_bytes_be(ca_modulus);

    let mut map = InputMap::from([
        (
            "trust_anchors".to_owned(),
            record([
                ("ca_modulus", limbs_value(limbs(&ca, scheme.ca_pubkey_bit_len())?)),
                ("bin_root", native(challenge.bin.map_or_else(Fr::zero, |(root, _)| root.to_field()))),
            ]),
        ),
        (
            "challenge".to_owned(),
            record([
                ("nonce", bytes(&challenge.nonce)),
                ("today_yymm", field(challenge.today.yymm().into())),
                ("scope", native(scope)),
                ("disclosure", field(challenge.bin.map_or(0, |(_, d)| d.bits()).into())),
            ]),
        ),
    ]);
    if let Some(t) = challenge.transaction {
        map.insert(
            "transaction".to_owned(),
            record([("amount_authorised", bytes(&t.amount_authorised)), ("currency_code", bytes(&t.currency_code))]),
        );
    }
    Ok(map)
}

pub(crate) fn input_map(abi: &Abi, challenge: &Fields, ca_modulus: &[u8], scope: Fr, card: &Card, bin: &Membership) -> Result<InputMap> {
    let scheme = challenge.scheme;
    let mut map = public_input_map(challenge, ca_modulus, scope)?;
    map.insert("bin_membership".to_owned(), membership(bin));
    let (issuer_cert, icc_cert) = match card {
        Card::VisaFdda(c) => (&c.issuer_pubkey_cert, &c.icc_pubkey_cert),
        Card::MastercardDda(c) => (&c.issuer_pubkey_cert, &c.icc_pubkey_cert),
    };
    expect_len("issuer_pubkey_cert", issuer_cert, scheme.ca_pubkey_byte_len())?;
    expect_len("icc_pubkey_cert", icc_cert, scheme.issuer_pubkey_byte_len())?;
    let card = match card {
        Card::VisaFdda(c) => record([
            ("issuer_pubkey_cert", bytes(&c.issuer_pubkey_cert)),
            ("issuer_pubkey_exponent", field(c.issuer_pubkey_exponent.into())),
            ("icc_pubkey_cert", bytes(&c.icc_pubkey_cert)),
            ("icc_pubkey_exponent", field(c.icc_pubkey_exponent.into())),
            ("signed_dynamic_app_data", bytes(&c.signed_dynamic_app_data)),
            ("card_auth_related_data", bytes(&c.card_auth_related_data)),
        ]),
        Card::MastercardDda(c) => {
            let capacity = static_data_capacity(abi)?;
            let static_data = &c.static_data_to_authenticate;
            let len = u128::try_from(static_data.len())
                .ok()
                .filter(|_| static_data.len() <= capacity)
                .ok_or(Error::Card("static data exceeds the circuit's bound"))?;
            let mut storage = static_data.clone();
            storage.resize(capacity, 0);
            record([
                ("issuer_pubkey_cert", bytes(&c.issuer_pubkey_cert)),
                ("issuer_pubkey_remainder", bytes(&c.issuer_pubkey_remainder)),
                ("issuer_pubkey_exponent", field(c.issuer_pubkey_exponent.into())),
                ("icc_pubkey_cert", bytes(&c.icc_pubkey_cert)),
                ("icc_pubkey_exponent", field(c.icc_pubkey_exponent.into())),
                ("static_data_to_authenticate", record([("storage", bytes(&storage)), ("len", field(len))])),
                ("signed_dynamic_app_data", bytes(&c.signed_dynamic_app_data)),
            ])
        }
    };
    map.insert("card".to_owned(), card);
    Ok(map)
}

/// In the order ProveKit binds them into a proof: `main`'s public parameters, flattened in the
/// ABI's field order.
pub(crate) fn public_inputs(abi: &Abi, map: &InputMap) -> Result<Vec<FieldElement>> {
    let mut out = Vec::new();
    for p in abi.parameters.iter().filter(|p| p.is_public()) {
        let value = map.get(&p.name).ok_or_else(|| unknown(abi))?;
        flatten(value, &p.typ, &mut out).ok_or_else(|| unknown(abi))?;
    }
    Ok(out)
}

/// The storage length of the circuit's `card.static_data_to_authenticate` bounded vector.
fn static_data_capacity(abi: &Abi) -> Result<usize> {
    let card = abi.parameters.iter().find(|p| p.name == "card").map(|p| &p.typ);
    match card
        .and_then(|t| field_type(t, "static_data_to_authenticate"))
        .and_then(|t| field_type(t, "storage"))
    {
        Some(AbiType::Array { length, .. }) => usize::try_from(*length).ok(),
        _ => None,
    }
    .ok_or_else(|| unknown(abi))
}

/// Where `challenge.scope` is among the flattened public inputs.
pub(crate) fn scope_offset(abi: &Abi) -> Result<usize> {
    let count = |t: &AbiType| usize::try_from(t.field_count()).map_err(|_| unknown(abi));
    let mut offset: usize = 0;
    for p in abi.parameters.iter().filter(|p| p.is_public()) {
        let AbiType::Struct { fields, .. } = &p.typ else {
            offset = offset.saturating_add(count(&p.typ)?);
            continue;
        };
        for (name, typ) in fields {
            if p.name == "challenge" && name == "scope" {
                return Ok(offset);
            }
            offset = offset.saturating_add(count(typ)?);
        }
    }
    Err(unknown(abi))
}

fn field_type<'a>(typ: &'a AbiType, name: &str) -> Option<&'a AbiType> {
    match typ {
        AbiType::Struct { fields, .. } => fields.iter().find(|(n, _)| n == name).map(|(_, t)| t),
        _ => None,
    }
}

fn unknown(abi: &Abi) -> Error {
    Error::UnknownCircuit(abi.parameter_names().into_iter().cloned().collect())
}

fn flatten(value: &InputValue, typ: &AbiType, out: &mut Vec<FieldElement>) -> Option<()> {
    match (value, typ) {
        (InputValue::Field(f), _) => out.push(noir_to_native(*f)),
        (InputValue::Vec(values), AbiType::Array { typ, .. }) => {
            for v in values {
                flatten(v, typ, out)?;
            }
        }
        (InputValue::Struct(values), AbiType::Struct { fields, .. }) => {
            for (name, typ) in fields {
                flatten(values.get(name)?, typ, out)?;
            }
        }
        _ => return None,
    }
    Some(())
}

/// 120-bit little-endian limbs.
fn limbs(n: &BigUint, bits: usize) -> Result<Vec<u128>> {
    let too_wide = |_| Error::Card("modulus is wider than the circuit's");
    let base = BigUint::from(LIMB_BASE);
    let mut rest = n.clone();
    let mut out = Vec::new();
    for _ in 1..bits.div_ceil(LIMB_BIT_LEN) {
        let (quotient, limb) = rest.div_rem(&base);
        out.push(u128::try_from(limb).map_err(too_wide)?);
        rest = quotient;
    }
    out.push(u128::try_from(rest).map_err(too_wide)?);
    Ok(out)
}

fn expect_len(field: &'static str, bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::Length {
            field,
            expected,
            actual: bytes.len(),
        })
    }
}

fn membership(m: &Membership) -> InputValue {
    record([
        ("low", field(m.low.into())),
        ("high", field(m.high.into())),
        ("country", field(m.country.into())),
        ("card_type", field(m.card_type.into())),
        ("brand", field(m.brand.into())),
        ("commercial", field(m.commercial.into())),
        ("slot", field(m.slot.into())),
        ("siblings", InputValue::Vec(m.siblings.iter().copied().map(native).collect())),
    ])
}

fn record<const N: usize>(fields: [(&str, InputValue); N]) -> InputValue {
    InputValue::Struct(fields.into_iter().map(|(name, value)| (name.to_owned(), value)).collect())
}

fn field(v: u128) -> InputValue {
    InputValue::Field(NoirElement::from(v))
}

fn native(f: Fr) -> InputValue {
    InputValue::Field(NoirElement::from_be_bytes_reduce(&f.into_bigint().to_bytes_be()))
}

fn bytes(b: &[u8]) -> InputValue {
    InputValue::Vec(b.iter().map(|&x| field(x.into())).collect())
}

fn limbs_value(limbs: Vec<u128>) -> InputValue {
    InputValue::Vec(limbs.into_iter().map(field).collect())
}
