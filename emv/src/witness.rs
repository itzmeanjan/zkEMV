use std::collections::BTreeMap;

use acir::AcirField;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use noirc_abi::{Abi, AbiType, InputMap, input_parser::InputValue};
use num_bigint::BigUint;
use num_integer::Integer;
use provekit_common::{FieldElement, NoirElement, utils::noir_to_native};

use crate::{Card, Error, Result, bin_table::Membership, challenge::Fields};

const LIMB_BITS: usize = 120;
const LIMB_BASE: u128 = 1 << LIMB_BITS;

pub(crate) fn public_input_map(challenge: &Fields, ca_modulus: &[u8], scope: Fr) -> Result<InputMap> {
    let scheme = challenge.scheme;
    expect_len("ca_modulus", ca_modulus, scheme.ca_bits() / 8)?;
    let ca = BigUint::from_bytes_be(ca_modulus);

    let mut map = InputMap::from([
        ("ca_modulus".to_owned(), limbs_value(limbs(&ca, scheme.ca_bits())?)),
        ("nonce".to_owned(), bytes(&challenge.nonce)),
        ("today".to_owned(), field(challenge.today.yymm().into())),
        ("scope".to_owned(), native(scope)),
        ("bin_root".to_owned(), native(challenge.bin.map_or_else(Fr::zero, |(root, _)| root.to_field()))),
        ("disclose".to_owned(), field(challenge.bin.map_or(0, |(_, d)| d.bits()).into())),
    ]);
    if let Some(t) = challenge.transaction {
        map.insert("amount".to_owned(), bytes(&t.amount));
        map.insert("currency".to_owned(), bytes(&t.currency));
    }
    Ok(map)
}

pub(crate) fn input_map(abi: &Abi, challenge: &Fields, ca_modulus: &[u8], scope: Fr, card: &Card, bin: &Membership) -> Result<InputMap> {
    let scheme = challenge.scheme;
    let mut map = public_input_map(challenge, ca_modulus, scope)?;
    map.insert("bin".to_owned(), membership(bin));
    let (issuer_cert, icc_cert) = match card {
        Card::VisaFdda(c) => (&c.issuer_cert, &c.icc_cert),
        Card::MastercardDda(c) => (&c.issuer_cert, &c.icc_cert),
    };
    expect_len("issuer_cert", issuer_cert, scheme.ca_bits() / 8)?;
    expect_len("icc_cert", icc_cert, scheme.issuer_bits() / 8)?;
    match card {
        Card::VisaFdda(c) => map.extend([
            ("issuer_cert".to_owned(), bytes(&c.issuer_cert)),
            ("issuer_exponent".to_owned(), field(c.issuer_exponent.into())),
            ("icc_cert".to_owned(), bytes(&c.icc_cert)),
            ("icc_exponent".to_owned(), field(c.icc_exponent.into())),
            ("sdad".to_owned(), bytes(&c.sdad)),
            ("card_auth_data".to_owned(), bytes(&c.card_auth_data)),
        ]),
        Card::MastercardDda(c) => {
            let capacity = static_data_capacity(abi)?;
            let len = u128::try_from(c.static_data.len())
                .ok()
                .filter(|_| c.static_data.len() <= capacity)
                .ok_or(Error::Card("static data exceeds the circuit's bound"))?;
            let mut storage = c.static_data.clone();
            storage.resize(capacity, 0);
            let static_data = InputValue::Struct(BTreeMap::from([("storage".to_owned(), bytes(&storage)), ("len".to_owned(), field(len))]));
            map.extend([
                ("issuer_cert".to_owned(), bytes(&c.issuer_cert)),
                ("issuer_remainder".to_owned(), bytes(&c.issuer_remainder)),
                ("issuer_exponent".to_owned(), field(c.issuer_exponent.into())),
                ("icc_cert".to_owned(), bytes(&c.icc_cert)),
                ("icc_exponent".to_owned(), field(c.icc_exponent.into())),
                ("static_data".to_owned(), static_data),
                ("sdad".to_owned(), bytes(&c.sdad)),
            ]);
        }
    }
    Ok(map)
}

/// In the order ProveKit binds them into a proof: `main`'s public parameters, flattened.
pub(crate) fn public_inputs(abi: &Abi, map: &InputMap) -> Result<Vec<FieldElement>> {
    let unknown = || Error::UnknownCircuit(abi.parameter_names().into_iter().cloned().collect());
    let mut out = Vec::new();
    for p in abi.parameters.iter().filter(|p| p.is_public()) {
        let value = map.get(&p.name).ok_or_else(unknown)?;
        flatten(value, &mut out).ok_or_else(unknown)?;
    }
    Ok(out)
}

/// The storage length of the circuit's `static_data` bounded vector.
fn static_data_capacity(abi: &Abi) -> Result<usize> {
    let storage = abi.parameters.iter().find(|p| p.name == "static_data").and_then(|p| match &p.typ {
        AbiType::Struct { fields, .. } => fields.iter().find(|(name, _)| name == "storage").map(|(_, typ)| typ),
        _ => None,
    });
    match storage {
        Some(AbiType::Array { length, .. }) => usize::try_from(*length).ok(),
        _ => None,
    }
    .ok_or_else(|| Error::UnknownCircuit(abi.parameter_names().into_iter().cloned().collect()))
}

pub(crate) fn scope_offset(abi: &Abi) -> Result<usize> {
    let unknown = || Error::UnknownCircuit(abi.parameter_names().into_iter().cloned().collect());
    let mut offset: usize = 0;
    for p in abi.parameters.iter().filter(|p| p.is_public()) {
        if p.name == "scope" {
            return Ok(offset);
        }
        offset = offset.saturating_add(usize::try_from(p.typ.field_count()).map_err(|_| unknown())?);
    }
    Err(unknown())
}

fn flatten(value: &InputValue, out: &mut Vec<FieldElement>) -> Option<()> {
    match value {
        InputValue::Field(f) => out.push(noir_to_native(*f)),
        InputValue::Vec(values) => {
            for v in values {
                flatten(v, out)?;
            }
        }
        InputValue::String(_) | InputValue::Struct(_) => return None,
    }
    Some(())
}

/// 120-bit little-endian limbs.
fn limbs(n: &BigUint, bits: usize) -> Result<Vec<u128>> {
    let too_wide = |_| Error::Card("modulus is wider than the circuit's");
    let base = BigUint::from(LIMB_BASE);
    let mut rest = n.clone();
    let mut out = Vec::new();
    for _ in 1..bits.div_ceil(LIMB_BITS) {
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
    InputValue::Struct(BTreeMap::from([
        ("low".to_owned(), field(m.low.into())),
        ("high".to_owned(), field(m.high.into())),
        ("country".to_owned(), field(m.country.into())),
        ("card_type".to_owned(), field(m.card_type.into())),
        ("brand".to_owned(), field(m.brand.into())),
        ("commercial".to_owned(), field(m.commercial.into())),
        ("slot".to_owned(), field(m.slot.into())),
        ("siblings".to_owned(), InputValue::Vec(m.siblings.iter().copied().map(native).collect())),
    ]))
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
