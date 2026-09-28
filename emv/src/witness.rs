use std::collections::BTreeMap;

use noirc_abi::{Abi, InputMap, input_parser::InputValue};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{CheckedDiv, pow};
use provekit_common::{FieldElement, NoirElement, utils::noir_to_native};

use crate::{Card, Error, Result, Scheme, Statement};

const LIMB_BITS: usize = 120;
const LIMB_BASE: u128 = 1 << LIMB_BITS;
/// noir-bignum's `BARRETT_REDUCTION_OVERFLOW_BITS`.
const BARRETT_OVERFLOW_BITS: usize = 6;
/// `mastercard_dda`'s `MAX_STATIC_DATA_LEN`.
const MAX_STATIC_DATA_LEN: u16 = 256;
/// SHA-1 hash and the `BC` trailer that end every recovered EMV certificate.
const CERT_TAIL_LEN: usize = 21;

pub(crate) fn public_input_map(scheme: Scheme, statement: &Statement) -> Result<InputMap> {
    expect_len("ca_modulus", &statement.ca_modulus, scheme.ca_bits() / 8)?;
    let ca = BigUint::from_bytes_be(&statement.ca_modulus);

    let mut map = InputMap::from([
        ("ca_modulus".to_owned(), limbs_value(limbs(&ca, scheme.ca_bits())?)),
        ("nonce".to_owned(), bytes(&statement.nonce)),
        ("today".to_owned(), field(statement.today.into())),
    ]);
    match (scheme, statement.transaction) {
        (Scheme::VisaFastDda, Some(t)) => {
            map.insert("amount".to_owned(), bytes(&t.amount));
            map.insert("currency".to_owned(), bytes(&t.currency));
        }
        (Scheme::MastercardDda, None) => {}
        (Scheme::VisaFastDda, None) => {
            return Err(Error::Statement("Visa fDDA signs the amount and currency; transaction is required"));
        }
        (Scheme::MastercardDda, Some(_)) => {
            return Err(Error::Statement("Mastercard DDA signs no transaction; transaction must be None"));
        }
    }
    Ok(map)
}

pub(crate) fn input_map(scheme: Scheme, statement: &Statement, card: &Card) -> Result<InputMap> {
    let mut map = public_input_map(scheme, statement)?;
    let (issuer_cert, issuer_remainder, icc_cert) = match card {
        Card::VisaFastDda(c) => (&c.issuer_cert, &[][..], &c.icc_cert),
        Card::MastercardDda(c) => (&c.issuer_cert, &c.issuer_remainder[..], &c.icc_cert),
    };
    let (issuer, icc) = chain_moduli(scheme, &statement.ca_modulus, issuer_cert, issuer_remainder, icc_cert)?;

    let ca = BigUint::from_bytes_be(&statement.ca_modulus);
    map.extend([
        ("ca_redc".to_owned(), limbs_value(redc(&ca, scheme.ca_bits())?)),
        ("issuer_redc".to_owned(), limbs_value(redc(&issuer, scheme.issuer_bits())?)),
        ("icc_redc".to_owned(), limbs_value(redc(&icc, scheme.icc_bits())?)),
    ]);
    match card {
        Card::VisaFastDda(c) => map.extend([
            ("issuer_cert".to_owned(), bytes(&c.issuer_cert)),
            ("issuer_exponent".to_owned(), field(c.issuer_exponent.into())),
            ("icc_cert".to_owned(), bytes(&c.icc_cert)),
            ("icc_exponent".to_owned(), field(c.icc_exponent.into())),
            ("sdad".to_owned(), bytes(&c.sdad)),
            ("card_auth_data".to_owned(), bytes(&c.card_auth_data)),
        ]),
        Card::MastercardDda(c) => {
            let len = u16::try_from(c.static_data.len())
                .ok()
                .filter(|&len| len <= MAX_STATIC_DATA_LEN)
                .ok_or(Error::Card("static data exceeds the circuit's 256-byte bound"))?;
            let mut storage = c.static_data.clone();
            storage.resize(MAX_STATIC_DATA_LEN.into(), 0);
            let static_data = InputValue::Struct(BTreeMap::from([("storage".to_owned(), bytes(&storage)), ("len".to_owned(), field(len.into()))]));
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

/// The issuer and ICC moduli, which the prover needs for their Barrett hints. The circuit
/// re-derives and checks both; this only fails early on data that cannot be proved.
fn chain_moduli(scheme: Scheme, ca: &[u8], issuer_cert: &[u8], issuer_remainder: &[u8], icc_cert: &[u8]) -> Result<(BigUint, BigUint)> {
    expect_len("issuer_cert", issuer_cert, scheme.ca_bits() / 8)?;
    expect_len("icc_cert", icc_cert, scheme.issuer_bits() / 8)?;

    // EMV Book 2 tables 6 and 14: format byte, then the offset of the key length byte.
    let issuer = next_key(
        &recover(issuer_cert, ca)?,
        0x02,
        13,
        issuer_remainder,
        scheme.issuer_bits() / 8,
        "issuer certificate (90) does not recover to an issuer key of the circuit's width under this CA key",
    )?;
    let icc = next_key(
        &recover(icc_cert, &issuer)?,
        0x04,
        19,
        &[],
        scheme.icc_bits() / 8,
        "ICC certificate (9F46) does not recover to an ICC key of the circuit's width",
    )?;
    Ok((BigUint::from_bytes_be(&issuer), BigUint::from_bytes_be(&icc)))
}

fn recover(sig: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    let n = BigUint::from_bytes_be(modulus);
    let s = BigUint::from_bytes_be(sig);
    if s >= n {
        return Err(Error::Card("signature is not below its modulus"));
    }
    let m = s.modpow(&BigUint::from(3u8), &n).to_bytes_be();
    let pad = modulus
        .len()
        .checked_sub(m.len())
        .ok_or(Error::Card("recovered message is longer than its modulus"))?;
    let mut out = vec![0; pad];
    out.extend(m);
    Ok(out)
}

fn next_key(m: &[u8], format: u8, key_len_at: usize, remainder: &[u8], key_len: usize, err: &'static str) -> Result<Vec<u8>> {
    let key = || {
        let header_ok =
            m.first() == Some(&0x6A) && m.get(1) == Some(&format) && m.last() == Some(&0xBC) && m.get(key_len_at).map(|&l| usize::from(l)) == Some(key_len);
        if !header_ok {
            return None;
        }
        let body = m.get(key_len_at.checked_add(2)?..m.len().checked_sub(CERT_TAIL_LEN)?)?;
        [body, remainder].concat().get(..key_len).map(<[u8]>::to_vec)
    };
    key().ok_or(Error::Card(err))
}

/// 120-bit little-endian limbs; the top limb absorbs any excess, as a Barrett hint can.
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

/// A width that is a multiple of 120 bits is held modulo 2n in the circuit
/// (`emv::DoubledKey`), so its hint is for 2n at one bit wider:
/// floor(2^s / 2n) = floor(2^(s-1) / n).
fn redc(modulus: &BigUint, bits: usize) -> Result<Vec<u128>> {
    let doubled = bits.is_multiple_of(LIMB_BITS);
    let bits = bits.saturating_add(doubled.into());
    let shift = bits.saturating_mul(2).saturating_add(BARRETT_OVERFLOW_BITS).saturating_sub(doubled.into());
    let quotient = pow(BigUint::from(2u8), shift).checked_div(modulus).ok_or(Error::Card("modulus is zero"))?;
    limbs(&quotient, bits)
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

fn field(v: u128) -> InputValue {
    InputValue::Field(NoirElement::from(v))
}

fn bytes(b: &[u8]) -> InputValue {
    InputValue::Vec(b.iter().map(|&x| field(x.into())).collect())
}

fn limbs_value(limbs: Vec<u128>) -> InputValue {
    InputValue::Vec(limbs.into_iter().map(field).collect())
}
