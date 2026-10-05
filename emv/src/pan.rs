use num_bigint::BigUint;

use crate::{
    Card, Error, PAN_PREFIX_DIGIT_COUNT, Result,
    layout::{DECIMAL_BASE, MAX_DECIMAL_DIGIT, NIBBLE_BIT_LEN, NIBBLE_MASK, NIBBLES_PER_BYTE, RSA_EXPONENT},
};

/// `circuits/emv/src/card_chain.nr`'s layout of recovered certificates, Book 2 tables 6 and 14.
const RECOVERED_DATA_HEADER: u8 = 0x6A;
const FMT_ISSUER_CERT: u8 = 0x02;
const FMT_ICC_CERT: u8 = 0x04;
const HEADER_BYTE_LEN: usize = 1;
const FORMAT_BYTE_LEN: usize = 1;
const ALGORITHM_ID_BYTE_LEN: usize = 1;
const LENGTH_FIELD_BYTE_LEN: usize = 1;
const ISSUER_ID_BYTE_LEN: usize = 4;
const EXPIRY_BYTE_LEN: usize = 2;
const SERIAL_BYTE_LEN: usize = 3;
const HASH_BYTE_LEN: usize = 20;
const TRAILER_BYTE_LEN: usize = 1;
const HASH_AND_TRAILER_BYTE_LEN: usize = HASH_BYTE_LEN + TRAILER_BYTE_LEN;

const HEADER_OFFSET: usize = 0;
const FORMAT_OFFSET: usize = HEADER_OFFSET + HEADER_BYTE_LEN;
const FIELDS_OFFSET: usize = FORMAT_OFFSET + FORMAT_BYTE_LEN;
const ISSUER_ID_OFFSET: usize = FIELDS_OFFSET;
const ISSUER_EXPIRY_OFFSET: usize = ISSUER_ID_OFFSET + ISSUER_ID_BYTE_LEN;
const ISSUER_SERIAL_OFFSET: usize = ISSUER_EXPIRY_OFFSET + EXPIRY_BYTE_LEN;
const ISSUER_HASH_ALG_OFFSET: usize = ISSUER_SERIAL_OFFSET + SERIAL_BYTE_LEN;
const ISSUER_PK_ALG_OFFSET: usize = ISSUER_HASH_ALG_OFFSET + ALGORITHM_ID_BYTE_LEN;
const ISSUER_KEY_BYTE_LEN_OFFSET: usize = ISSUER_PK_ALG_OFFSET + ALGORITHM_ID_BYTE_LEN;
const ISSUER_EXPONENT_BYTE_LEN_OFFSET: usize = ISSUER_KEY_BYTE_LEN_OFFSET + LENGTH_FIELD_BYTE_LEN;
const ISSUER_KEY_OFFSET: usize = ISSUER_EXPONENT_BYTE_LEN_OFFSET + LENGTH_FIELD_BYTE_LEN;
const ICC_PAN_OFFSET: usize = FIELDS_OFFSET;
const PAN_PREFIX_BYTE_LEN: usize = PAN_PREFIX_DIGIT_COUNT / NIBBLES_PER_BYTE;

/// The first `PAN_PREFIX_DIGIT_COUNT` PAN digits of the ICC certificate, recovered as the circuit does. Unchecked:
/// a wrong value only makes the proof fail.
pub(crate) fn prefix(card: &Card, ca_modulus: &[u8]) -> Result<u64> {
    let (issuer_cert, remainder, icc_cert) = match card {
        Card::VisaFdda(c) => (&c.issuer_pubkey_cert, &[][..], &c.icc_pubkey_cert),
        Card::MastercardDda(c) => (&c.issuer_pubkey_cert, &c.issuer_pubkey_remainder[..], &c.icc_pubkey_cert),
    };
    let issuer = recover(issuer_cert, ca_modulus, FMT_ISSUER_CERT).ok_or(Error::Card("issuer certificate doesn't recover under the CA key"))?;
    let key_len = issuer.get(ISSUER_KEY_BYTE_LEN_OFFSET).copied().map(usize::from);
    let leftmost = issuer.get(ISSUER_KEY_OFFSET..issuer.len().saturating_sub(HASH_AND_TRAILER_BYTE_LEN));
    let issuer_key: Vec<u8> = leftmost
        .unwrap_or_default()
        .iter()
        .chain(remainder)
        .take(key_len.unwrap_or_default())
        .copied()
        .collect();
    if key_len != Some(issuer_key.len()) {
        return Err(Error::Card("issuer key is longer than its certificate and remainder"));
    }

    let icc = recover(icc_cert, &issuer_key, FMT_ICC_CERT).ok_or(Error::Card("ICC certificate doesn't recover under the issuer key"))?;
    let mut prefix: u64 = 0;
    let pan_prefix = icc.get(ICC_PAN_OFFSET..ICC_PAN_OFFSET.saturating_add(PAN_PREFIX_BYTE_LEN));
    for &b in pan_prefix.unwrap_or_default() {
        for digit in [b >> NIBBLE_BIT_LEN, b & NIBBLE_MASK] {
            if u64::from(digit) > MAX_DECIMAL_DIGIT {
                return Err(Error::Card("PAN has fewer than 12 digits"));
            }
            prefix = prefix.saturating_mul(DECIMAL_BASE).saturating_add(digit.into());
        }
    }
    Ok(prefix)
}

/// `sig^3 mod n` as `n`'s length in bytes, if it has the header and `format`.
fn recover(sig: &[u8], modulus: &[u8], format: u8) -> Option<Vec<u8>> {
    let n = BigUint::from_bytes_be(modulus);
    if n.bits() == 0 {
        return None;
    }
    let m = BigUint::from_bytes_be(sig).modpow(&BigUint::from(RSA_EXPONENT), &n).to_bytes_be();
    let mut out = vec![0; modulus.len().checked_sub(m.len())?];
    out.extend(m);
    (out.get(HEADER_OFFSET..FIELDS_OFFSET) == Some(&[RECOVERED_DATA_HEADER, format][..])).then_some(out)
}
