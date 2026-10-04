use num_bigint::BigUint;

use crate::{Card, Error, Result};

const HEADER: u8 = 0x6A;
const FMT_ISSUER_CERT: u8 = 0x02;
const FMT_ICC_CERT: u8 = 0x04;
/// Book 2 table 6.
const ISSUER_KEY_LEN_AT: usize = 13;
const ISSUER_KEY_AT: usize = 15;
/// Hash and trailer.
const TAIL: usize = 21;
/// Book 2 table 14: the PAN's first 12 digits, BCD.
const PAN_PREFIX: std::ops::Range<usize> = 2..8;

/// The first 12 PAN digits of the ICC certificate, recovered as the circuit does. Unchecked:
/// a wrong value only makes the proof fail.
pub(crate) fn prefix(card: &Card, ca_modulus: &[u8]) -> Result<u64> {
    let (issuer_cert, remainder, icc_cert) = match card {
        Card::VisaFdda(c) => (&c.issuer_pubkey_cert, &[][..], &c.icc_pubkey_cert),
        Card::MastercardDda(c) => (&c.issuer_pubkey_cert, &c.issuer_pubkey_remainder[..], &c.icc_pubkey_cert),
    };
    let issuer = recover(issuer_cert, ca_modulus, FMT_ISSUER_CERT).ok_or(Error::Card("issuer certificate doesn't recover under the CA key"))?;
    let key_len = issuer.get(ISSUER_KEY_LEN_AT).copied().map(usize::from);
    let leftmost = issuer.get(ISSUER_KEY_AT..issuer.len().saturating_sub(TAIL));
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
    for &b in icc.get(PAN_PREFIX).unwrap_or_default() {
        for digit in [b >> 4, b & 0xF] {
            if digit > 9 {
                return Err(Error::Card("PAN has fewer than 12 digits"));
            }
            prefix = prefix.saturating_mul(10).saturating_add(digit.into());
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
    let m = BigUint::from_bytes_be(sig).modpow(&BigUint::from(3u8), &n).to_bytes_be();
    let mut out = vec![0; modulus.len().checked_sub(m.len())?];
    out.extend(m);
    (out.get(..2) == Some(&[HEADER, format][..])).then_some(out)
}
