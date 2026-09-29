use serde_json::Value;
use sha1::{Digest, Sha1};

use crate::{Challenge, Error, Result, Scheme, challenge::Fields};

const EXPONENT: &[u8] = &[0x03];

/// Certification authority public keys the verifier trusts. Which keys, real or test, is
/// the caller's choice: trusting a key whose private key is known, such as the synthetic
/// test CA's, accepts forged proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaTable {
    keys: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    rid: [u8; 5],
    index: u8,
    exponent: Vec<u8>,
    modulus: Vec<u8>,
    /// Year and month; valid until the end of that month.
    expires: Option<(u16, u8)>,
}

impl CaTable {
    /// Parses a table in the format of `data/certificate-authority-public-keys.json` and
    /// checks each key's checksum. Every key in it becomes trusted.
    ///
    /// # Errors
    ///
    /// [`Error::CaTable`]: malformed, a checksum doesn't match, or two keys of the same
    /// length share a RID and index.
    pub fn from_json(json: &[u8]) -> Result<Self> {
        let doc: Value = serde_json::from_slice(json).map_err(|_| Error::CaTable("not JSON"))?;
        let keys = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(Error::CaTable("no keys array"))?
            .iter()
            .map(parse_entry)
            .collect::<Result<Vec<_>>>()?;
        for (i, a) in keys.iter().enumerate() {
            if keys
                .iter()
                .skip(i.saturating_add(1))
                .any(|b| (a.rid, a.index, a.modulus.len()) == (b.rid, b.index, b.modulus.len()))
            {
                return Err(Error::CaTable("two keys of the same length share a RID and index"));
            }
        }
        Ok(Self { keys })
    }

    /// The key a card names by RID (the first 5 bytes of its AID) and CA Public Key Index
    /// `8F`, checked against `challenge`: the RID must be the challenge's scheme's, the key
    /// must be exactly the scheme's CA width with exponent 3, and it must not expire before
    /// the challenge's month.
    ///
    /// # Errors
    ///
    /// [`Error::CaKey`]: no such trusted key, or it fails a check.
    pub fn lookup<S>(&self, challenge: &Challenge<S>, rid: [u8; 5], index: u8) -> Result<CaKey> {
        let scheme = challenge.scheme();
        if rid != scheme.rid() {
            return Err(Error::CaKey("the RID is not the challenge's scheme's"));
        }
        let entry = self
            .keys
            .iter()
            .find(|e| e.rid == rid && e.index == index && e.exponent == EXPONENT && has_bits(&e.modulus, scheme.ca_bits()))
            .ok_or(Error::CaKey("no trusted key of the scheme's width and exponent 3 for this RID and index"))?;
        let key = CaKey {
            scheme,
            modulus: entry.modulus.clone(),
            expires: entry.expires,
        };
        key.check(challenge.fields())?;
        Ok(key)
    }
}

/// A trusted CA public key, from [`CaTable::lookup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaKey {
    scheme: Scheme,
    modulus: Vec<u8>,
    expires: Option<(u16, u8)>,
}

impl CaKey {
    /// The scheme whose challenge it was looked up for.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// RSA modulus, big-endian.
    #[must_use]
    pub fn modulus(&self) -> &[u8] {
        &self.modulus
    }

    /// Repeated by `prove` and `verify`, which may get a key looked up for another challenge.
    pub(crate) fn check(&self, challenge: &Fields) -> Result<()> {
        if self.scheme != challenge.scheme {
            return Err(Error::CaKey("the key is for another scheme"));
        }
        if self.expires.is_some_and(|expires| expires < (challenge.today.year(), challenge.today.month())) {
            return Err(Error::CaKey("the key expired before the challenge's month"));
        }
        Ok(())
    }
}

/// Exactly `bits` long, as the circuit requires; `bits` is a multiple of 8.
fn has_bits(modulus: &[u8], bits: usize) -> bool {
    modulus.len() == bits / 8 && modulus.first().is_some_and(|&b| b >= 0x80)
}

fn parse_entry(key: &Value) -> Result<Entry> {
    let hex = |field: &'static str| -> Result<Vec<u8>> {
        let s = key.get(field).and_then(Value::as_str).ok_or(Error::CaTable("missing field"))?;
        const_hex::decode(s).map_err(|_| Error::CaTable("invalid hex"))
    };
    let rid: [u8; 5] = hex("rid")?.try_into().map_err(|_| Error::CaTable("RID is not 5 bytes"))?;
    let [index]: [u8; 1] = hex("index")?.try_into().map_err(|_| Error::CaTable("index is not 1 byte"))?;
    let exponent = hex("exponent")?;
    let modulus = hex("modulus")?;

    let digest = Sha1::new()
        .chain_update(rid)
        .chain_update([index])
        .chain_update(&modulus)
        .chain_update(&exponent)
        .finalize();
    if hex("checksum")? != digest.as_slice() {
        return Err(Error::CaTable("checksum mismatch"));
    }

    let expires = match key.get("expires") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_str().and_then(parse_year_month).ok_or(Error::CaTable("expires is not YYYY-MM-DD"))?),
    };
    Ok(Entry {
        rid,
        index,
        exponent,
        modulus,
        expires,
    })
}

fn parse_year_month(date: &str) -> Option<(u16, u8)> {
    let mut parts = date.split('-');
    let (year, month, day) = (parts.next()?, parts.next()?, parts.next()?);
    let valid = parts.next().is_none() && [year.len(), month.len(), day.len()] == [4, 2, 2] && day.bytes().all(|b| b.is_ascii_digit());
    let (year, month) = (year.parse().ok()?, month.parse().ok()?);
    (valid && (1..=12).contains(&month)).then_some((year, month))
}
