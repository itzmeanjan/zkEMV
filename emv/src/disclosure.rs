use std::ops::BitOr;

use ark_bn254::Fr;

use crate::{CardType, nullifier::to_be_bytes};

/// BIN table attributes a challenge asks the proof to reveal; combine them with `|`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Disclosure(u8);

impl Disclosure {
    /// No attribute: the proof needs no BIN table.
    pub const NONE: Self = Self(0);
    /// Issuer country.
    pub const COUNTRY: Self = Self(1 << 0);
    /// Credit, debit or prepaid.
    pub const CARD_TYPE: Self = Self(1 << 1);
    /// Card brand.
    pub const BRAND: Self = Self(1 << 2);
    /// Issued to a business.
    pub const COMMERCIAL: Self = Self(1 << 3);
    /// Every attribute.
    pub const ALL: Self = Self::COUNTRY.union(Self::CARD_TYPE).union(Self::BRAND).union(Self::COMMERCIAL);

    /// The attributes of both; `|` in non-const code.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether it asks for every attribute of `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether it asks for no attribute.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The circuit's `disclose`.
    pub(crate) const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) const fn from_bits(bits: u8) -> Option<Self> {
        if Self::ALL.contains(Self(bits)) { Some(Self(bits)) } else { None }
    }
}

/// The circuit's `DISCLOSE_BIT_LEN`: one bit per attribute.
pub(crate) const DISCLOSE_BIT_LEN: usize = 4;
const _: () = assert!(Disclosure::ALL.bits() == (1 << DISCLOSE_BIT_LEN) - 1);
const U64_BYTE_LEN: usize = size_of::<u64>();

impl BitOr for Disclosure {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

/// BIN table attributes a proof revealed: `None` for those its challenge didn't ask for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Disclosed {
    /// Issuer country, ISO 3166-1 numeric.
    pub country: Option<u16>,
    /// Credit, debit or prepaid.
    pub card_type: Option<CardType>,
    /// Brand code; [`BinTable::brand`](crate::BinTable::brand) names it.
    pub brand: Option<u8>,
    /// Issued to a business.
    pub commercial: Option<bool>,
}

impl Disclosed {
    /// The circuit's outputs, in order.
    pub(crate) fn from_outputs(asked: Disclosure, [country, card_type, brand, commercial]: [Fr; DISCLOSE_BIT_LEN]) -> Option<Self> {
        Some(Self {
            country: output(asked.contains(Disclosure::COUNTRY), country, |v| u16::try_from(v).ok()).ok()?,
            card_type: output(asked.contains(Disclosure::CARD_TYPE), card_type, CardType::from_code).ok()?,
            brand: output(asked.contains(Disclosure::BRAND), brand, |v| u8::try_from(v).ok()).ok()?,
            commercial: output(asked.contains(Disclosure::COMMERCIAL), commercial, |v| match v {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            })
            .ok()?,
        })
    }
}

/// `Err` if invalid. An attribute not asked for must be 0.
fn output<T>(asked: bool, f: Fr, decode: impl FnOnce(u64) -> Option<T>) -> Result<Option<T>, ()> {
    let bytes = to_be_bytes(f);
    let (high, low) = bytes.split_last_chunk::<U64_BYTE_LEN>().ok_or(())?;
    if high.iter().any(|&b| b != 0) {
        return Err(());
    }
    match (asked, u64::from_be_bytes(*low)) {
        (true, v) => decode(v).map(Some).ok_or(()),
        (false, 0) => Ok(None),
        (false, _) => Err(()),
    }
}
