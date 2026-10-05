mod json;
mod tree;

use std::collections::{BTreeMap, BTreeSet};

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use serde_json::{Map, Value};

use crate::{
    Error, Result,
    layout::{BINARY_BASE, DECIMAL_BASE, FIELD_BYTE_LEN},
    nullifier::to_be_bytes,
};
use tree::{TREE_DEPTH, Tree, root_of};

/// PAN digits a range bound has.
pub const PAN_PREFIX_DIGIT_COUNT: usize = 12;
const MAX_PAN_PREFIX: u64 = pow10(PAN_PREFIX_DIGIT_COUNT) - 1;
/// ISO 3166-1 numeric.
const COUNTRY_CODE_DIGIT_COUNT: usize = 3;
const MAX_COUNTRY_CODE: u64 = pow10(COUNTRY_CODE_DIGIT_COUNT) - 1;
const CARD_TYPE_COUNT: u64 = 3;
const SLOT_COUNT: usize = 1 << TREE_DEPTH;

/// Leaf field widths, as in `circuits/emv/src/bin_table.nr`.
const PAN_PREFIX_BIT_LEN: u32 = u64::BITS - MAX_PAN_PREFIX.leading_zeros();
const COUNTRY_CODE_BIT_LEN: u32 = u64::BITS - MAX_COUNTRY_CODE.leading_zeros();
const CARD_TYPE_BIT_LEN: u32 = u64::BITS - CARD_TYPE_COUNT.leading_zeros();
const BRAND_CODE_BIT_LEN: u32 = u8::BITS;
const COMMERCIAL_FLAG_BIT_LEN: u32 = 1;
const LEAF_VERSION: u64 = 1;
/// Brand codes are the index plus 1, so 0 is unused.
const MAX_BRAND_COUNT: usize = (1 << BRAND_CODE_BIT_LEN) - 1;

const fn pow10(n: usize) -> u64 {
    let mut x: u64 = 1;
    let mut i = 0;
    while i < n {
        x = x.saturating_mul(DECIMAL_BASE);
        i = i.saturating_add(1);
    }
    x
}

/// How the card is funded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CardType {
    /// Credit or charge card.
    Credit,
    /// Debit card.
    Debit,
    /// Prepaid, gift or voucher card.
    Prepaid,
}

impl CardType {
    fn code(self) -> u64 {
        match self {
            Self::Credit => 1,
            Self::Debit => 2,
            Self::Prepaid => 3,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Credit => "credit",
            Self::Debit => "debit",
            Self::Prepaid => "prepaid",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Self::Credit, Self::Debit, Self::Prepaid].into_iter().find(|t| t.name() == name)
    }

    pub(crate) fn from_code(code: u64) -> Option<Self> {
        [Self::Credit, Self::Debit, Self::Prepaid].into_iter().find(|t| t.code() == code)
    }
}

/// Attributes of a range's cards.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attributes {
    /// Issuer country, ISO 3166-1 numeric.
    pub country: u16,
    /// How the card is funded.
    pub card_type: CardType,
    /// Card brand, e.g. `VISA`.
    pub brand: String,
    /// Issued to a business.
    pub commercial: bool,
}

/// PANs whose first [`PAN_PREFIX_DIGIT_COUNT`] digits are in `low..=high`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Range {
    /// Lowest prefix.
    pub low: u64,
    /// Highest prefix.
    pub high: u64,
    /// Attributes of every card in the range.
    pub attributes: Attributes,
}

/// Merkle root of a [`BinTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BinRoot([u8; FIELD_BYTE_LEN]);

impl BinRoot {
    /// Big-endian.
    #[must_use]
    pub fn to_bytes(self) -> [u8; FIELD_BYTE_LEN] {
        self.0
    }

    /// `None` unless a field element below the BN254 scalar modulus.
    #[must_use]
    pub fn from_bytes(bytes: [u8; FIELD_BYTE_LEN]) -> Option<Self> {
        let root = Self::from_field(Fr::from_be_bytes_mod_order(&bytes));
        (root.0 == bytes).then_some(root)
    }

    pub(crate) fn to_field(self) -> Fr {
        Fr::from_be_bytes_mod_order(&self.0)
    }

    fn from_field(f: Fr) -> Self {
        Self(to_be_bytes(f))
    }
}

/// A range's leaf fields and Merkle path: the circuit's `BinMembership`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Membership {
    pub(crate) low: u64,
    pub(crate) high: u64,
    pub(crate) country: u16,
    pub(crate) card_type: u64,
    pub(crate) brand: u64,
    pub(crate) commercial: bool,
    pub(crate) slot: u64,
    pub(crate) siblings: Vec<Fr>,
}

impl Membership {
    /// For a proof that discloses nothing.
    pub(crate) fn empty() -> Self {
        Self {
            low: 0,
            high: 0,
            country: 0,
            card_type: 0,
            brand: 0,
            commercial: false,
            slot: 0,
            siblings: vec![Fr::zero(); TREE_DEPTH],
        }
    }
}

/// One slot's change, with its Merkle path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    slot: usize,
    old_leaf: Fr,
    new_leaf: Fr,
    siblings: Vec<Fr>,
}

impl Change {
    /// The slot that changed.
    #[must_use]
    pub fn slot(&self) -> usize {
        self.slot
    }

    /// Whether this change alone turns root `old` into `new`.
    #[must_use]
    pub fn verify(&self, old: BinRoot, new: BinRoot) -> bool {
        self.siblings.len() == TREE_DEPTH
            && BinRoot::from_field(root_of(self.slot, self.old_leaf, &self.siblings)) == old
            && BinRoot::from_field(root_of(self.slot, self.new_leaf, &self.siblings)) == new
    }
}

/// Disjoint PAN prefix ranges with card attributes, one per leaf of a binary Merkle tree.
///
/// Leaf, from bit 0: `low`, `high`, country, type (credit 1, debit 2, prepaid 3), brand index + 1,
/// commercial, version 1, each at the circuits' width. Empty leaf: 0. Node: noir-lang/poseidon
/// v0.3.0 Poseidon2 of both children.
#[derive(Clone, Debug)]
pub struct BinTable {
    other_keys: Map<String, Value>,
    brands: Vec<String>,
    slots: Vec<Option<Range>>,
    by_low: BTreeMap<u64, usize>,
    free: BTreeSet<usize>,
    tree: Tree,
}

impl BinTable {
    /// The Merkle root.
    #[must_use]
    pub fn root(&self) -> BinRoot {
        BinRoot::from_field(self.tree.root())
    }

    /// The range in `slot`, if any.
    #[must_use]
    pub fn get(&self, slot: usize) -> Option<&Range> {
        self.slots.get(slot).and_then(Option::as_ref)
    }

    /// The slot and range holding `prefix`, the PAN's first [`PAN_PREFIX_DIGIT_COUNT`] digits.
    #[must_use]
    pub fn find(&self, prefix: u64) -> Option<(usize, &Range)> {
        let (_, &slot) = self.by_low.range(..=prefix).next_back()?;
        let range = self.get(slot)?;
        (prefix <= range.high).then_some((slot, range))
    }

    /// The brand whose code a proof disclosed.
    #[must_use]
    pub fn brand(&self, code: u8) -> Option<&str> {
        self.brands.get(usize::from(code).checked_sub(1)?).map(String::as_str)
    }

    pub(crate) fn membership(&self, prefix: u64) -> Option<Membership> {
        let (slot, range) = self.find(prefix)?;
        let a = &range.attributes;
        let brand = self.brands.iter().position(|b| *b == a.brand).and_then(|i| u64::try_from(i).ok())?;
        Some(Membership {
            low: range.low,
            high: range.high,
            country: a.country,
            card_type: a.card_type.code(),
            brand: brand.checked_add(1)?,
            commercial: a.commercial,
            slot: u64::try_from(slot).ok()?,
            siblings: self.tree.path(slot),
        })
    }

    /// Puts `range` in the lowest empty slot.
    ///
    /// # Errors
    ///
    /// [`Error::BinTable`]: invalid or overlapping range, a 256th brand, or a full table.
    pub fn insert(&mut self, range: Range) -> Result<Change> {
        self.check(&range, None)?;
        let slot = self.free.first().copied().unwrap_or(self.slots.len());
        if slot >= SLOT_COUNT {
            return Err(Error::BinTable("table is full"));
        }
        self.set(slot, Some(range))
    }

    /// Replaces the range in `slot`.
    ///
    /// # Errors
    ///
    /// [`Error::BinTable`]: empty slot, invalid or overlapping range, or a 256th brand.
    pub fn update(&mut self, slot: usize, range: Range) -> Result<Change> {
        if self.get(slot).is_none() {
            return Err(Error::BinTable("slot is empty"));
        }
        self.check(&range, Some(slot))?;
        self.set(slot, Some(range))
    }

    /// Empties `slot`. Brand codes don't change.
    ///
    /// # Errors
    ///
    /// [`Error::BinTable`]: empty slot.
    pub fn remove(&mut self, slot: usize) -> Result<Change> {
        if self.get(slot).is_none() {
            return Err(Error::BinTable("slot is empty"));
        }
        self.set(slot, None)
    }

    /// Ranges are disjoint, so only the last one starting at or before `range.high` can overlap.
    fn check(&self, range: &Range, replacing: Option<usize>) -> Result<()> {
        validate(range)?;
        let overlaps = self
            .by_low
            .range(..=range.high)
            .rev()
            .find(|&(_, &slot)| Some(slot) != replacing)
            .and_then(|(_, &slot)| self.get(slot))
            .is_some_and(|other| other.high >= range.low);
        if overlaps {
            return Err(Error::BinTable("range overlaps another"));
        }
        Ok(())
    }

    /// `range` is checked.
    fn set(&mut self, slot: usize, range: Option<Range>) -> Result<Change> {
        let new_leaf = match &range {
            Some(r) => {
                let brand = self.brand_code(&r.attributes.brand)?;
                leaf(r, brand)
            }
            None => Fr::zero(),
        };
        let change = Change {
            slot,
            old_leaf: self.tree.leaf(slot),
            new_leaf,
            siblings: self.tree.path(slot),
        };
        if let Some(old) = self.get(slot) {
            let low = old.low;
            self.by_low.remove(&low);
        }
        if self.slots.len() <= slot {
            self.slots.resize(slot.saturating_add(1), None);
        }
        match &range {
            Some(r) => {
                self.by_low.insert(r.low, slot);
                self.free.remove(&slot);
            }
            None => {
                self.free.insert(slot);
            }
        }
        if let Some(s) = self.slots.get_mut(slot) {
            *s = range;
        }
        self.tree.set(slot, new_leaf);
        Ok(change)
    }

    /// Appends a new brand.
    fn brand_code(&mut self, brand: &str) -> Result<u64> {
        let index = match self.brands.iter().position(|b| b == brand) {
            Some(i) => i,
            None if self.brands.len() < MAX_BRAND_COUNT => {
                self.brands.push(brand.to_owned());
                self.brands.len().saturating_sub(1)
            }
            None => return Err(Error::BinTable("more than 255 brands")),
        };
        u64::try_from(index).map(|i| i.saturating_add(1)).map_err(|_| Error::BinTable("brand index"))
    }
}

fn validate(range: &Range) -> Result<()> {
    let a = &range.attributes;
    if range.low > range.high || range.high > MAX_PAN_PREFIX {
        return Err(Error::BinTable("range bounds must be 12-digit prefixes, low at most high"));
    }
    if a.country == 0 || u64::from(a.country) > MAX_COUNTRY_CODE {
        return Err(Error::BinTable("country must be an ISO 3166-1 numeric code"));
    }
    if a.brand.is_empty() {
        return Err(Error::BinTable("brand is empty"));
    }
    Ok(())
}

/// Layout in [`BinTable`]'s docs. Each input must fit its width.
fn leaf(range: &Range, brand: u64) -> Fr {
    let a = &range.attributes;
    [
        (u64::from(a.commercial), COMMERCIAL_FLAG_BIT_LEN),
        (brand, BRAND_CODE_BIT_LEN),
        (a.card_type.code(), CARD_TYPE_BIT_LEN),
        (u64::from(a.country), COUNTRY_CODE_BIT_LEN),
        (range.high, PAN_PREFIX_BIT_LEN),
        (range.low, PAN_PREFIX_BIT_LEN),
    ]
    .into_iter()
    .fold(Fr::from(LEAF_VERSION), |acc, (value, bits)| {
        acc * Fr::from(BINARY_BASE).pow([u64::from(bits)]) + Fr::from(value)
    })
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::Zero;

    use super::{Attributes, BinRoot, CardType, Range, Tree, leaf};

    fn range() -> Range {
        Range {
            low: 1,
            high: 999_999_999_999,
            attributes: Attributes {
                country: 999,
                card_type: CardType::Prepaid,
                brand: "X".to_owned(),
                commercial: true,
            },
        }
    }

    /// The layout's bits: 2^101 + 2^100 + 7·2^92 + 3·2^90 + 999·2^80 + (10^12 - 1)·2^40 + 1.
    #[test]
    fn leaf_layout() {
        let expected: u128 = 0x30_7FE7_E8D4_A50F_FF00_0000_0001;
        assert_eq!(leaf(&range(), 7), Fr::from(expected));
    }

    /// `circuits/emv/src/tests/bin_table.nr` and `scripts/bin_tree.py` give the same root.
    #[test]
    fn root_known_answer() {
        let mut leaves = vec![Fr::zero(); 5];
        leaves.push(leaf(&range(), 7));
        assert_eq!(
            const_hex::encode(BinRoot::from_field(Tree::new(leaves).root()).to_bytes()),
            "297d4dd4a82f4c56e9367532bd636f3a617638f25392938f317fbc4af114147a"
        );
    }
}
