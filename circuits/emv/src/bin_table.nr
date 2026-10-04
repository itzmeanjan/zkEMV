use crate::{bytes::{bit_length, BITS_PER_BYTE, DECIMAL_BASE, MAX_DECIMAL_DIGIT, nibbles, NIBBLES_PER_BYTE, pow10, pow2}, PAN_BYTE_LEN};
use poseidon::poseidon2::Poseidon2;

/// The emv crate's `BinTable`: 2^TREE_DEPTH leaves.
pub global TREE_DEPTH: u32 = 24;
global PAN_PREFIX_DIGIT_COUNT: u32 = 12;
global PAN_PREFIX_BYTE_LEN: u32 = PAN_PREFIX_DIGIT_COUNT / NIBBLES_PER_BYTE;
global COUNTRY_CODE_DIGIT_COUNT: u32 = 3;
global CARD_TYPE_COUNT: u64 = 3;

global PAN_PREFIX_BIT_LEN: u32 = bit_length(pow10(PAN_PREFIX_DIGIT_COUNT) - 1);
global COUNTRY_CODE_BIT_LEN: u32 = bit_length(pow10(COUNTRY_CODE_DIGIT_COUNT) - 1);
global CARD_TYPE_BIT_LEN: u32 = bit_length(CARD_TYPE_COUNT);
global BRAND_CODE_BIT_LEN: u32 = BITS_PER_BYTE;
global COMMERCIAL_FLAG_BIT_LEN: u32 = 1;
global LEAF_VERSION: Field = 1;

global DISCLOSE_COUNTRY_BIT_INDEX: u32 = 0;
global DISCLOSE_CARD_TYPE_BIT_INDEX: u32 = DISCLOSE_COUNTRY_BIT_INDEX + 1;
global DISCLOSE_BRAND_BIT_INDEX: u32 = DISCLOSE_CARD_TYPE_BIT_INDEX + 1;
global DISCLOSE_COMMERCIAL_BIT_INDEX: u32 = DISCLOSE_BRAND_BIT_INDEX + 1;
global DISCLOSE_BIT_LEN: u32 = DISCLOSE_COMMERCIAL_BIT_INDEX + 1;

/// A table range, its slot and Merkle path. Zero when nothing is disclosed.
pub struct BinMembership {
    pub low: Field,
    pub high: Field,
    /// ISO 3166-1 numeric.
    pub country: Field,
    /// Credit 1, debit 2, prepaid 3.
    pub card_type: Field,
    /// Index in the table's brand list, plus 1.
    pub brand: Field,
    pub commercial: bool,
    pub slot: Field,
    pub siblings: [Field; TREE_DEPTH],
}

/// The attributes `disclose` selects; 0 or false for the others.
pub struct BinAttributes {
    pub country: Field,
    pub card_type: Field,
    pub brand: Field,
    pub commercial: bool,
}

/// `disclose` has a bit per attribute, from `DISCLOSE_COUNTRY_BIT_INDEX`. With none set, the table is not checked.
pub fn bin_attributes(pan: [u8; PAN_BYTE_LEN], root: Field, disclose: u8, m: BinMembership) -> BinAttributes {
    let select: [bool; DISCLOSE_BIT_LEN] = (disclose as Field).to_le_bits();

    // Widths make the packing injective, so a leaf in the tree fixes every field.
    m.low.assert_max_bit_size::<PAN_PREFIX_BIT_LEN>();
    m.high.assert_max_bit_size::<PAN_PREFIX_BIT_LEN>();
    m.country.assert_max_bit_size::<COUNTRY_CODE_BIT_LEN>();
    m.card_type.assert_max_bit_size::<CARD_TYPE_BIT_LEN>();
    m.brand.assert_max_bit_size::<BRAND_CODE_BIT_LEN>();

    let computed = root_of(leaf(m), m.slot, m.siblings);
    let x = pan_prefix(pan, disclose != 0);
    if disclose != 0 {
        assert_eq(computed, root, "range is not in the BIN table");
        (x - m.low).assert_max_bit_size::<PAN_PREFIX_BIT_LEN>();
        (m.high - x).assert_max_bit_size::<PAN_PREFIX_BIT_LEN>();
    }

    BinAttributes {
        country: if select[DISCLOSE_COUNTRY_BIT_INDEX] {
            m.country
        } else {
            0
        },
        card_type: if select[DISCLOSE_CARD_TYPE_BIT_INDEX] {
            m.card_type
        } else {
            0
        },
        brand: if select[DISCLOSE_BRAND_BIT_INDEX] {
            m.brand
        } else {
            0
        },
        commercial: select[DISCLOSE_COMMERCIAL_BIT_INDEX] & m.commercial,
    }
}

/// From bit 0: low, high, country, card type, brand, commercial, version.
pub fn leaf(m: BinMembership) -> Field {
    let mut acc = LEAF_VERSION * pow2(COMMERCIAL_FLAG_BIT_LEN) + m.commercial as Field;

    acc = acc * pow2(BRAND_CODE_BIT_LEN) + m.brand;
    acc = acc * pow2(CARD_TYPE_BIT_LEN) + m.card_type;
    acc = acc * pow2(COUNTRY_CODE_BIT_LEN) + m.country;
    acc = acc * pow2(PAN_PREFIX_BIT_LEN) + m.high;

    acc * pow2(PAN_PREFIX_BIT_LEN) + m.low
}

pub fn root_of(leaf: Field, slot: Field, siblings: [Field; TREE_DEPTH]) -> Field {
    let bits: [bool; TREE_DEPTH] = slot.to_le_bits();
    let mut node = leaf;
    for i in 0..TREE_DEPTH {
        let (left, right) = if bits[i] {
            (siblings[i], node)
        } else {
            (node, siblings[i])
        };
        let pair = [left, right];
        node = Poseidon2::hash(pair, pair.len());
    }
    node
}

/// The PAN's first `PAN_PREFIX_DIGIT_COUNT` digits as an integer. `checked`: each nibble must be a digit.
fn pan_prefix(pan: [u8; PAN_BYTE_LEN], checked: bool) -> Field {
    let base = DECIMAL_BASE as Field;
    let mut x = 0;
    for i in 0..PAN_PREFIX_BYTE_LEN {
        let (hi, lo) = nibbles(pan[i]);
        if checked {
            assert((hi <= MAX_DECIMAL_DIGIT) & (lo <= MAX_DECIMAL_DIGIT), "PAN has fewer than 12 digits");
        }
        x = (x * base + hi as Field) * base + lo as Field;
    }
    x
}
