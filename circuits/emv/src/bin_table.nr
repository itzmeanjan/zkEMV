use crate::policy::nibbles;
use poseidon::poseidon2::Poseidon2;

/// The emv crate's `BinTable`: 2^24 leaves.
pub global DEPTH: u32 = 24;
/// 12 PAN digits, BCD.
global PREFIX_BYTES: u32 = 6;
global VERSION: Field = 1;
global TWO_POW_40: Field = 0x10000000000;

/// A table range, its slot and Merkle path. Zero when nothing is disclosed.
pub struct BinMembership {
    /// 40 bits.
    pub low: Field,
    /// 40 bits.
    pub high: Field,
    /// ISO 3166-1 numeric, 10 bits.
    pub country: Field,
    /// Credit 1, debit 2, prepaid 3.
    pub card_type: Field,
    /// Index in the table's brand list, plus 1; 8 bits.
    pub brand: Field,
    pub commercial: bool,
    /// 24 bits.
    pub slot: Field,
    pub siblings: [Field; DEPTH],
}

/// The attributes `disclose` selects; 0 or false for the others.
pub struct BinAttributes {
    pub country: Field,
    pub card_type: Field,
    pub brand: Field,
    pub commercial: bool,
}

/// `disclose` bits: 0 country, 1 card type, 2 brand, 3 commercial. With none set, the table is not checked.
pub fn bin_attributes(pan: [u8; 10], root: Field, disclose: u8, m: BinMembership) -> BinAttributes {
    let select: [bool; 4] = (disclose as Field).to_le_bits();

    // Widths make the packing injective, so a leaf in the tree fixes every field.
    m.low.assert_max_bit_size::<40>();
    m.high.assert_max_bit_size::<40>();
    m.country.assert_max_bit_size::<10>();
    m.card_type.assert_max_bit_size::<2>();
    m.brand.assert_max_bit_size::<8>();

    let computed = root_of(leaf(m), m.slot, m.siblings);
    let x = pan_prefix(pan, disclose != 0);
    if disclose != 0 {
        assert_eq(computed, root, "range is not in the BIN table");
        (x - m.low).assert_max_bit_size::<40>();
        (m.high - x).assert_max_bit_size::<40>();
    }

    BinAttributes {
        country: if select[0] { m.country } else { 0 },
        card_type: if select[1] { m.card_type } else { 0 },
        brand: if select[2] { m.brand } else { 0 },
        commercial: select[3] & m.commercial,
    }
}

/// From bit 0: low (40), high (40), country (10), card type (2), brand (8), commercial (1), version.
pub fn leaf(m: BinMembership) -> Field {
    let mut acc = VERSION * 2 + m.commercial as Field;

    acc = acc * 256 + m.brand;
    acc = acc * 4 + m.card_type;
    acc = acc * 1024 + m.country;
    acc = acc * TWO_POW_40 + m.high;

    acc * TWO_POW_40 + m.low
}

pub fn root_of(leaf: Field, slot: Field, siblings: [Field; DEPTH]) -> Field {
    let bits: [bool; DEPTH] = slot.to_le_bits();
    let mut node = leaf;
    for i in 0..DEPTH {
        let (left, right) = if bits[i] {
            (siblings[i], node)
        } else {
            (node, siblings[i])
        };
        node = Poseidon2::hash([left, right], 2);
    }
    node
}

/// The PAN's first 12 digits as an integer. `checked`: each nibble must be a digit.
fn pan_prefix(pan: [u8; 10], checked: bool) -> Field {
    let mut x = 0;
    for i in 0..PREFIX_BYTES {
        let (hi, lo) = nibbles(pan[i]);
        if checked {
            assert((hi <= 9) & (lo <= 9), "PAN has fewer than 12 digits");
        }
        x = x * 100 + hi as Field * 10 + lo as Field;
    }
    x
}
