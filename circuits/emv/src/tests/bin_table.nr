use crate::bin_table::{bin_attributes, BinMembership, leaf, root_of, TREE_DEPTH};
use poseidon::poseidon2::Poseidon2;

fn empty_roots() -> [Field; TREE_DEPTH] {
    let mut roots = [0; TREE_DEPTH];
    for i in 1..TREE_DEPTH {
        roots[i] = Poseidon2::hash([roots[i - 1], roots[i - 1]], 2);
    }
    roots
}

/// 457100 split around 45710040, as in data/bin-table.json.
fn parent() -> BinMembership {
    BinMembership { low: 457100000000, high: 457100399999, country: 208, card_type: 2, brand: 2, commercial: false, slot: 0, siblings: empty_roots() }
}

fn child() -> BinMembership {
    BinMembership { low: 457100400000, high: 457100409999, country: 208, card_type: 3, brand: 1, commercial: true, slot: 1, siblings: empty_roots() }
}

/// Both ranges in slots 0 and 1.
fn with_paths() -> (BinMembership, BinMembership, Field) {
    let (mut p, mut c) = (parent(), child());
    p.siblings[0] = leaf(c);
    c.siblings[0] = leaf(p);
    (p, c, root_of(leaf(p), 0, p.siblings))
}

/// 4571004012345678
global PAN_IN_CHILD: [u8; 10] = [0x45, 0x71, 0x00, 0x40, 0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF];
global ALL: u8 = 0xF;

/// `emv/src/bin_table/mod.rs`'s `leaf_layout` and `scripts/bin_tree.py` give the same values.
#[test]
fn known_answer() {
    let m = BinMembership { low: 1, high: 999999999999, country: 999, card_type: 3, brand: 7, commercial: true, slot: 5, siblings: empty_roots() };
    assert_eq(leaf(m), 0x307fe7e8d4a50fff0000000001);
    assert_eq(root_of(leaf(m), m.slot, m.siblings), 0x297d4dd4a82f4c56e9367532bd636f3a617638f25392938f317fbc4af114147a);
}

#[test]
fn discloses_what_is_selected() {
    let (_, c, root) = with_paths();
    let all = bin_attributes(PAN_IN_CHILD, root, ALL, c);
    assert_eq((all.country, all.card_type, all.brand, all.commercial), (208, 3, 1, true));
    let some = bin_attributes(PAN_IN_CHILD, root, 2, c);
    assert_eq((some.country, some.card_type, some.brand, some.commercial), (0, 3, 0, false));
}

#[test]
fn range_bounds_are_inclusive() {
    let (p, c, root) = with_paths();
    let _ = bin_attributes(
        [0x45, 0x71, 0x00, 0x40, 0x00, 0x00, 0, 0, 0, 0],
        root,
        ALL,
        c,
    );
    let _ = bin_attributes(
        [0x45, 0x71, 0x00, 0x40, 0x99, 0x99, 0, 0, 0, 0],
        root,
        ALL,
        c,
    );
    let _ = bin_attributes(
        [0x45, 0x71, 0x00, 0x39, 0x99, 0x99, 0, 0, 0, 0],
        root,
        ALL,
        p,
    );
}

#[test]
fn nothing_disclosed_checks_nothing() {
    let zero = BinMembership { low: 0, high: 0, country: 0, card_type: 0, brand: 0, commercial: false, slot: 0, siblings: [0; TREE_DEPTH] };
    let a = bin_attributes([0xFF; 10], 12345, 0, zero);
    assert_eq((a.country, a.card_type, a.brand, a.commercial), (0, 0, 0, false));
}

#[test(should_fail_with = "range is not in the BIN table")]
fn wrong_root_fails() {
    let (_, c, root) = with_paths();
    let _ = bin_attributes(PAN_IN_CHILD, root + 1, ALL, c);
}

#[test(should_fail_with = "range is not in the BIN table")]
fn changed_attribute_fails() {
    let (_, mut c, root) = with_paths();
    c.card_type = 2;
    let _ = bin_attributes(PAN_IN_CHILD, root, ALL, c);
}

#[test(should_fail)]
fn field_borrowing_from_its_neighbour_fails() {
    // Same leaf: country + 2^10 and card type - 1. Only the width checks catch it.
    let (_, mut c, root) = with_paths();
    let packed = leaf(c);
    c.country += 1024;
    c.card_type -= 1;
    assert_eq(leaf(c), packed);
    let _ = bin_attributes(PAN_IN_CHILD, root, ALL, c);
}

#[test(should_fail)]
fn prefix_outside_the_range_fails() {
    let (p, _, root) = with_paths();
    let _ = bin_attributes(PAN_IN_CHILD, root, ALL, p);
}

#[test(should_fail_with = "PAN has fewer than 12 digits")]
fn short_pan_fails() {
    let (_, c, root) = with_paths();
    let _ = bin_attributes(
        [0x45, 0x71, 0x00, 0x40, 0x12, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF],
        root,
        ALL,
        c,
    );
}

#[test(should_fail)]
fn unknown_disclose_bit_fails() {
    let (_, c, root) = with_paths();
    let _ = bin_attributes(PAN_IN_CHILD, root, 0x10, c);
}

#[test(should_fail)]
fn country_wider_than_10_bits_fails() {
    let (_, mut c, root) = with_paths();
    c.country = 1024;
    let _ = bin_attributes(PAN_IN_CHILD, root, 0, c);
}
