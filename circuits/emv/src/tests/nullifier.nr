use crate::nullifier::{DOMAIN_SEPARATOR, nullifier};
use poseidon::poseidon2::Poseidon2;

fn counting<let K: u32>() -> [u8; K] {
    let mut m = [0; K];
    for i in 0..K {
        m[i] = (i + 1) as u8;
    }
    m
}

#[test]
fn lanes_are_31_byte_big_endian_chunks() {
    let lane1 = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    let lane2 = 0x2021;
    assert_eq(nullifier(counting::<33>(), 7), Poseidon2::hash([DOMAIN_SEPARATOR, 7, lane1, lane2, 0, 0, 0, 0], 8));
}

/// `emv/src/nullifier.rs`'s `nullifier_known_answer` checks the same value on the host.
#[test]
fn known_answer() {
    assert_eq(nullifier(counting::<128>(), 7), 0x10bea8dfa6f518e8c2f41fd4bec8efbbb0932081fb73a04a9a6b7d71aa0c48ba);
}

#[test]
fn every_byte_and_the_scope_matter() {
    let m = counting::<128>();
    let base = nullifier(m, 7);
    assert(nullifier(m, 8) != base);
    // First and last byte of lane 1, first byte of lane 2, last byte of lane 5.
    for i in [0, 30, 31, 127] {
        let mut changed = m;
        changed[i] ^= 1;
        assert(nullifier(changed, 7) != base);
    }
}
