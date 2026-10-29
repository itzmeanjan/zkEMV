//! Merkle paths in the BIN table's tree, which `emv::BinTable` keeps private: leaf layout
//! and node hash as in its docs and the circuits.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use serde_json::Value;
use taceo_poseidon2::bn254::t4::permutation_in_place;

pub(crate) const TREE_DEPTH: usize = 24;
const TREE_ARITY: usize = 2;
const CARD_TYPES: [&str; 3] = ["credit", "debit", "prepaid"];

const MAX_PAN_PREFIX: u64 = 999_999_999_999;
const MAX_COUNTRY_CODE: u64 = 999;
const PAN_PREFIX_BIT_LEN: u32 = u64::BITS - MAX_PAN_PREFIX.leading_zeros();
const COUNTRY_CODE_BIT_LEN: u32 = u64::BITS - MAX_COUNTRY_CODE.leading_zeros();
const CARD_TYPE_BIT_LEN: u32 = usize::BITS - CARD_TYPES.len().leading_zeros();
const BRAND_CODE_BIT_LEN: u32 = u8::BITS;
const COMMERCIAL_FLAG_BIT_LEN: u32 = 1;
const LEAF_VERSION: u128 = 1;

/// noir-lang/poseidon's sponge: t = 4, rate 3, the input length times 2^64 in the capacity lane.
const SPONGE_WIDTH: usize = 4;
const SPONGE_RATE: usize = SPONGE_WIDTH - 1;
const LENGTH_TAG_SCALE: u128 = 1 << u64::BITS;

/// Codes start at 1: card type by [`CARD_TYPES`], brand by the table's brand list.
pub(crate) fn card_type_code(range: &Value) -> u128 {
    code(CARD_TYPES.iter().position(|&t| range["type"] == t))
}

pub(crate) fn brand_code(table: &Value, range: &Value) -> u128 {
    code(table["brands"].as_array().unwrap().iter().position(|b| *b == range["brand"]))
}

/// The siblings of `slot`, leaf level first.
pub(crate) fn path(table: &Value, slot: usize) -> Vec<BigUint> {
    let ranges = table["ranges"].as_array().unwrap();
    let mut nodes = vec![Fr::from(0_u8); ranges.iter().map(|r| slot_of(r) + 1).max().unwrap_or_default()];
    for r in ranges {
        nodes[slot_of(r)] = leaf(table, r);
    }

    let mut empty = Fr::from(0_u8);
    let mut index = slot;
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    for _ in 0..TREE_DEPTH {
        siblings.push(to_biguint(nodes.get(index ^ 1).copied().unwrap_or(empty)));
        nodes = nodes
            .chunks(TREE_ARITY)
            .map(|pair| hash(&[pair[0], pair.get(1).copied().unwrap_or(empty)]))
            .collect();
        empty = hash(&[empty, empty]);
        index /= TREE_ARITY;
    }
    siblings
}

pub(crate) fn slot_of(range: &Value) -> usize {
    usize::try_from(range["slot"].as_u64().unwrap()).unwrap()
}

fn leaf(table: &Value, range: &Value) -> Fr {
    let uint = |key: &str| u128::from(range[key].as_u64().unwrap());
    [
        (u128::from(range["commercial"].as_bool().unwrap()), COMMERCIAL_FLAG_BIT_LEN),
        (brand_code(table, range), BRAND_CODE_BIT_LEN),
        (card_type_code(range), CARD_TYPE_BIT_LEN),
        (uint("country"), COUNTRY_CODE_BIT_LEN),
        (uint("high"), PAN_PREFIX_BIT_LEN),
        (uint("low"), PAN_PREFIX_BIT_LEN),
    ]
    .into_iter()
    .fold(LEAF_VERSION, |acc, (value, bit_len)| {
        assert_eq!(value >> bit_len, 0);
        (acc << bit_len) | value
    })
    .into()
}

fn hash(input: &[Fr]) -> Fr {
    let mut state = [Fr::from(0_u8); SPONGE_WIDTH];
    state[SPONGE_RATE] = Fr::from(u64::try_from(input.len()).unwrap()) * Fr::from(LENGTH_TAG_SCALE);
    for block in input.chunks(SPONGE_RATE) {
        for (lane, x) in state.iter_mut().zip(block) {
            *lane += x;
        }
        permutation_in_place(&mut state);
    }
    state[0]
}

fn code(index: Option<usize>) -> u128 {
    u128::try_from(index.unwrap()).unwrap() + 1
}

fn to_biguint(f: Fr) -> BigUint {
    BigUint::from_bytes_be(&f.into_bigint().to_bytes_be())
}
