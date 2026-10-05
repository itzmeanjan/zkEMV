use crate::bytes::{be_bytes_to_field, BITS_PER_BYTE, BYTE_BASE};
use poseidon::poseidon2::Poseidon2;

pub global DOMAIN_SEPARATOR: Field = be_bytes_to_field("zkEMV nullifier v1".as_bytes());

/// Bytes per lane: the most that always fit in a field element.
global LANE_BYTE_LEN: u32 = (std::field::modulus_num_bits() as u32 - 1) / BITS_PER_BYTE;
global LANE_COUNT: u32 = 6;

global DOMAIN_SEPARATOR_INDEX: u32 = 0;
global SCOPE_INDEX: u32 = DOMAIN_SEPARATOR_INDEX + 1;
global FIRST_LANE_INDEX: u32 = SCOPE_INDEX + 1;
global HASH_INPUT_FIELD_COUNT: u32 = FIRST_LANE_INDEX + LANE_COUNT;

/// The card's identifier in `scope`: Poseidon2([DOMAIN_SEPARATOR, scope, m₀, …, m₅]), s.t., `m` being `modulus` in `LANE_BYTE_LEN`-byte lanes.
pub fn nullifier<let K: u32>(modulus: [u8; K], scope: Field) -> Field {
    std::static_assert(K <= LANE_COUNT * LANE_BYTE_LEN, "modulus exceeds the lanes");

    let mut input = [0; HASH_INPUT_FIELD_COUNT];
    input[DOMAIN_SEPARATOR_INDEX] = DOMAIN_SEPARATOR;
    input[SCOPE_INDEX] = scope;

    for i in 0..K {
        let lane = FIRST_LANE_INDEX + i / LANE_BYTE_LEN;
        input[lane] = input[lane] * BYTE_BASE + modulus[i] as Field;
    }

    Poseidon2::hash(input, HASH_INPUT_FIELD_COUNT)
}
