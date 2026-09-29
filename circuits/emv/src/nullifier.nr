use poseidon::poseidon2::Poseidon2;

/// Result of python3 -c 'print(hex(int.from_bytes(b"zkEMV nullifier v1", "big")))'
pub global DOMAIN_SEPARATOR: Field = 0x7a6b454d56206e756c6c6966696572207631;

/// Bytes per lane: 31 bytes always fit in a field element.
global CHUNK: u32 = 31;
global LANES: u32 = 6;

/// The card's identifier in `scope`: Poseidon2([DOMAIN_SEPARATOR, scope, m₀, …, m₅]), s.t., `m` being `modulus` in 31-byte lanes.
pub fn nullifier<let K: u32>(modulus: [u8; K], scope: Field) -> Field {
    std::static_assert(K <= LANES * CHUNK, "modulus exceeds six lanes");

    let mut input = [0; 2 + LANES];
    input[0] = DOMAIN_SEPARATOR;
    input[1] = scope;

    for i in 0..K {
        let lane = 2 + i / CHUNK;
        input[lane] = input[lane] * 256 + modulus[i] as Field;
    }

    Poseidon2::hash(input, 2 + LANES)
}
