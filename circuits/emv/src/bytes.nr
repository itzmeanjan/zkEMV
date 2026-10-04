pub global BITS_PER_BYTE: u32 = 8;
pub global BYTE_BASE: Field = pow2(BITS_PER_BYTE);
pub global BYTE_MASK: u128 = (1 << BITS_PER_BYTE as u128) - 1;
pub global BYTE_TOP_BIT_VALUE: Field = pow2(BITS_PER_BYTE - 1);

pub global NIBBLE_BIT_LEN: u8 = 4;
pub global NIBBLES_PER_BYTE: u32 = BITS_PER_BYTE / NIBBLE_BIT_LEN as u32;
pub global NIBBLE_MASK: u8 = (1 << NIBBLE_BIT_LEN) - 1;

global U64_BIT_LEN: u32 = 64;

pub global DECIMAL_BASE: u32 = 10;
pub global MAX_DECIMAL_DIGIT: u8 = DECIMAL_BASE as u8 - 1;

pub fn pow2(n: u32) -> Field {
    let mut x = 1;
    for _ in 0..n {
        x *= 2;
    }
    x
}

pub fn pow10(n: u32) -> u64 {
    let mut x = 1;
    for _ in 0..n {
        x *= DECIMAL_BASE as u64;
    }
    x
}

/// Bits needed to write `x`.
pub fn bit_length(x: u64) -> u32 {
    let mut bits = 0;
    let mut rest = x;
    for _ in 0..U64_BIT_LEN {
        if rest != 0 {
            bits += 1;
            rest >>= 1;
        }
    }
    bits
}

pub fn be_bytes_to_field<let N: u32>(b: [u8; N]) -> Field {
    let mut x = 0;
    for i in 0..N {
        x = x * BYTE_BASE + b[i] as Field;
    }
    x
}

pub fn nibbles(b: u8) -> (u8, u8) {
    (b >> NIBBLE_BIT_LEN, b & NIBBLE_MASK)
}

pub fn concat<let A: u32, let B: u32>(a: [u8; A], b: [u8; B]) -> [u8; A + B] {
    let mut out = [0; A + B];
    for i in 0..A {
        out[i] = a[i];
    }
    for i in 0..B {
        out[A + i] = b[i];
    }
    out
}

/// `N` bytes of `bytes` from `at`.
pub fn read<let N: u32, let L: u32>(bytes: [u8; L], at: u32) -> [u8; N] {
    let mut out = [0; N];
    for i in 0..N {
        out[i] = bytes[at + i];
    }
    out
}
