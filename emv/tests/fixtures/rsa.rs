//! RSA with public exponent 3, signing ISO/IEC 9796-2 scheme 1 blocks as EMV Book 2 does.

use num_bigint::BigUint;
use sha1::{Digest, Sha1};

use crate::{
    Rng, be_bytes,
    layout::{BITS_PER_BYTE, RECOVERED_DATA_HEADER, RECOVERED_DATA_TRAILER, RSA_EXPONENT},
    random_bytes,
};

const PRIME_COUNT: usize = 2;
/// Set in each prime, so the product of two is exactly twice as long.
const PRIME_TOP_BITS: u8 = 0b11;
const PRIME_TOP_BIT_COUNT: usize = 2;
const SMALL_PRIMES: [u8; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
const MILLER_RABIN_ROUND_COUNT: usize = 40;

pub(crate) struct RsaKey {
    n: BigUint,
    d: BigUint,
    byte_len: usize,
}

impl RsaKey {
    pub(crate) fn generate(bit_len: usize, rng: &mut Rng) -> Self {
        loop {
            let p = prime(bit_len / PRIME_COUNT, rng);
            let q = prime(bit_len / PRIME_COUNT, rng);
            let n = &p * &q;
            if p != q && n.bits() == u64::try_from(bit_len).unwrap() {
                let phi = (p - 1_u8) * (q - 1_u8);
                let d = BigUint::from(RSA_EXPONENT).modinv(&phi).unwrap();
                return Self {
                    n,
                    d,
                    byte_len: bit_len / BITS_PER_BYTE,
                };
            }
        }
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub(crate) fn modulus(&self) -> Vec<u8> {
        be_bytes(&self.n, self.byte_len)
    }

    pub(crate) fn private_exponent(&self) -> Vec<u8> {
        be_bytes(&self.d, self.byte_len)
    }

    /// `6A || body || SHA-1(body || hashed_tail) || BC` as one RSA block: scheme 1 recovers the
    /// whole message, so there is no separate padding.
    pub(crate) fn sign(&self, body: &[u8], hashed_tail: &[u8]) -> Vec<u8> {
        let digest = Sha1::new().chain_update(body).chain_update(hashed_tail).finalize();
        let block = [&[RECOVERED_DATA_HEADER], body, &digest, &[RECOVERED_DATA_TRAILER]].concat();
        let x = BigUint::from_bytes_be(&block);
        assert!(x < self.n);
        let s = x.modpow(&self.d, &self.n);
        assert_eq!(s.modpow(&BigUint::from(RSA_EXPONENT), &self.n), x);
        be_bytes(&s, self.byte_len)
    }
}

/// `p mod 3 = 2`, so 3 is invertible modulo `p - 1`.
fn prime(bit_len: usize, rng: &mut Rng) -> BigUint {
    let top = BigUint::from(PRIME_TOP_BITS) << (bit_len - PRIME_TOP_BIT_COUNT);
    loop {
        let p = BigUint::from_bytes_be(&random_bytes(rng, bit_len / BITS_PER_BYTE)) | &top | BigUint::from(1_u8);
        if &p % RSA_EXPONENT == BigUint::from(RSA_EXPONENT - 1) && is_probable_prime(&p, rng) {
            return p;
        }
    }
}

/// Miller-Rabin with witnesses in `2..=n - 2`, after trial division.
fn is_probable_prime(n: &BigUint, rng: &mut Rng) -> bool {
    for small in SMALL_PRIMES {
        if n % small == BigUint::ZERO {
            return *n == BigUint::from(small);
        }
    }
    let one = BigUint::from(1_u8);
    let two = BigUint::from(2_u8);
    let n_minus_one = n - &one;
    let witness_span = n - 3_u8;
    let witness_byte_len = n.to_bytes_be().len();
    let r = n_minus_one.trailing_zeros().unwrap();
    let d = &n_minus_one >> r;
    'witness: for _ in 0..MILLER_RABIN_ROUND_COUNT {
        let witness = BigUint::from_bytes_be(&random_bytes(rng, witness_byte_len)) % &witness_span + &two;
        let mut x = witness.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'witness;
            }
        }
        return false;
    }
    true
}
