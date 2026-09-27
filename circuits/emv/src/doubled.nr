//! RSA recovery for widths that are a multiple of 120 bits, where noir-bignum's Barrett
//! reduction has no top-limb headroom and witness generation fails. Works mod 2n, one bit
//! wider, then reduces mod n; s^3 mod 2n = s^3 (mod n).

use bignum::internal::{cmp, from_be_bytes_unsafe};
use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use std::cmp::Ordering;

global TWO_POW_120: Field = 0x1000000000000000000000000000000;

/// An RSA key `n` of `BITS - 1` bits, held as arithmetic modulo `2n` (`BITS` bits).
pub struct DoubledKey<let N: u32, let BITS: u32> {
    params: BigNumParams<N, BITS>,
    n: [u128; N],
}

impl<let N: u32, let BITS: u32> DoubledKey<N, BITS> {
    /// `redc` is the Barrett hint for `2n`, not `n`.
    pub fn from_be_bytes(modulus: [u8; (BITS - 1) / 8], redc: [u128; N]) -> Self {
        let n = from_be_bytes_unsafe::<N, BITS>(&widen::<BITS>(modulus));

        // `BigNumParams::new` range-checks doubled[i] below 2^120 and carries are boolean, so
        // this relation cannot wrap the field: doubled is exactly 2n.
        // Safety: constrained by the loop below.
        let (doubled, carries) = unsafe { __double(n) };
        let mut carry_in: Field = 0;
        for i in 0..N {
            assert_eq(2 * (n[i] as Field) + carry_in, (doubled[i] as Field) + (carries[i] as Field) * TWO_POW_120);
            carry_in = carries[i] as Field;
        }
        assert(!carries[N - 1], "doubled modulus overflows its limbs");

        // Top bit of 2n at BITS: n is exactly BITS - 1 bits.
        let params = BigNumParams::new(false, doubled, redc);
        Self { params, n }
    }

    pub fn recover(self, sig: [u8; (BITS - 1) / 8]) -> [u8; (BITS - 1) / 8] {
        let n = RuntimeBigNum { limbs: self.n, params: self.params };
        // `from_be_bytes` only bounds sig below 2n.
        let s = RuntimeBigNum::from_be_bytes(self.params, widen::<BITS>(sig));
        assert(cmp::<N, BITS>(&s.limbs, &self.n) == Ordering::less(), "signature >= modulus");

        // `udiv_mod` constrains c = q * n + m with m < n.
        let c = s.sqr() * s;
        let (_, m) = c.udiv_mod(&n);

        let bytes = m.to_be_bytes();
        assert_eq(bytes[0], 0);
        let mut out = [0; (BITS - 1) / 8];
        for i in 0..(BITS - 1) / 8 {
            out[i] = bytes[1 + i];
        }
        out
    }
}

fn widen<let BITS: u32>(x: [u8; (BITS - 1) / 8]) -> [u8; (BITS + 7) / 8] {
    let mut out = [0; (BITS + 7) / 8];
    for i in 0..(BITS - 1) / 8 {
        out[1 + i] = x[i];
    }

    out
}

unconstrained fn __double<let N: u32>(n: [u128; N]) -> ([u128; N], [bool; N]) {
    let mut doubled = [0; N];
    let mut carries = [false; N];

    let mut carry_in: u128 = 0;
    for i in 0..N {
        let v = 2 * n[i] + carry_in;

        doubled[i] = v & 0xffffffffffffffffffffffffffffff;
        carries[i] = (v >> 120) != 0;

        carry_in = carries[i] as u128;
    }

    (doubled, carries)
}
