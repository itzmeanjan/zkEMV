//! RSA recovery for widths that are a multiple of 120 bits, where noir-bignum's Barrett
//! reduction has no top-limb headroom and witness generation fails. Works mod 2n, one bit
//! wider, then reduces mod n; s^3 mod 2n = s^3 (mod n).

use bignum::internal::{cmp, from_be_bytes_unsafe};
use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;
use std::cmp::Ordering;

/// An RSA key `n` of `BITS - 1` bits, held as arithmetic modulo `2n` (`BITS` bits).
pub struct DoubledKey<let N: u32, let BITS: u32> {
    params: BigNumParams<N, BITS>,
    n: [u128; N],
}

impl<let N: u32, let BITS: u32> DoubledKey<N, BITS> {
    /// `redc` is the Barrett hint for `2n`, not `n`.
    pub fn from_be_bytes(modulus: [u8; (BITS - 1) / 8], redc: [u128; N]) -> Self {
        let n = from_be_bytes_unsafe::<N, BITS>(&widen::<BITS>(modulus));

        let mut doubled = [0; N];
        let mut carry: u128 = 0;
        for i in 0..N {
            let v = 2 * n[i] + carry;
            doubled[i] = v & 0xffffffffffffffffffffffffffffff;
            carry = v >> 120;
        }
        assert_eq(carry, 0, "doubled modulus overflows its limbs");

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
