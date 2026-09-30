//! RSA with public exponent 3 and message recovery, laid out for ProveKit's R1CS.
//!
//! Numbers are little-endian 120-bit limbs. A product `a b = q n + r` is checked as the polynomial
//! identity `a(X) b(X) - q(X) n(X) - r(X) = (X - 2^120) h(X)` at 2N - 1 constant points, two
//! multiplications each, instead of N^2 limb products. With every limb below 2^120 and every carry
//! in `h` below 2^125 in magnitude, both sides stay far below the field modulus, so the identity
//! holds over the integers. Recovery is `s^2 = q1 n + t`, then `t s = q2 n + m`, so
//! `m = s^3 (mod n)`; `m < n` is checked explicitly. `s < n` isn't needed: `s mod n` recovers the
//! same message. One Brillig call per recovery supplies every hint.

global LIMB_BITS: u32 = 120;
global LIMB: Field = 0x1000000000000000000000000000000;
/// Carries lie in (-2^125, 2^125) while N < 31 (see `recover`), so `h + 2^125` fits in 126 bits.
global CARRY_OFFSET: Field = LIMB * 32;

/// An RSA public key with exponent 3 and a `B`-byte modulus.
pub struct RsaKey<let B: u32> {
    n: [Field; (B + 14) / 15],
}

impl<let B: u32> RsaKey<B> {
    /// The public CA modulus. Its limbs aren't range-checked here: the verifier compares them with
    /// its CA table.
    pub fn from_limbs(n: [Field; (B + 14) / 15]) -> Self {
        RsaKey { n }
    }

    /// A modulus recovered from a certificate, whose bytes are range-checked. Its top bit must be
    /// set, so the key is exactly `8 B` bits.
    pub fn from_be_bytes(n: [u8; B]) -> Self {
        (n[0] as Field - 0x80).assert_max_bit_size::<7>();
        RsaKey { n: limbs(n) }
    }

    /// `sig^3 mod n`, as `B` big-endian bytes.
    pub fn recover(self, sig: [u8; B]) -> [u8; B] {
        std::static_assert((B + 14) / 15 < 31, "carry bound needs fewer than 31 limbs");
        let s = limbs(sig);
        // Safety: range-checked, and tied to `s` and `n` by `assert_product`.
        let (q1, t, h1) = unsafe { square_hints(self.n, s) };
        range_check(q1);
        range_check(t);
        assert_product(s, s, self.n, q1, t, h1);

        // Separate from `square_hints` so that `t`, once constrained, counts as an input for the
        // compiler's Brillig-constraint check.
        // Safety: range-checked, and tied to `t`, `s` and `n` by `assert_product` and `assert_below`.
        let hint = unsafe { cube_hints(self.n, s, t) };
        range_check(hint.q2);
        range_check(hint.d);
        let m = limbs(hint.m);
        assert_product(t, s, self.n, hint.q2, m, hint.h2);
        assert_below(m, self.n, hint.d, hint.c);
        hint.m
    }
}

/// Little-endian 120-bit limbs of big-endian bytes.
fn limbs<let B: u32>(bytes: [u8; B]) -> [Field; (B + 14) / 15] {
    let mut out = [0; (B + 14) / 15];
    let mut scale = 1;
    for i in 0..B {
        out[i / 15] += bytes[B - 1 - i] as Field * scale;
        scale = if i % 15 == 14 { 1 } else { scale * 256 };
    }
    out
}

fn range_check<let N: u32>(x: [Field; N]) {
    for i in 0..N {
        x[i].assert_max_bit_size::<LIMB_BITS>();
    }
}

fn eval<let N: u32>(a: [Field; N], x: Field) -> Field {
    let mut acc = 0;
    for i in 0..N {
        acc = acc * x + a[N - 1 - i];
    }
    std::as_witness(acc);
    acc
}

/// Asserts `a b = q n + r` over the integers, with `h` the carries. The polynomial identity has
/// degree 2N - 2, so 2N - 1 points pin it.
fn assert_product<let N: u32>(a: [Field; N], b: [Field; N], n: [Field; N], q: [Field; N], r: [Field; N], h: [Field; 2 * N - 2]) {
    for i in 0..2 * N - 2 {
        (h[i] + CARRY_OFFSET).assert_max_bit_size::<LIMB_BITS + 6>();
    }
    for k in 0..2 * N - 1 {
        let x = k as Field;
        let qn = eval(q, x) * eval(n, x);
        std::as_witness(qn);
        assert_eq(eval(a, x) * eval(b, x), qn + eval(r, x) + (x - LIMB) * eval(h, x));
    }
}

/// Asserts `m < n`: `m + 1 + d = n` limb by limb for range-checked `d`, with `c` the carries.
/// Hints on one side and `n` alone on the other, as the Brillig-constraint check expects.
fn assert_below<let N: u32>(m: [Field; N], n: [Field; N], d: [Field; N], c: [Field; N]) {
    let mut carry_in = 1;
    for i in 0..N {
        assert_eq(c[i] * c[i], c[i]);
        assert_eq(m[i] + d[i] + carry_in - c[i] * LIMB, n[i]);
        carry_in = c[i];
    }
    assert_eq(carry_in, 0);
}

/// `s^2 = q1 n + t`, with the carries.
unconstrained fn square_hints<let N: u32>(n: [Field; N], s: [Field; N]) -> ([Field; N], [Field; N], [Field; 2 * N - 2]) {
    let sd = digits(s);
    let (q1, t) = divmod(mul(sd, sd), digits(n));
    let (q1, t) = (from_digits(q1), from_digits(t));
    (q1, t, carries(s, s, n, q1, t))
}

struct CubeHints<let N: u32, let B: u32> {
    q2: [Field; N],
    h2: [Field; 2 * N - 2],
    m: [u8; B],
    d: [Field; N],
    c: [Field; N],
}

/// `t s = q2 n + m` with the carries, `m` as bytes, and `d = n - 1 - m` with the carries of
/// `m + 1 + d`.
unconstrained fn cube_hints<let N: u32, let B: u32>(n: [Field; N], s: [Field; N], t: [Field; N]) -> CubeHints<N, B> {
    let (q2, m) = divmod(mul(digits(t), digits(s)), digits(n));
    let (q2, m) = (from_digits(q2), from_digits(m));
    let h2 = carries(t, s, n, q2, m);

    // d = n - 1 - m, then the carries of m + 1 + d.
    let mut d = [0; N];
    let mut borrow: u128 = 1;
    for i in 0..N {
        let (ni, mi) = (n[i] as u128, m[i] as u128);
        let sub = mi + borrow;
        if ni >= sub {
            d[i] = (ni - sub) as Field;
            borrow = 0;
        } else {
            d[i] = (ni + (1 << 120) - sub) as Field;
            borrow = 1;
        }
    }
    let mut c = [0; N];
    let mut carry: u128 = 1;
    for i in 0..N {
        let sum = m[i] as u128 + d[i] as u128 + carry;
        carry = sum >> 120;
        c[i] = carry as Field;
    }

    let mut bytes = [0; B];
    for i in 0..B {
        let limb = m[i / 15] as u128;
        bytes[B - 1 - i] = ((limb >> (8 * (i % 15)) as u128) & 0xff) as u8;
    }

    CubeHints { q2, h2, m: bytes, d, c }
}

/// The carries `h` of `a b - q n - r = (X - 2^120) h(X)`: `h_k = (h_{k-1} - c_k) / 2^120`, exact
/// over the integers, so computed in the field.
unconstrained fn carries<let N: u32>(a: [Field; N], b: [Field; N], n: [Field; N], q: [Field; N], r: [Field; N]) -> [Field; 2 * N - 2] {
    let inv = 1 / LIMB;
    let mut h = [0; 2 * N - 2];
    let mut prev = 0;
    for k in 0..2 * N - 2 {
        let mut c = 0;
        for i in 0..N {
            if k >= i {
                if k - i < N {
                    c += a[i] * b[k - i] - q[i] * n[k - i];
                }
            }
        }
        if k < N {
            c -= r[k];
        }
        prev = (prev - c) * inv;
        h[k] = prev;
    }
    h
}

// Brillig big integers: little-endian 60-bit digits in u128, so a digit product fits.

global DIGIT_BITS: u128 = 60;
global DIGIT: u128 = 1 << 60;
global MASK: u128 = (1 << 60) - 1;

unconstrained fn digits<let N: u32>(limbs: [Field; N]) -> [u128; 2 * N] {
    let mut out = [0; 2 * N];
    for i in 0..N {
        let limb = limbs[i] as u128;
        out[2 * i] = limb & MASK;
        out[2 * i + 1] = limb >> DIGIT_BITS;
    }
    out
}

/// The low N limbs; the hints of an honest prover fit.
unconstrained fn from_digits<let N: u32, let D: u32>(d: [u128; D]) -> [Field; N] {
    let mut out = [0; N];
    for i in 0..N {
        out[i] = (d[2 * i] + (d[2 * i + 1] << DIGIT_BITS)) as Field;
    }
    for i in 2 * N..D {
        assert_eq(d[i], 0, "hint exceeds its limbs");
    }
    out
}

unconstrained fn mul<let L: u32>(a: [u128; L], b: [u128; L]) -> [u128; 2 * L] {
    let mut out = [0; 2 * L];
    for i in 0..L {
        let mut carry = 0;
        for j in 0..L {
            let v = out[i + j] + a[i] * b[j] + carry;
            out[i + j] = v & MASK;
            carry = v >> DIGIT_BITS;
        }
        out[i + L] = carry;
    }
    out
}

/// Long division, Knuth's algorithm D (TAOCP 4.3.1) as in Hacker's Delight `divmnu`, base 2^60.
unconstrained fn divmod<let U: u32, let V: u32>(u: [u128; U], v: [u128; V]) -> ([u128; U], [u128; V]) {
    let mut n = 0;
    for i in 0..V {
        if v[i] != 0 {
            n = i + 1;
        }
    }
    let mut m = 0;
    for i in 0..U {
        if u[i] != 0 {
            m = i + 1;
        }
    }
    assert(n >= 2, "divisor needs two digits");
    let mut q = [0; U];
    let mut r = [0; V];
    if m < n {
        for i in 0..V {
            r[i] = u[i];
        }
    } else {
        // Normalise so the divisor's top digit has its top bit set.
        let mut s: u128 = 0;
        let mut top = v[n - 1];
        for _ in 0..60 {
            if top < (1 << 59) {
                top <<= 1;
                s += 1;
            }
        }
        let mut vn = [0; V];
        for i in 1..n {
            vn[i] = ((v[i] << s) | (v[i - 1] >> (DIGIT_BITS - s))) & MASK;
        }
        vn[0] = (v[0] << s) & MASK;
        let mut un = [0; U + 1];
        un[m] = u[m - 1] >> (DIGIT_BITS - s);
        for i in 1..m {
            un[i] = ((u[i] << s) | (u[i - 1] >> (DIGIT_BITS - s))) & MASK;
        }
        un[0] = (u[0] << s) & MASK;

        for jj in 0..m - n + 1 {
            let j = m - n - jj;
            let num = un[j + n] * DIGIT + un[j + n - 1];
            let mut qhat = num / vn[n - 1];
            let mut rhat = num % vn[n - 1];
            for _ in 0..2 {
                if rhat < DIGIT {
                    if (qhat >= DIGIT) | (qhat * vn[n - 2] > rhat * DIGIT + un[j + n - 2]) {
                        qhat -= 1;
                        rhat += vn[n - 1];
                    }
                }
            }

            // un[j..j+n] -= qhat vn; the partial remainder then fits in n digits.
            let mut carry = 0;
            let mut borrow = 0;
            for i in 0..n {
                let p = qhat * vn[i] + carry;
                carry = p >> DIGIT_BITS;
                let sub = (p & MASK) + borrow;
                if un[i + j] >= sub {
                    un[i + j] -= sub;
                    borrow = 0;
                } else {
                    un[i + j] = un[i + j] + DIGIT - sub;
                    borrow = 1;
                }
            }
            if un[j + n] < carry + borrow {
                // qhat was one too large: add vn back, dropping the carry out.
                qhat -= 1;
                let mut c = 0;
                for i in 0..n {
                    let v = un[i + j] + vn[i] + c;
                    un[i + j] = v & MASK;
                    c = v >> DIGIT_BITS;
                }
            }
            un[j + n] = 0;
            q[j] = qhat;
        }

        for i in 0..n {
            r[i] = (un[i] >> s) | ((un[i + 1] << (DIGIT_BITS - s)) & MASK);
        }
    }
    (q, r)
}
