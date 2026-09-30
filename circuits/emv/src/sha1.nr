//! SHA-1 (FIPS 180-4), laid out for ProveKit's R1CS.
//!
//! Boolean functions work on spread words, bit i moved to bit 2i. Adding two or three spreads and
//! splitting the sum as `spread(x) + 2 spread(y)` gives x = XOR and y = AND or MAJ per bit; the sum
//! stays below 4^32, so the split is unique. Each chunk is a read of a constant table, which bounds
//! the chunk and returns its spread in one lookup. State words are cut at bits 2 and 27 and schedule
//! words at bit 31, so ROTL30, ROTL5 and ROTL1 are linear in the chunks. One Brillig call per block
//! supplies every chunk.
//!
//! An optimization over baseline Noir implementation of SHA1 https://github.com/zac-williamson/sha1.

global SPREAD11: [Field; 2048] = spread_table();
global SPREAD5: [Field; 32] = spread_table();
global SPREAD3: [Field; 8] = spread_table();
global SPREAD2: [Field; 4] = spread_table();

global POW2: [Field; 65] = {
    let mut t = [1; 65];
    for i in 1..65 {
        t[i] = t[i - 1] * 2;
    }

    t
};

/// spread(2^32 - 1): subtracting a spread from it complements the word.
global SPREAD_ONES: Field = 0x5555555555555555;

global IV: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
global K: [Field; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

fn spread_table<let L: u32>() -> [Field; L] {
    let mut table = [0; L];
    for i in 0..L {
        let mut s = 0;
        for b in 0..11 {
            if ((i >> b) & 1) == 1 {
                s += POW2[2 * b];
            }
        }
        table[i] = s;
    }
    table
}

/// A state word in chunks of 2, 11, 11, 3 and 5 bits (bits 0, 2, 13, 24, 27), with their spreads.
struct Word {
    c: [Field; 5],
    s: [Field; 5],
}

impl Word {
    fn new(c: [u32; 5]) -> Self {
        Word {
            c: [c[0] as Field, c[1] as Field, c[2] as Field, c[3] as Field, c[4] as Field],
            s: [SPREAD2[c[0]], SPREAD11[c[1]], SPREAD11[c[2]], SPREAD3[c[3]], SPREAD5[c[4]]],
        }
    }

    fn raw(self) -> Field {
        self.c[0] + self.c[1] * POW2[2] + self.c[2] * POW2[13] + self.c[3] * POW2[24] + self.c[4] * POW2[27]
    }

    fn rotl5(self) -> Field {
        self.c[0] * POW2[5] + self.c[1] * POW2[7] + self.c[2] * POW2[18] + self.c[3] * POW2[29] + self.c[4]
    }

    fn rotl30(self) -> Field {
        self.c[1] + self.c[2] * POW2[11] + self.c[3] * POW2[22] + self.c[4] * POW2[25] + self.c[0] * POW2[30]
    }

    fn spread(self) -> Field {
        self.s[0] + self.s[1] * POW2[4] + self.s[2] * POW2[26] + self.s[3] * POW2[48] + self.s[4] * POW2[54]
    }

    fn spread_rotl30(self) -> Field {
        self.s[1] + self.s[2] * POW2[22] + self.s[3] * POW2[44] + self.s[4] * POW2[50] + self.s[0] * POW2[60]
    }
}

fn cut(x: u32) -> [u32; 5] {
    [x & 3, (x >> 2) & 0x7ff, (x >> 13) & 0x7ff, (x >> 24) & 7, x >> 27]
}

fn cut11(x: u32) -> [u32; 3] {
    [x & 0x7ff, (x >> 11) & 0x7ff, x >> 22]
}

fn rotl(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn raw11(c: [u32; 3]) -> Field {
    c[0] as Field + c[1] as Field * POW2[11] + c[2] as Field * POW2[22]
}

fn spread11(c: [u32; 3]) -> Field {
    SPREAD11[c[0]] + SPREAD11[c[1]] * POW2[22] + SPREAD11[c[2]] * POW2[44]
}

/// Asserts `sum = spread(x) + 2 spread(y)` for a sum of at most three spreads, and returns
/// spread(x).
fn split(sum: Field, x: [u32; 3], y: [u32; 3]) -> Field {
    let sx = spread11(x);
    assert_eq(sum, sx + 2 * spread11(y));
    sx
}

/// What a block's rounds read of the chaining value: A_-1 to A_-4 (H0, H1, ROTL2 of H2 and of H3)
/// as words, and H4, which is only added.
struct State {
    w: [Word; 4],
    e: Field,
}

fn chaining(state: State) -> [Field; 5] {
    [state.w[0].raw(), state.w[1].raw(), state.w[2].rotl30(), state.w[3].rotl30(), state.e]
}

fn initial_state() -> State {
    State {
        w: [
            Word::new(comptime { cut(IV[0]) }),
            Word::new(comptime { cut(IV[1]) }),
            Word::new(comptime { cut(rotl(IV[2], 2)) }),
            Word::new(comptime { cut(rotl(IV[3], 2)) }),
        ],
        e: IV[4] as Field,
    }
}

struct Hints {
    msg: [[u32; 3]; 16],
    // Schedule, t = 16..80: x1 = w[t-3] ^ w[t-8] ^ w[t-14], x2 = x1 ^ w[t-16], w[t] = ROTL1(x2).
    x1: [[u32; 3]; 64],
    y1: [[u32; 3]; 64],
    // x2 in chunks of 11, 11 and 9 bits, and bit 31.
    x2: [[u32; 3]; 64],
    x2_top: [Field; 64],
    y2: [[u32; 3]; 64],
    // Rounds: the split of b + c (+ d), and for Ch also of ~b + d.
    fx: [[u32; 3]; 80],
    fy: [[u32; 3]; 80],
    gx: [[u32; 3]; 20],
    gy: [[u32; 3]; 20],
    a: [[u32; 5]; 78],
    // A_78 below and above bit 27.
    a78: [Field; 2],
    carry: [Field; 79],
    out_carry: [Field; 5],
}

unconstrained fn block_hints(h: [Field; 5], block: [Field; 16]) -> Hints {
    let mut hint = Hints {
        msg: [[0; 3]; 16],
        x1: [[0; 3]; 64],
        y1: [[0; 3]; 64],
        x2: [[0; 3]; 64],
        x2_top: [0; 64],
        y2: [[0; 3]; 64],
        fx: [[0; 3]; 80],
        fy: [[0; 3]; 80],
        gx: [[0; 3]; 20],
        gy: [[0; 3]; 20],
        a: [[0; 5]; 78],
        a78: [0; 2],
        carry: [0; 79],
        out_carry: [0; 5],
    };

    let mut w: [u32; 80] = [0; 80];
    for t in 0..16 {
        w[t] = block[t] as u32;
        hint.msg[t] = cut11(w[t]);
    }
    for t in 16..80 {
        let (p, q, r, s) = (w[t - 3], w[t - 8], w[t - 14], w[t - 16]);
        let x1 = p ^ q ^ r;
        hint.x1[t - 16] = cut11(x1);
        hint.y1[t - 16] = cut11((p & q) | (p & r) | (q & r));
        let x2 = x1 ^ s;
        hint.x2[t - 16] = [x2 & 0x7ff, (x2 >> 11) & 0x7ff, (x2 >> 22) & 0x1ff];
        hint.x2_top[t - 16] = (x2 >> 31) as Field;
        hint.y2[t - 16] = cut11(x1 & s);
        w[t] = rotl(x2, 1);
    }

    let h: [u32; 5] = h.map(|v: Field| v as u32);
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    let mut t79: u64 = 0;
    for t in 0..80 {
        let f = if t < 20 {
            hint.fx[t] = cut11(b ^ c);
            hint.fy[t] = cut11(b & c);
            hint.gx[t] = cut11(!b ^ d);
            hint.gy[t] = cut11(!b & d);
            (b & c) | (!b & d)
        } else {
            let parity = b ^ c ^ d;
            let maj = (b & c) | (b & d) | (c & d);
            hint.fx[t] = cut11(parity);
            hint.fy[t] = cut11(maj);
            if (t >= 40) & (t < 60) {
                maj
            } else {
                parity
            }
        };
        let temp = rotl(a, 5) as u64 + f as u64 + e as u64 + (K[t / 20] as u32) as u64 + w[t] as u64;
        let next = temp as u32;
        if t < 78 {
            hint.a[t] = cut(next);
        } else if t == 78 {
            hint.a78 = [(next & 0x7ffffff) as Field, (next >> 27) as Field];
        } else {
            t79 = temp;
        }
        if t < 79 {
            hint.carry[t] = (temp >> 32) as Field;
        }
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = next;
    }

    let sums = [h[0] as u64 + t79, h[1] as u64 + b as u64, h[2] as u64 + c as u64, h[3] as u64 + d as u64, h[4] as u64 + e as u64];
    for k in 0..5 {
        hint.out_carry[k] = (sums[k] >> 32) as Field;
    }
    hint
}

/// Chunks of the next block's State words. Separate from `block_hints`: a Brillig output that is
/// never used as a table index is range-checked, and the last block has no next state.
unconstrained fn next_hints(sums: [Field; 5]) -> [[u32; 5]; 4] {
    let mut out = [[0; 5]; 4];
    for k in 0..4 {
        let v = sums[k] as u64 as u32;
        out[k] = if k < 2 { cut(v) } else { cut(rotl(v, 2)) };
    }
    out
}

/// The chaining sums of a compression, before reduction mod 2^32.
struct Chained {
    sums: [Field; 5],
    carry: [Field; 5],
}

impl Chained {
    fn assert_carries(self) {
        // sums[0] adds H0 to an unreduced round sum of five words.
        self.carry[0].assert_max_bit_size::<3>();
        for k in 1..5 {
            assert_eq(self.carry[k] * self.carry[k], self.carry[k]);
        }
    }

    /// The state for another block.
    fn next(self) -> State {
        self.assert_carries();
        // Safety: each word is tied to its sum below.
        let out = unsafe { next_hints(self.sums) };
        let mut w = [Word { c: [0; 5], s: [0; 5] }; 4];
        for k in 0..4 {
            let word = Word::new(out[k]);
            let v = if k < 2 { word.raw() } else { word.rotl30() };
            assert_eq(v + self.carry[k] * POW2[32], self.sums[k]);
            w[k] = word;
        }
        let e = self.sums[4] - self.carry[4] * POW2[32];
        e.assert_max_bit_size::<32>();
        State { w, e }
    }

    /// The hash, when this was the last block.
    fn digest(self) -> [Field; 5] {
        self.assert_carries();
        let mut out = [0; 5];
        for k in 0..5 {
            out[k] = self.sums[k] - self.carry[k] * POW2[32];
            out[k].assert_max_bit_size::<32>();
        }
        out
    }
}

/// One compression. `block` holds 16 words, each already known to be below 2^32.
///
/// `words[j]` is A_{j-5}, the output of round j - 5; round t reads a, b, c, d, e from words t + 4
/// to t (e from H4 in round 0). A_78 is only rotated and added and A_79 only added, so neither is
/// cut into table chunks: a table read whose result goes unused is replaced by a costlier bounds
/// check.
fn compress(state: State, block: [Field; 16]) -> Chained {
    let h = chaining(state);
    // Safety: chunks are bounded by their table reads and tied to the words by the asserts below;
    // carries, A_78's halves and the top schedule bit are range-checked.
    let hint = unsafe { block_hints(h, block) };

    let mut w: [Field; 80] = [0; 80];
    let mut sw: [Field; 80] = [0; 80];
    for t in 0..16 {
        assert_eq(raw11(hint.msg[t]), block[t]);
        w[t] = block[t];
        sw[t] = spread11(hint.msg[t]);
    }
    for t in 16..80 {
        let x1 = split(
            sw[t - 3] + sw[t - 8] + sw[t - 14],
            hint.x1[t - 16],
            hint.y1[t - 16],
        );
        let lo = hint.x2[t - 16];
        let top = hint.x2_top[t - 16];
        // The 9-bit chunk sits below bit 31, so it must be exact for ROTL1 to be sound.
        (lo[2] as Field).assert_max_bit_size::<9>();
        assert_eq(top * top, top);
        let lo_spread = spread11(lo);
        assert_eq(x1 + sw[t - 16], lo_spread + top * POW2[62] + 2 * spread11(hint.y2[t - 16]));
        w[t] = 2 * raw11(lo) + top;
        sw[t] = 4 * lo_spread + top;
    }

    let mut words = [Word { c: [0; 5], s: [0; 5] }; 83];
    for k in 0..4 {
        words[4 - k] = state.w[k];
    }
    let mut a5 = state.w[0].rotl5();
    for t in 0..20 {
        let b = words[t + 3].spread();
        let _ = split(b + words[t + 2].spread_rotl30(), hint.fx[t], hint.fy[t]);
        let _ = split(
            SPREAD_ONES - b + words[t + 1].spread_rotl30(),
            hint.gx[t],
            hint.gy[t],
        );
        let f = raw11(hint.fy[t]) + raw11(hint.gy[t]);
        let e = if t == 0 { state.e } else { words[t].rotl30() };
        words[t + 5] = reduce(a5 + f + e + K[0] + w[t], hint.a[t], hint.carry[t]);
        a5 = words[t + 5].rotl5();
    }
    for t in 20..78 {
        let f = parity_or_maj(words, t, hint);
        words[t + 5] = reduce(
            a5 + f + words[t].rotl30() + K[t / 20] + w[t],
            hint.a[t],
            hint.carry[t],
        );
        a5 = words[t + 5].rotl5();
    }

    let (lo, hi) = (hint.a78[0], hint.a78[1]);
    lo.assert_max_bit_size::<27>();
    hi.assert_max_bit_size::<5>();
    hint.carry[78].assert_max_bit_size::<3>();
    let t78 = a5 + parity_or_maj(words, 78, hint) + words[78].rotl30() + K[3] + w[78];
    assert_eq(lo + hi * POW2[27] + hint.carry[78] * POW2[32], t78);
    let t79 = lo * POW2[5] + hi + parity_or_maj(words, 79, hint) + words[79].rotl30() + K[3] + w[79];

    Chained {
        sums: [h[0] + t79, h[1] + lo + hi * POW2[27], h[2] + words[82].rotl30(), h[3] + words[81].rotl30(), h[4] + words[80].rotl30()],
        carry: hint.out_carry,
    }
}

/// f for rounds 20 to 79: MAJ in 40 to 59, XOR otherwise.
fn parity_or_maj(words: [Word; 83], t: u32, hint: Hints) -> Field {
    let sum = words[t + 3].spread() + words[t + 2].spread_rotl30() + words[t + 1].spread_rotl30();
    let _ = split(sum, hint.fx[t], hint.fy[t]);
    if (t >= 40) & (t < 60) {
        raw11(hint.fy[t])
    } else {
        raw11(hint.fx[t])
    }
}

/// The word `temp mod 2^32`, for a `temp` of at most five 32-bit terms.
fn reduce(temp: Field, a: [u32; 5], carry: Field) -> Word {
    let word = Word::new(a);
    carry.assert_max_bit_size::<3>();
    assert_eq(word.raw() + carry * POW2[32], temp);
    word
}

/// Big-endian words of `bytes`, whose bytes are all below 256.
fn to_words<let W: u32>(bytes: [Field; 4 * W]) -> [Field; W] {
    let mut words = [0; W];
    for q in 0..W {
        words[q] = bytes[4 * q] * POW2[24] + bytes[4 * q + 1] * POW2[16] + bytes[4 * q + 2] * POW2[8] + bytes[4 * q + 3];
    }
    words
}

fn block_of<let W: u32>(words: [Field; W], k: u32) -> [Field; 16] {
    let mut block = [0; 16];
    for i in 0..16 {
        block[i] = words[16 * k + i];
    }
    block
}

/// SHA-1 of `msg` as five big-endian words, each below 2^32.
pub fn digest_words<let N: u32>(msg: [u8; N]) -> [Field; 5] {
    let mut bytes = [0; ((N + 72) / 64) * 64];
    for i in 0..N {
        bytes[i] = msg[i] as Field;
    }
    bytes[N] = 0x80;
    let mut words: [Field; ((N + 72) / 64) * 16] = to_words(bytes);
    words[((N + 72) / 64) * 16 - 1] = (8 * N) as Field;

    let mut state = initial_state();
    for k in 0..(N + 72) / 64 - 1 {
        state = compress(state, block_of(words, k)).next();
    }
    compress(state, block_of(words, (N + 72) / 64 - 1)).digest()
}

unconstrained fn one_hot<let L: u32>(i: u32) -> [Field; L] {
    let mut flags = [0; L];
    flags[i] = 1;
    flags
}

/// 1 if the message, `P` bytes plus the tail length flagged in `end`, ends in block `k`: its
/// length is in [64k - 8, 64k + 56).
fn ends_in<let P: u32, let S: u32>(end: [Field; S + 1], k: u32) -> Field {
    let mut last = 0;
    for j in 0..S + 1 {
        if (P + j + 8 >= 64 * k) & (P + j + 8 < 64 * k + 64) {
            last += end[j];
        }
    }
    std::as_witness(last);
    last
}

/// SHA-1 of `head || tail` as five big-endian words. Every block the tail can reach is compressed;
/// the output is selected from the blocks the message can end in.
pub fn digest_words_var<let P: u32, let S: u32>(head: [u8; P], tail: BoundedVec<u8, S>) -> [Field; 5] {
    let len = tail.len();
    // Safety: boolean, one flag set, at index `len`.
    let end: [Field; S + 1] = unsafe { one_hot(len) };
    let mut count = 0;
    let mut at = 0;
    for j in 0..S + 1 {
        assert_eq(end[j] * end[j], end[j]);
        count += end[j];
        at += end[j] * j as Field;
    }
    assert_eq(count, 1);
    assert_eq(at, len as Field);

    let mut bytes = [0; ((P + S + 72) / 64) * 64];
    for i in 0..P {
        bytes[i] = head[i] as Field;
    }
    let storage = tail.storage();
    // Past the end once the flag at or before j is set.
    let mut ended = 0;
    for j in 0..S {
        ended += end[j];
        std::as_witness(ended);
        bytes[P + j] = storage[j] as Field * (1 - ended) + 0x80 * end[j];
    }
    bytes[P + S] = 0x80 * end[S];
    let mut words: [Field; ((P + S + 72) / 64) * 16] = to_words(bytes);
    let bit_len = 8 * (P as Field + len as Field);

    let mut state = initial_state();
    let mut out = [0; 5];
    for k in 0..(P + S + 72) / 64 - 1 {
        let last = ends_in::<P, S>(end, k);
        words[16 * k + 15] += last * bit_len;
        state = compress(state, block_of(words, k)).next();
        let h = chaining(state);
        for i in 0..5 {
            std::as_witness(h[i]);
            out[i] += last * h[i];
        }
    }
    let k = (P + S + 72) / 64 - 1;
    let last = ends_in::<P, S>(end, k);
    words[16 * k + 15] += last * bit_len;
    let h = compress(state, block_of(words, k)).digest();
    for i in 0..5 {
        out[i] += last * h[i];
    }
    out
}

fn to_bytes(words: [Field; 5]) -> [u8; 20] {
    let mut out = [0; 20];
    for k in 0..5 {
        let b: [u8; 4] = words[k].to_be_bytes();
        for i in 0..4 {
            out[4 * k + i] = b[i];
        }
    }
    out
}

pub fn digest<let N: u32>(msg: [u8; N]) -> [u8; 20] {
    to_bytes(digest_words(msg))
}

pub fn digest_var<let N: u32>(msg: BoundedVec<u8, N>) -> [u8; 20] {
    to_bytes(digest_words_var::<0, N>([], msg))
}
