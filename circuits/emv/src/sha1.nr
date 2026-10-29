//! SHA-1 (FIPS 180-4), laid out for ProveKit's R1CS.
//!
//! Boolean functions work on spread words, bit i moved to bit `SPREAD_STRIDE * i`. Adding two or
//! three spreads and splitting the sum as `spread(x) + 2 spread(y)` gives x = XOR and y = AND or MAJ
//! per bit; the sum stays below 4^32, so the split is unique. Each chunk is a read of a constant
//! table, which bounds the chunk and returns its spread in one lookup. State words are cut where
//! ROTL30 and ROTL5 wrap, and schedule words below their top bit, so every rotation is linear in the
//! chunks. One Brillig call per block supplies every chunk.
//!
//! An optimization over baseline Noir implementation of SHA1 https://github.com/zac-williamson/sha1.

use crate::bytes::{bit_length, BITS_PER_BYTE, BYTE_BASE, BYTE_TOP_BIT_VALUE, pow2};

pub global WORD_BIT_LEN: u32 = 32;
pub global WORD_BYTE_LEN: u32 = WORD_BIT_LEN / BITS_PER_BYTE;
global WORD_BASE: Field = pow2(WORD_BIT_LEN);
pub global DIGEST_WORD_COUNT: u32 = 5;
pub global DIGEST_BYTE_LEN: u32 = DIGEST_WORD_COUNT * WORD_BYTE_LEN;

global BLOCK_WORD_COUNT: u32 = 16;
global BLOCK_BYTE_LEN: u32 = BLOCK_WORD_COUNT * WORD_BYTE_LEN;
global LAST_BLOCK_WORD_INDEX: u32 = BLOCK_WORD_COUNT - 1;
global PAD_MARKER: Field = BYTE_TOP_BIT_VALUE;
global PAD_MARKER_BYTE_LEN: u32 = 1;
global LENGTH_BYTE_LEN: u32 = 8;
global PADDING_MIN_BYTE_LEN: u32 = PAD_MARKER_BYTE_LEN + LENGTH_BYTE_LEN;

global ROUND_COUNT: u32 = 80;
global LAST_ROUND: u32 = ROUND_COUNT - 1;
global ROUNDS_PER_STAGE: u32 = 20;
global CH_STAGE: u32 = 0;
global MAJ_STAGE: u32 = 2;
global LAST_STAGE: u32 = ROUND_COUNT / ROUNDS_PER_STAGE - 1;
global CH_ROUND_END: u32 = (CH_STAGE + 1) * ROUNDS_PER_STAGE;
global MAJ_ROUND_START: u32 = MAJ_STAGE * ROUNDS_PER_STAGE;
global MAJ_ROUND_END: u32 = MAJ_ROUND_START + ROUNDS_PER_STAGE;

global SCHEDULE_ROUND_COUNT: u32 = ROUND_COUNT - BLOCK_WORD_COUNT;
global SCHEDULE_XOR_LAGS: [u32; 3] = [3, 8, 14];
global SCHEDULE_LAST_LAG: u32 = BLOCK_WORD_COUNT;

global A_ROTATION: u32 = 5;
global B_ROTATION: u32 = 30;
global SCHEDULE_ROTATION: u32 = 1;

/// The registers a to e, by position in the chaining value; round t reads register X from
/// `history[t + HISTORY_X]` and writes `history[t + REGISTER_COUNT]`.
global REGISTER_COUNT: u32 = DIGEST_WORD_COUNT;
global CHAIN_A: u32 = 0;
global CHAIN_B: u32 = CHAIN_A + 1;
global CHAIN_C: u32 = CHAIN_B + 1;
global CHAIN_E: u32 = REGISTER_COUNT - 1;
global HISTORY_A: u32 = REGISTER_COUNT - 1 - CHAIN_A;
global HISTORY_B: u32 = REGISTER_COUNT - 1 - CHAIN_B;
global HISTORY_C: u32 = REGISTER_COUNT - 1 - CHAIN_C;
global HISTORY_D: u32 = HISTORY_C - 1;
global HISTORY_E: u32 = REGISTER_COUNT - 1 - CHAIN_E;
/// A_78 is only rotated and added and A_79 only added, so neither is cut into chunks: a table read
/// whose result goes unused is replaced by a costlier bounds check.
global UNCUT_FINAL_ROUND_COUNT: u32 = 2;
global CUT_ROUND_COUNT: u32 = ROUND_COUNT - UNCUT_FINAL_ROUND_COUNT;
global CARRIED_ROUND_COUNT: u32 = LAST_ROUND;
global HISTORY_LEN: u32 = CUT_ROUND_COUNT + REGISTER_COUNT;
/// a and b enter as words; c and d pre-rotated, since round 0 reads them rotated by 30; e is only added.
global CHUNKED_STATE_WORD_COUNT: u32 = CHAIN_E;
global FIRST_PRE_ROTATED_STATE_WORD: u32 = CHAIN_C;

global ROUND_SUM_TERM_COUNT: u64 = 5;
global ROUND_CARRY_BIT_LEN: u32 = bit_length(ROUND_SUM_TERM_COUNT - 1);
global CHAINING_SUM_CARRY_BIT_LEN: u32 = bit_length(ROUND_SUM_TERM_COUNT);

global SPREAD_STRIDE: u32 = 2;
global SPREAD_HIGH_BIT_WEIGHT: Field = pow2(SPREAD_STRIDE - 1);
global SPREAD_ONES: Field = spread_ones();

global CHUNK_BIT_LEN: u32 = 11;
global CHUNK_TABLE_LEN: u32 = 1 << CHUNK_BIT_LEN;

global ROTL30_CUT: u32 = WORD_BIT_LEN - B_ROTATION;
global ROTL5_CUT: u32 = WORD_BIT_LEN - A_ROTATION;
global STATE_CHUNK_COUNT: u32 = 5;
global LOW_CHUNK_OFFSET: u32 = 0;
global MID1_CHUNK_OFFSET: u32 = ROTL30_CUT;
global MID2_CHUNK_OFFSET: u32 = MID1_CHUNK_OFFSET + CHUNK_BIT_LEN;
global UPPER_CHUNK_OFFSET: u32 = MID2_CHUNK_OFFSET + CHUNK_BIT_LEN;
global TOP_CHUNK_OFFSET: u32 = ROTL5_CUT;
global STATE_CHUNK_OFFSETS: [u32; STATE_CHUNK_COUNT] = [LOW_CHUNK_OFFSET, MID1_CHUNK_OFFSET, MID2_CHUNK_OFFSET, UPPER_CHUNK_OFFSET, TOP_CHUNK_OFFSET];
global LOW_CHUNK_BIT_LEN: u32 = MID1_CHUNK_OFFSET - LOW_CHUNK_OFFSET;
global UPPER_CHUNK_BIT_LEN: u32 = TOP_CHUNK_OFFSET - UPPER_CHUNK_OFFSET;
global TOP_CHUNK_BIT_LEN: u32 = WORD_BIT_LEN - TOP_CHUNK_OFFSET;
global STATE_CHUNK_BIT_LENS: [u32; STATE_CHUNK_COUNT] = [LOW_CHUNK_BIT_LEN, CHUNK_BIT_LEN, CHUNK_BIT_LEN, UPPER_CHUNK_BIT_LEN, TOP_CHUNK_BIT_LEN];
global LOW_TABLE_LEN: u32 = 1 << LOW_CHUNK_BIT_LEN;
global UPPER_TABLE_LEN: u32 = 1 << UPPER_CHUNK_BIT_LEN;
global TOP_TABLE_LEN: u32 = 1 << TOP_CHUNK_BIT_LEN;

global SCHEDULE_CHUNK_COUNT: u32 = (WORD_BIT_LEN + CHUNK_BIT_LEN - 1) / CHUNK_BIT_LEN;
global SCHEDULE_TOP_CHUNK_INDEX: u32 = SCHEDULE_CHUNK_COUNT - 1;
global SCHEDULE_TOP_CHUNK_OFFSET: u32 = SCHEDULE_TOP_CHUNK_INDEX * CHUNK_BIT_LEN;
/// The schedule's pre-rotation word below its top bit, which ROTL1 moves to bit 0.
global X2_TOP_BIT_INDEX: u32 = WORD_BIT_LEN - SCHEDULE_ROTATION;
global X2_TOP_CHUNK_BIT_LEN: u32 = X2_TOP_BIT_INDEX - SCHEDULE_TOP_CHUNK_OFFSET;
global X2_TOP_BIT_SPREAD: Field = pow2(SPREAD_STRIDE * X2_TOP_BIT_INDEX);
global ROTL1_WEIGHT: Field = pow2(SCHEDULE_ROTATION);
global ROTL5_WEIGHT: Field = pow2(A_ROTATION);
global TOP_CHUNK_WEIGHT: Field = pow2(TOP_CHUNK_OFFSET);
global SPREAD_ROTL1_WEIGHT: Field = pow2(SPREAD_STRIDE * SCHEDULE_ROTATION);

global SPREAD_CHUNK_TABLE: [Field; CHUNK_TABLE_LEN] = spread_table();
global SPREAD_LOW_TABLE: [Field; LOW_TABLE_LEN] = spread_table();
global SPREAD_UPPER_TABLE: [Field; UPPER_TABLE_LEN] = spread_table();
global SPREAD_TOP_TABLE: [Field; TOP_TABLE_LEN] = spread_table();

global RAW_WEIGHTS: [Field; STATE_CHUNK_COUNT] = state_weights(0, 1);
global ROTL5_WEIGHTS: [Field; STATE_CHUNK_COUNT] = state_weights(A_ROTATION, 1);
global ROTL30_WEIGHTS: [Field; STATE_CHUNK_COUNT] = state_weights(B_ROTATION, 1);
global SPREAD_WEIGHTS: [Field; STATE_CHUNK_COUNT] = state_weights(0, SPREAD_STRIDE);
global SPREAD_ROTL30_WEIGHTS: [Field; STATE_CHUNK_COUNT] = state_weights(B_ROTATION, SPREAD_STRIDE);
global SCHEDULE_RAW_WEIGHTS: [Field; SCHEDULE_CHUNK_COUNT] = schedule_weights(1);
global SCHEDULE_SPREAD_WEIGHTS: [Field; SCHEDULE_CHUNK_COUNT] = schedule_weights(SPREAD_STRIDE);

global INITIAL_HASH: [u32; DIGEST_WORD_COUNT] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
global ROUND_CONSTANTS: [Field; ROUND_COUNT / ROUNDS_PER_STAGE] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
global INITIAL_STATE_CHUNKS: [[u32; STATE_CHUNK_COUNT]; CHUNKED_STATE_WORD_COUNT] = initial_state_chunks();

fn spread_table<let L: u32>() -> [Field; L] {
    let mut table = [0; L];
    for i in 0..L {
        let mut s = 0;
        for b in 0..CHUNK_BIT_LEN {
            if ((i >> b) & 1) == 1 {
                s += pow2(SPREAD_STRIDE * b);
            }
        }
        table[i] = s;
    }
    table
}

fn spread_ones() -> Field {
    let mut s = 0;
    for b in 0..WORD_BIT_LEN {
        s += pow2(SPREAD_STRIDE * b);
    }
    s
}

/// The weight of each state chunk in the word rotated left by `rotation`, spread by `stride`.
fn state_weights(rotation: u32, stride: u32) -> [Field; STATE_CHUNK_COUNT] {
    let mut weights = [0; STATE_CHUNK_COUNT];
    for i in 0..STATE_CHUNK_COUNT {
        weights[i] = pow2(
            stride * ((STATE_CHUNK_OFFSETS[i] + rotation) % WORD_BIT_LEN),
        );
    }
    weights
}

fn schedule_weights(stride: u32) -> [Field; SCHEDULE_CHUNK_COUNT] {
    let mut weights = [0; SCHEDULE_CHUNK_COUNT];
    for i in 0..SCHEDULE_CHUNK_COUNT {
        weights[i] = pow2(stride * i * CHUNK_BIT_LEN);
    }
    weights
}

fn weighted<let N: u32>(values: [Field; N], weights: [Field; N]) -> Field {
    let mut sum = 0;
    for i in 0..N {
        sum += values[i] * weights[i];
    }
    sum
}

/// A state word in chunks at `STATE_CHUNK_OFFSETS`, with their spreads.
struct Word {
    c: [Field; STATE_CHUNK_COUNT],
    s: [Field; STATE_CHUNK_COUNT],
}

impl Word {
    fn new(c: [u32; STATE_CHUNK_COUNT]) -> Self {
        Word {
            c: c.map(|x: u32| x as Field),
            s: [SPREAD_LOW_TABLE[c[0]], SPREAD_CHUNK_TABLE[c[1]], SPREAD_CHUNK_TABLE[c[2]], SPREAD_UPPER_TABLE[c[3]], SPREAD_TOP_TABLE[c[4]]],
        }
    }

    fn raw(self) -> Field {
        weighted(self.c, RAW_WEIGHTS)
    }

    fn rotl5(self) -> Field {
        weighted(self.c, ROTL5_WEIGHTS)
    }

    fn rotl30(self) -> Field {
        weighted(self.c, ROTL30_WEIGHTS)
    }

    fn spread(self) -> Field {
        weighted(self.s, SPREAD_WEIGHTS)
    }

    fn spread_rotl30(self) -> Field {
        weighted(self.s, SPREAD_ROTL30_WEIGHTS)
    }
}

fn bits(x: u32, offset: u32, bit_len: u32) -> u32 {
    (x >> offset) & ((1 << bit_len) - 1)
}

fn cut(x: u32) -> [u32; STATE_CHUNK_COUNT] {
    let mut chunks = [0; STATE_CHUNK_COUNT];
    for i in 0..STATE_CHUNK_COUNT {
        chunks[i] = bits(x, STATE_CHUNK_OFFSETS[i], STATE_CHUNK_BIT_LENS[i]);
    }
    chunks
}

fn cut_schedule(x: u32) -> [u32; SCHEDULE_CHUNK_COUNT] {
    let mut chunks = [0; SCHEDULE_CHUNK_COUNT];
    for i in 0..SCHEDULE_CHUNK_COUNT {
        chunks[i] = bits(x, i * CHUNK_BIT_LEN, CHUNK_BIT_LEN);
    }
    chunks
}

fn rotl(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (WORD_BIT_LEN - n))
}

fn schedule_raw(c: [u32; SCHEDULE_CHUNK_COUNT]) -> Field {
    weighted(c.map(|x: u32| x as Field), SCHEDULE_RAW_WEIGHTS)
}

fn schedule_spread(c: [u32; SCHEDULE_CHUNK_COUNT]) -> Field {
    weighted(
        c.map(|x: u32| SPREAD_CHUNK_TABLE[x]),
        SCHEDULE_SPREAD_WEIGHTS,
    )
}

/// Asserts `sum = spread(x) + 2 spread(y)` for a sum of at most three spreads, and returns
/// spread(x).
fn split(sum: Field, x: [u32; SCHEDULE_CHUNK_COUNT], y: [u32; SCHEDULE_CHUNK_COUNT]) -> Field {
    let sx = schedule_spread(x);
    assert_eq(sum, sx + SPREAD_HIGH_BIT_WEIGHT * schedule_spread(y));
    sx
}

/// What a block's rounds read of the chaining value: H0 to H3 as words, H2 and H3 pre-rotated, and
/// H4, which is only added.
struct State {
    w: [Word; CHUNKED_STATE_WORD_COUNT],
    e: Field,
}

fn initial_state_chunks() -> [[u32; STATE_CHUNK_COUNT]; CHUNKED_STATE_WORD_COUNT] {
    let mut chunks = [[0; STATE_CHUNK_COUNT]; CHUNKED_STATE_WORD_COUNT];
    for k in 0..CHUNKED_STATE_WORD_COUNT {
        chunks[k] = if k < FIRST_PRE_ROTATED_STATE_WORD {
            cut(INITIAL_HASH[k])
        } else {
            cut(rotl(INITIAL_HASH[k], ROTL30_CUT))
        };
    }
    chunks
}

fn chaining(state: State) -> [Field; DIGEST_WORD_COUNT] {
    let mut h = [0; DIGEST_WORD_COUNT];
    for k in 0..CHUNKED_STATE_WORD_COUNT {
        h[k] = if k < FIRST_PRE_ROTATED_STATE_WORD {
            state.w[k].raw()
        } else {
            state.w[k].rotl30()
        };
    }
    h[CHAIN_E] = state.e;
    h
}

fn initial_state() -> State {
    let mut w = [Word { c: [0; STATE_CHUNK_COUNT], s: [0; STATE_CHUNK_COUNT] }; CHUNKED_STATE_WORD_COUNT];
    for k in 0..CHUNKED_STATE_WORD_COUNT {
        w[k] = Word::new(INITIAL_STATE_CHUNKS[k]);
    }
    State { w, e: INITIAL_HASH[CHAIN_E] as Field }
}

/// A word cut at `ROTL5_CUT`.
struct Halves {
    low: Field,
    high: Field,
}

struct Hints {
    msg: [[u32; SCHEDULE_CHUNK_COUNT]; BLOCK_WORD_COUNT],
    // Schedule, from round BLOCK_WORD_COUNT: x1 = XOR of the first three lagged words, x2 = x1 XOR
    // the last, w[t] = ROTL1(x2).
    x1: [[u32; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
    y1: [[u32; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
    // x2 below its top bit, and the top bit.
    x2: [[u32; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
    x2_top: [Field; SCHEDULE_ROUND_COUNT],
    y2: [[u32; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
    // Rounds: the split of b + c (+ d), and for Ch also of ~b + d.
    fx: [[u32; SCHEDULE_CHUNK_COUNT]; ROUND_COUNT],
    fy: [[u32; SCHEDULE_CHUNK_COUNT]; ROUND_COUNT],
    gx: [[u32; SCHEDULE_CHUNK_COUNT]; CH_ROUND_END],
    gy: [[u32; SCHEDULE_CHUNK_COUNT]; CH_ROUND_END],
    a: [[u32; STATE_CHUNK_COUNT]; CUT_ROUND_COUNT],
    a_first_uncut: Halves,
    carry: [Field; CARRIED_ROUND_COUNT],
    out_carry: [Field; DIGEST_WORD_COUNT],
}

unconstrained fn block_hints(h: [Field; DIGEST_WORD_COUNT], block: [Field; BLOCK_WORD_COUNT]) -> Hints {
    let mut hint = Hints {
        msg: [[0; SCHEDULE_CHUNK_COUNT]; BLOCK_WORD_COUNT],
        x1: [[0; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
        y1: [[0; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
        x2: [[0; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
        x2_top: [0; SCHEDULE_ROUND_COUNT],
        y2: [[0; SCHEDULE_CHUNK_COUNT]; SCHEDULE_ROUND_COUNT],
        fx: [[0; SCHEDULE_CHUNK_COUNT]; ROUND_COUNT],
        fy: [[0; SCHEDULE_CHUNK_COUNT]; ROUND_COUNT],
        gx: [[0; SCHEDULE_CHUNK_COUNT]; CH_ROUND_END],
        gy: [[0; SCHEDULE_CHUNK_COUNT]; CH_ROUND_END],
        a: [[0; STATE_CHUNK_COUNT]; CUT_ROUND_COUNT],
        a_first_uncut: Halves { low: 0, high: 0 },
        carry: [0; CARRIED_ROUND_COUNT],
        out_carry: [0; DIGEST_WORD_COUNT],
    };

    let mut w: [u32; ROUND_COUNT] = [0; ROUND_COUNT];
    for t in 0..BLOCK_WORD_COUNT {
        w[t] = block[t] as u32;
        hint.msg[t] = cut_schedule(w[t]);
    }
    for t in BLOCK_WORD_COUNT..ROUND_COUNT {
        let s = t - BLOCK_WORD_COUNT;
        let lagged = SCHEDULE_XOR_LAGS.map(|lag| w[t - lag]);
        let (p, q, r) = (lagged[0], lagged[1], lagged[2]);
        let last = w[t - SCHEDULE_LAST_LAG];
        let x1 = p ^ q ^ r;
        hint.x1[s] = cut_schedule(x1);
        hint.y1[s] = cut_schedule((p & q) | (p & r) | (q & r));
        let x2 = x1 ^ last;
        let mut below_top = cut_schedule(x2);
        below_top[SCHEDULE_TOP_CHUNK_INDEX] = bits(x2, SCHEDULE_TOP_CHUNK_OFFSET, X2_TOP_CHUNK_BIT_LEN);
        hint.x2[s] = below_top;
        hint.x2_top[s] = (x2 >> X2_TOP_BIT_INDEX) as Field;
        hint.y2[s] = cut_schedule(x1 & last);
        w[t] = rotl(x2, SCHEDULE_ROTATION);
    }

    let h: [u32; DIGEST_WORD_COUNT] = h.map(|v: Field| v as u32);
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    let mut last_temp: u64 = 0;
    for t in 0..ROUND_COUNT {
        let f = if t < CH_ROUND_END {
            hint.fx[t] = cut_schedule(b ^ c);
            hint.fy[t] = cut_schedule(b & c);
            hint.gx[t] = cut_schedule(!b ^ d);
            hint.gy[t] = cut_schedule(!b & d);
            (b & c) | (!b & d)
        } else {
            let parity = b ^ c ^ d;
            let maj = (b & c) | (b & d) | (c & d);
            hint.fx[t] = cut_schedule(parity);
            hint.fy[t] = cut_schedule(maj);
            if (t >= MAJ_ROUND_START) & (t < MAJ_ROUND_END) {
                maj
            } else {
                parity
            }
        };
        let k = ROUND_CONSTANTS[t / ROUNDS_PER_STAGE] as u32;
        let temp = rotl(a, A_ROTATION) as u64 + f as u64 + e as u64 + k as u64 + w[t] as u64;
        let next = temp as u32;
        if t < CUT_ROUND_COUNT {
            hint.a[t] = cut(next);
        } else if t == CUT_ROUND_COUNT {
            hint.a_first_uncut = Halves { low: bits(next, 0, ROTL5_CUT) as Field, high: (next >> ROTL5_CUT) as Field };
        } else {
            last_temp = temp;
        }
        if t < CARRIED_ROUND_COUNT {
            hint.carry[t] = (temp >> WORD_BIT_LEN as u64) as Field;
        }
        e = d;
        d = c;
        c = rotl(b, B_ROTATION);
        b = a;
        a = next;
    }

    let sums = [h[0] as u64 + last_temp, h[1] as u64 + b as u64, h[2] as u64 + c as u64, h[3] as u64 + d as u64, h[4] as u64 + e as u64];
    for k in 0..DIGEST_WORD_COUNT {
        hint.out_carry[k] = (sums[k] >> WORD_BIT_LEN as u64) as Field;
    }
    hint
}

/// Chunks of the next block's State words. Separate from `block_hints`: a Brillig output that is
/// never used as a table index is range-checked, and the last block has no next state.
unconstrained fn next_hints(sums: [Field; DIGEST_WORD_COUNT]) -> [[u32; STATE_CHUNK_COUNT]; CHUNKED_STATE_WORD_COUNT] {
    let mut out = [[0; STATE_CHUNK_COUNT]; CHUNKED_STATE_WORD_COUNT];
    for k in 0..CHUNKED_STATE_WORD_COUNT {
        let v = sums[k] as u64 as u32;
        out[k] = if k < FIRST_PRE_ROTATED_STATE_WORD {
            cut(v)
        } else {
            cut(rotl(v, ROTL30_CUT))
        };
    }
    out
}

/// The chaining sums of a compression, before reduction mod 2^32.
struct Chained {
    sums: [Field; DIGEST_WORD_COUNT],
    carry: [Field; DIGEST_WORD_COUNT],
}

impl Chained {
    fn assert_carries(self) {
        // sums[0] adds H0 to an unreduced round sum.
        self.carry[CHAIN_A].assert_max_bit_size::<CHAINING_SUM_CARRY_BIT_LEN>();
        for k in CHAIN_B..DIGEST_WORD_COUNT {
            assert_eq(self.carry[k] * self.carry[k], self.carry[k]);
        }
    }

    /// The state for another block.
    fn next(self) -> State {
        self.assert_carries();
        // Safety: each word is tied to its sum below.
        let out = unsafe { next_hints(self.sums) };
        let mut w = [Word { c: [0; STATE_CHUNK_COUNT], s: [0; STATE_CHUNK_COUNT] }; CHUNKED_STATE_WORD_COUNT];
        for k in 0..CHUNKED_STATE_WORD_COUNT {
            let word = Word::new(out[k]);
            let v = if k < FIRST_PRE_ROTATED_STATE_WORD {
                word.raw()
            } else {
                word.rotl30()
            };
            assert_eq(v + self.carry[k] * WORD_BASE, self.sums[k]);
            w[k] = word;
        }
        let e = self.sums[CHAIN_E] - self.carry[CHAIN_E] * WORD_BASE;
        e.assert_max_bit_size::<WORD_BIT_LEN>();
        State { w, e }
    }

    /// The hash, when this was the last block.
    fn digest(self) -> [Field; DIGEST_WORD_COUNT] {
        self.assert_carries();
        let mut out = [0; DIGEST_WORD_COUNT];
        for k in 0..DIGEST_WORD_COUNT {
            out[k] = self.sums[k] - self.carry[k] * WORD_BASE;
            out[k].assert_max_bit_size::<WORD_BIT_LEN>();
        }
        out
    }
}

/// One compression. `block` holds words each already known to be below 2^32. `history[j]` is
/// A_{j - REGISTER_COUNT}, the output of round j - REGISTER_COUNT (e from H4 in round 0).
fn compress(state: State, block: [Field; BLOCK_WORD_COUNT]) -> Chained {
    let h = chaining(state);
    // Safety: chunks are bounded by their table reads and tied to the words by the asserts below;
    // carries, A_78's halves and the top schedule bit are range-checked.
    let hint = unsafe { block_hints(h, block) };

    let mut w: [Field; ROUND_COUNT] = [0; ROUND_COUNT];
    let mut sw: [Field; ROUND_COUNT] = [0; ROUND_COUNT];
    for t in 0..BLOCK_WORD_COUNT {
        assert_eq(schedule_raw(hint.msg[t]), block[t]);
        w[t] = block[t];
        sw[t] = schedule_spread(hint.msg[t]);
    }
    for t in BLOCK_WORD_COUNT..ROUND_COUNT {
        let s = t - BLOCK_WORD_COUNT;
        let mut lagged = 0;
        for lag in SCHEDULE_XOR_LAGS {
            lagged += sw[t - lag];
        }
        let x1 = split(lagged, hint.x1[s], hint.y1[s]);
        let below_top = hint.x2[s];
        let top = hint.x2_top[s];
        // The top chunk sits below the top bit, so it must be exact for ROTL1 to be sound.
        (below_top[SCHEDULE_TOP_CHUNK_INDEX] as Field).assert_max_bit_size::<X2_TOP_CHUNK_BIT_LEN>();
        assert_eq(top * top, top);
        let below_top_spread = schedule_spread(below_top);
        assert_eq(x1 + sw[t - SCHEDULE_LAST_LAG], below_top_spread + top * X2_TOP_BIT_SPREAD + SPREAD_HIGH_BIT_WEIGHT * schedule_spread(hint.y2[s]));
        w[t] = ROTL1_WEIGHT * schedule_raw(below_top) + top;
        sw[t] = SPREAD_ROTL1_WEIGHT * below_top_spread + top;
    }

    let mut history = [Word { c: [0; STATE_CHUNK_COUNT], s: [0; STATE_CHUNK_COUNT] }; HISTORY_LEN];
    for k in 0..CHUNKED_STATE_WORD_COUNT {
        history[HISTORY_A - k] = state.w[k];
    }
    let mut a5 = state.w[CHAIN_A].rotl5();
    for t in 0..CH_ROUND_END {
        let b = history[t + HISTORY_B].spread();
        let _ = split(
            b + history[t + HISTORY_C].spread_rotl30(),
            hint.fx[t],
            hint.fy[t],
        );
        let _ = split(
            SPREAD_ONES - b + history[t + HISTORY_D].spread_rotl30(),
            hint.gx[t],
            hint.gy[t],
        );
        let f = schedule_raw(hint.fy[t]) + schedule_raw(hint.gy[t]);
        let e = if t == 0 {
            state.e
        } else {
            history[t + HISTORY_E].rotl30()
        };
        history[t + REGISTER_COUNT] = reduce(
            a5 + f + e + ROUND_CONSTANTS[CH_STAGE] + w[t],
            hint.a[t],
            hint.carry[t],
        );
        a5 = history[t + REGISTER_COUNT].rotl5();
    }
    for t in CH_ROUND_END..CUT_ROUND_COUNT {
        let f = parity_or_maj(history, t, hint);
        history[t + REGISTER_COUNT] = reduce(
            a5 + f + history[t + HISTORY_E].rotl30() + ROUND_CONSTANTS[t / ROUNDS_PER_STAGE] + w[t],
            hint.a[t],
            hint.carry[t],
        );
        a5 = history[t + REGISTER_COUNT].rotl5();
    }

    let first_uncut = CUT_ROUND_COUNT;
    let Halves { low, high } = hint.a_first_uncut;
    low.assert_max_bit_size::<ROTL5_CUT>();
    high.assert_max_bit_size::<TOP_CHUNK_BIT_LEN>();
    hint.carry[first_uncut].assert_max_bit_size::<ROUND_CARRY_BIT_LEN>();
    let raw_first_uncut = low + high * TOP_CHUNK_WEIGHT;
    let temp = a5 + parity_or_maj(history, first_uncut, hint) + history[first_uncut + HISTORY_E].rotl30() + ROUND_CONSTANTS[LAST_STAGE] + w[first_uncut];
    assert_eq(raw_first_uncut + hint.carry[first_uncut] * WORD_BASE, temp);
    let rotl5_first_uncut = low * ROTL5_WEIGHT + high;
    let last_temp =
        rotl5_first_uncut + parity_or_maj(history, LAST_ROUND, hint) + history[LAST_ROUND + HISTORY_E].rotl30() + ROUND_CONSTANTS[LAST_STAGE] + w[LAST_ROUND];

    // After the last round, register k (from c on) holds A_{LAST_ROUND - k}, rotated.
    let mut sums = [0; DIGEST_WORD_COUNT];
    sums[CHAIN_A] = h[CHAIN_A] + last_temp;
    sums[CHAIN_B] = h[CHAIN_B] + raw_first_uncut;
    for k in CHAIN_C..DIGEST_WORD_COUNT {
        sums[k] = h[k] + history[LAST_ROUND - k + REGISTER_COUNT].rotl30();
    }
    Chained { sums, carry: hint.out_carry }
}

/// f for the rounds after Ch: MAJ in its stage, XOR otherwise.
fn parity_or_maj(history: [Word; HISTORY_LEN], t: u32, hint: Hints) -> Field {
    let sum = history[t + HISTORY_B].spread() + history[t + HISTORY_C].spread_rotl30() + history[t + HISTORY_D].spread_rotl30();
    let _ = split(sum, hint.fx[t], hint.fy[t]);
    if (t >= MAJ_ROUND_START) & (t < MAJ_ROUND_END) {
        schedule_raw(hint.fy[t])
    } else {
        schedule_raw(hint.fx[t])
    }
}

/// The word `temp mod 2^32`, for a `temp` of at most `ROUND_SUM_TERM_COUNT` words.
fn reduce(temp: Field, a: [u32; STATE_CHUNK_COUNT], carry: Field) -> Word {
    let word = Word::new(a);
    carry.assert_max_bit_size::<ROUND_CARRY_BIT_LEN>();
    assert_eq(word.raw() + carry * WORD_BASE, temp);
    word
}

/// Big-endian words of `bytes`, whose bytes are all below 256.
fn to_words<let W: u32>(bytes: [Field; WORD_BYTE_LEN * W]) -> [Field; W] {
    let mut words = [0; W];
    for q in 0..W {
        let mut word = 0;
        for i in 0..WORD_BYTE_LEN {
            word = word * BYTE_BASE + bytes[WORD_BYTE_LEN * q + i];
        }
        words[q] = word;
    }
    words
}

fn block_of<let W: u32>(words: [Field; W], k: u32) -> [Field; BLOCK_WORD_COUNT] {
    let mut block = [0; BLOCK_WORD_COUNT];
    for i in 0..BLOCK_WORD_COUNT {
        block[i] = words[BLOCK_WORD_COUNT * k + i];
    }
    block
}

/// SHA-1 of `msg` as big-endian words, each below 2^32.
pub fn digest_words<let N: u32>(msg: [u8; N]) -> [Field; DIGEST_WORD_COUNT] {
    let mut bytes = [0; ((N + PADDING_MIN_BYTE_LEN + BLOCK_BYTE_LEN - 1) / BLOCK_BYTE_LEN) * BLOCK_BYTE_LEN];
    for i in 0..N {
        bytes[i] = msg[i] as Field;
    }
    bytes[N] = PAD_MARKER;
    let mut words: [Field; ((N + PADDING_MIN_BYTE_LEN + BLOCK_BYTE_LEN - 1) / BLOCK_BYTE_LEN) * BLOCK_WORD_COUNT] = to_words(bytes);
    let block_count = (N + PADDING_MIN_BYTE_LEN + BLOCK_BYTE_LEN - 1) / BLOCK_BYTE_LEN;
    words[BLOCK_WORD_COUNT * (block_count - 1) + LAST_BLOCK_WORD_INDEX] = (BITS_PER_BYTE * N) as Field;

    let mut state = initial_state();
    for k in 0..block_count - 1 {
        state = compress(state, block_of(words, k)).next();
    }
    compress(state, block_of(words, block_count - 1)).digest()
}

unconstrained fn one_hot<let L: u32>(i: u32) -> [Field; L] {
    let mut flags = [0; L];
    flags[i] = 1;
    flags
}

/// 1 if the message, `P` bytes plus the tail length flagged in `end`, ends in block `k`: its
/// length field then starts in that block.
fn ends_in<let P: u32, let S: u32>(end: [Field; S + 1], k: u32) -> Field {
    let mut last = 0;
    for j in 0..S + 1 {
        let length_field_end = P + j + LENGTH_BYTE_LEN;
        if (length_field_end >= BLOCK_BYTE_LEN * k) & (length_field_end < BLOCK_BYTE_LEN * (k + 1)) {
            last += end[j];
        }
    }
    std::as_witness(last);
    last
}

/// SHA-1 of `head || tail` as big-endian words. Every block the tail can reach is compressed; the
/// output is selected from the blocks the message can end in.
pub fn digest_words_var<let P: u32, let S: u32>(head: [u8; P], tail: BoundedVec<u8, S>) -> [Field; DIGEST_WORD_COUNT] {
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

    let mut bytes = [0; ((P + S + PADDING_MIN_BYTE_LEN + BLOCK_BYTE_LEN - 1) / BLOCK_BYTE_LEN) * BLOCK_BYTE_LEN];
    for i in 0..P {
        bytes[i] = head[i] as Field;
    }
    let storage = tail.storage();
    // Past the end once the flag at or before j is set.
    let mut ended = 0;
    for j in 0..S {
        ended += end[j];
        std::as_witness(ended);
        bytes[P + j] = storage[j] as Field * (1 - ended) + PAD_MARKER * end[j];
    }
    bytes[P + S] = PAD_MARKER * end[S];
    let mut words: [Field; ((P + S + PADDING_MIN_BYTE_LEN + BLOCK_BYTE_LEN - 1) / BLOCK_BYTE_LEN) * BLOCK_WORD_COUNT] = to_words(bytes);
    let bit_len = BITS_PER_BYTE as Field * (P as Field + len as Field);
    let block_count = (P + S + PADDING_MIN_BYTE_LEN + BLOCK_BYTE_LEN - 1) / BLOCK_BYTE_LEN;

    let mut state = initial_state();
    let mut out = [0; DIGEST_WORD_COUNT];
    for k in 0..block_count - 1 {
        let last = ends_in::<P, S>(end, k);
        words[BLOCK_WORD_COUNT * k + LAST_BLOCK_WORD_INDEX] += last * bit_len;
        state = compress(state, block_of(words, k)).next();
        let h = chaining(state);
        for i in 0..DIGEST_WORD_COUNT {
            std::as_witness(h[i]);
            out[i] += last * h[i];
        }
    }
    let k = block_count - 1;
    let last = ends_in::<P, S>(end, k);
    words[BLOCK_WORD_COUNT * k + LAST_BLOCK_WORD_INDEX] += last * bit_len;
    let h = compress(state, block_of(words, k)).digest();
    for i in 0..DIGEST_WORD_COUNT {
        out[i] += last * h[i];
    }
    out
}

fn to_bytes(words: [Field; DIGEST_WORD_COUNT]) -> [u8; DIGEST_BYTE_LEN] {
    let mut out = [0; DIGEST_BYTE_LEN];
    for k in 0..DIGEST_WORD_COUNT {
        let b: [u8; WORD_BYTE_LEN] = words[k].to_be_bytes();
        for i in 0..WORD_BYTE_LEN {
            out[WORD_BYTE_LEN * k + i] = b[i];
        }
    }
    out
}

pub fn digest<let N: u32>(msg: [u8; N]) -> [u8; DIGEST_BYTE_LEN] {
    to_bytes(digest_words(msg))
}

pub fn digest_var<let N: u32>(msg: BoundedVec<u8, N>) -> [u8; DIGEST_BYTE_LEN] {
    to_bytes(digest_words_var::<0, N>([], msg))
}
