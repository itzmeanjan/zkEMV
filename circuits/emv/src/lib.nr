//! EMV Book 2 offline data authentication:
//! CA key -> issuer cert `90` -> ICC cert `9F46` -> SDAD `9F4B`
//!
//! Each RSA (e = 3) with ISO/IEC 9796-2 scheme 1 recovery and SHA-1.
//!
//! Each key width is a type parameter of `RsaKey`, so a circuit is built per key-width profile.
//! Recovery (`RsaKey::recover`) is split from parsing (`verify_*`).

mod nullifier;
mod policy;
mod rsa;
mod sha1;
mod tests;

pub use nullifier::nullifier;

pub use policy::{assert_issuer_id_matches_pan, assert_not_expired};

pub use rsa::RsaKey;

pub global HEADER: u8 = 0x6A;
pub global TRAILER: u8 = 0xBC;
pub global PAD: u8 = 0xBB;

pub global FMT_ISSUER_CERT: u8 = 0x02;
pub global FMT_ICC_CERT: u8 = 0x04;
/// Book 2 (Mastercard, RuPay).
pub global FMT_SDAD_DDA: u8 = 0x05;
/// Visa contactless kernel, fDDA.
pub global FMT_SDAD_FDDA: u8 = 0x95;

global HASH_ALG_SHA1: u8 = 0x01;
global PK_ALG_RSA: u8 = 0x01;
global EXPONENT: u8 = 3;
global HASH_LEN: u32 = 20;

global HASH_TAIL: u32 = HASH_LEN + 1;

fn assert_envelope<let L: u32>(m: [u8; L], format: u8) {
    assert_eq(m[0], HEADER, "recovered data header is not 6A");
    assert_eq(m[1], format, "unexpected recovered data format");
    assert_eq(m[L - 1], TRAILER, "recovered data trailer is not BC");
}

/// Compares the embedded hash word by word: `m`'s bytes are range-checked, so each packed word is
/// below 2^32, as are the digest's.
fn assert_hash<let L: u32>(m: [u8; L], digest: [Field; 5]) {
    for k in 0..5 {
        let mut word = 0;
        for i in 0..4 {
            word = word * 256 + m[L - HASH_TAIL + 4 * k + i] as Field;
        }
        assert_eq(word, digest[k], "recovered hash mismatch");
    }
}

fn copy_hashed_body<let L: u32, let H: u32>(m: [u8; L], out: &mut [u8; H]) {
    for i in 0..(L - 1 - HASH_TAIL) {
        out[i] = m[1 + i];
    }
}

/// Book 2, 5.1 and 6.1.
fn assemble_modulus<let L: u32, let K: u32, let REM: u32, let OFFSET: u32>(m: [u8; L], remainder: [u8; REM]) -> [u8; K] {
    let space = L - OFFSET - HASH_TAIL;
    if K > space {
        std::static_assert(
            REM == K - space,
            "remainder length does not match key length",
        );
    } else {
        std::static_assert(REM == 0, "key fits in certificate, remainder must be empty");
        for i in K..space {
            assert_eq(m[OFFSET + i], PAD, "certificate padding is not BB");
        }
    }

    let mut modulus: [u8; K] = [0; K];
    for i in 0..K {
        modulus[i] = if i < space {
            m[OFFSET + i]
        } else {
            remainder[i - space]
        };
    }
    modulus
}

pub struct IssuerCert<let K: u32> {
    pub modulus: [u8; K],
    /// Leftmost 3-8 PAN digits, BCD, `F`-padded.
    pub issuer_id: [u8; 4],
    /// MMYY, BCD.
    pub expiry: [u8; 2],
}

/// Book 2 table 6.
///
/// | offset | length | field |
/// |---|---|---|
/// | 0 | 1 | header `6A` |
/// | 1 | 1 | format `02` |
/// | 2 | 4 | issuer identifier |
/// | 6 | 2 | expiry MMYY |
/// | 8 | 3 | serial |
/// | 11 | 1 | hash algorithm `01` |
/// | 12 | 1 | public key algorithm `01` |
/// | 13 | 1 | issuer key length |
/// | 14 | 1 | issuer exponent length |
/// | 15 | L-36 | issuer modulus, leftmost digits |
/// | L-21 | 20 | SHA-1 |
/// | L-1 | 1 | trailer `BC` |
pub fn verify_issuer_cert<let L: u32, let K: u32, let REM: u32>(m: [u8; L], remainder: [u8; REM], exponent: u8) -> IssuerCert<K> {
    assert_envelope(m, FMT_ISSUER_CERT);
    assert_eq(m[11], HASH_ALG_SHA1, "issuer certificate hash algorithm is not SHA-1");
    assert_eq(m[12], PK_ALG_RSA, "issuer key algorithm is not RSA");
    assert_eq(m[13] as u32, K, "issuer key length does not match this circuit");
    assert_eq(m[14], 1, "issuer exponent must be one byte");
    assert_eq(exponent, EXPONENT, "issuer exponent must be 3");

    let mut input = [0; L - HASH_TAIL + REM];
    copy_hashed_body(m, &mut input);
    let body_len = L - 1 - HASH_TAIL;
    for i in 0..REM {
        input[body_len + i] = remainder[i];
    }
    input[body_len + REM] = exponent;
    assert_hash(m, sha1::digest_words(input));

    IssuerCert { modulus: assemble_modulus::<_, K, REM, 15>(m, remainder), issuer_id: [m[2], m[3], m[4], m[5]], expiry: [m[6], m[7]] }
}

pub struct IccCert<let K: u32> {
    pub modulus: [u8; K],
    /// BCD, `F`-padded.
    pub pan: [u8; 10],
    /// MMYY, BCD.
    pub expiry: [u8; 2],
}

/// Book 2 table 14.
///
/// | offset | length | field |
/// |---|---|---|
/// | 0 | 1 | header `6A` |
/// | 1 | 1 | format `04` |
/// | 2 | 10 | application PAN |
/// | 12 | 2 | expiry MMYY |
/// | 14 | 3 | serial |
/// | 17 | 1 | hash algorithm `01` |
/// | 18 | 1 | public key algorithm `01` |
/// | 19 | 1 | ICC key length |
/// | 20 | 1 | ICC exponent length |
/// | 21 | L-42 | ICC modulus, leftmost digits |
/// | L-21 | 20 | SHA-1 |
/// | L-1 | 1 | trailer `BC` |
///
/// With no static data (`S = 0`, as on Visa) the cheaper fixed-length hash is used.
pub fn verify_icc_cert<let L: u32, let K: u32, let REM: u32, let S: u32>(
    m: [u8; L],
    remainder: [u8; REM],
    exponent: u8,
    static_data: BoundedVec<u8, S>,
) -> IccCert<K> {
    assert_envelope(m, FMT_ICC_CERT);
    assert_eq(m[17], HASH_ALG_SHA1, "ICC certificate hash algorithm is not SHA-1");
    assert_eq(m[18], PK_ALG_RSA, "ICC key algorithm is not RSA");
    assert_eq(m[19] as u32, K, "ICC key length does not match this circuit");
    assert_eq(m[20], 1, "ICC exponent must be one byte");
    assert_eq(exponent, EXPONENT, "ICC exponent must be 3");

    let mut input = [0; L - HASH_TAIL + REM];
    copy_hashed_body(m, &mut input);
    let body_len = L - 1 - HASH_TAIL;
    for i in 0..REM {
        input[body_len + i] = remainder[i];
    }
    input[body_len + REM] = exponent;

    let digest = if S == 0 {
        sha1::digest_words(input)
    } else {
        sha1::digest_words_var(input, static_data)
    };
    assert_hash(m, digest);

    IccCert {
        modulus: assemble_modulus::<_, K, REM, 21>(m, remainder),
        pan: [m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11]],
        expiry: [m[12], m[13]],
    }
}

/// Book 2 table 17.
///
/// | offset | length | field |
/// |---|---|---|
/// | 0 | 1 | header `6A` |
/// | 1 | 1 | format: `05` (Book 2) or `95` (Visa fDDA) |
/// | 2 | 1 | hash algorithm `01` |
/// | 3 | 1 | ICC dynamic data length, LDD |
/// | 4 | LDD | ICC dynamic data |
/// | 4+LDD | L-LDD-25 | padding `BB` |
/// | L-21 | 20 | SHA-1 |
/// | L-1 | 1 | trailer `BC` |
///
/// The verifier's nonce enters through `terminal_data`. The hashed span is fixed, so LDD
/// is only bounds-checked.
pub fn verify_sdad<let L: u32, let T: u32>(m: [u8; L], format: u8, terminal_data: [u8; T]) {
    assert_envelope(m, format);
    assert_eq(m[2], HASH_ALG_SHA1, "signed data hash algorithm is not SHA-1");
    assert((m[3] as u32) <= L - 25, "ICC dynamic data overruns signed data");

    let mut input = [0; L - 1 - HASH_TAIL + T];
    copy_hashed_body(m, &mut input);
    let body_len = L - 1 - HASH_TAIL;
    for i in 0..T {
        input[body_len + i] = terminal_data[i];
    }
    assert_hash(m, sha1::digest_words(input));
}
