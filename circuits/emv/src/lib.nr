//! EMV Book 2 offline data authentication:
//! CA key -> issuer cert `90` -> ICC cert `9F46` -> SDAD `9F4B`
//!
//! Each RSA (e = 3) with ISO/IEC 9796-2 scheme 1 recovery and SHA-1.
//!
//! Each key width is a type parameter of `RsaKey`, so a circuit is built per key-width profile.
//! Recovery (`RsaKey::recover`) is split from parsing (`verify_*`).

mod bin_table;
mod bytes;
mod card_chain;
mod nullifier;
mod policy;
mod rsa;
mod sha1;
mod tests;

pub use bin_table::{bin_attributes, BinAttributes, BinMembership};
pub use bytes::{BITS_PER_BYTE, concat};
pub use card_chain::{AuthenticatedCard, CaKey, IccCert, IccKey, IssuerCert, IssuerKey, RecoveredIccCert, RecoveredIssuerCert, RecoveredSdad};
pub use nullifier::nullifier;

pub use policy::{assert_issuer_id_matches_pan, assert_not_expired};

pub use rsa::{LIMB_BYTE_LEN, RsaKey};

pub global RECOVERED_DATA_HEADER: u8 = 0x6A;
pub global RECOVERED_DATA_TRAILER: u8 = 0xBC;
pub global PAD_BYTE: u8 = 0xBB;

pub global FMT_ISSUER_CERT: u8 = 0x02;
pub global FMT_ICC_CERT: u8 = 0x04;
/// Book 2 (Mastercard, RuPay).
pub global FMT_SDAD_DDA: u8 = 0x05;
/// Visa contactless kernel, fDDA.
pub global FMT_SDAD_FDDA: u8 = 0x95;

global HASH_ALG_SHA1: u8 = 0x01;
global PK_ALG_RSA: u8 = 0x01;
global RSA_EXPONENT: u8 = 3;

pub global NONCE_BYTE_LEN: u32 = 4;
pub global AMOUNT_AUTHORISED_BYTE_LEN: u32 = 6;
pub global CURRENCY_CODE_BYTE_LEN: u32 = 2;

pub global ISSUER_ID_BYTE_LEN: u32 = 4;
pub global EXPIRY_BYTE_LEN: u32 = 2;
pub global PAN_BYTE_LEN: u32 = 10;
global SERIAL_BYTE_LEN: u32 = 3;
global EXPONENT_BYTE_LEN: u32 = 1;
global HASH_BYTE_LEN: u32 = 20;
global HASH_WORD_BYTE_LEN: u32 = 4;
global HASH_WORD_COUNT: u32 = HASH_BYTE_LEN / HASH_WORD_BYTE_LEN;

global HEADER_BYTE_LEN: u32 = 1;
global FORMAT_BYTE_LEN: u32 = 1;
global ALGORITHM_ID_BYTE_LEN: u32 = 1;
global LENGTH_FIELD_BYTE_LEN: u32 = 1;
global TRAILER_BYTE_LEN: u32 = 1;
global HASH_AND_TRAILER_BYTE_LEN: u32 = HASH_BYTE_LEN + TRAILER_BYTE_LEN;

global HEADER_OFFSET: u32 = 0;
global FORMAT_OFFSET: u32 = HEADER_OFFSET + HEADER_BYTE_LEN;
global BODY_OFFSET: u32 = FORMAT_OFFSET;
global FIELDS_OFFSET: u32 = FORMAT_OFFSET + FORMAT_BYTE_LEN;

/// Book 2 table 6.
global ISSUER_ID_OFFSET: u32 = FIELDS_OFFSET;
global ISSUER_EXPIRY_OFFSET: u32 = ISSUER_ID_OFFSET + ISSUER_ID_BYTE_LEN;
global ISSUER_SERIAL_OFFSET: u32 = ISSUER_EXPIRY_OFFSET + EXPIRY_BYTE_LEN;
global ISSUER_HASH_ALG_OFFSET: u32 = ISSUER_SERIAL_OFFSET + SERIAL_BYTE_LEN;
global ISSUER_PK_ALG_OFFSET: u32 = ISSUER_HASH_ALG_OFFSET + ALGORITHM_ID_BYTE_LEN;
global ISSUER_KEY_BYTE_LEN_OFFSET: u32 = ISSUER_PK_ALG_OFFSET + ALGORITHM_ID_BYTE_LEN;
global ISSUER_EXPONENT_BYTE_LEN_OFFSET: u32 = ISSUER_KEY_BYTE_LEN_OFFSET + LENGTH_FIELD_BYTE_LEN;
global ISSUER_KEY_OFFSET: u32 = ISSUER_EXPONENT_BYTE_LEN_OFFSET + LENGTH_FIELD_BYTE_LEN;

/// Book 2 table 14.
global ICC_PAN_OFFSET: u32 = FIELDS_OFFSET;
global ICC_EXPIRY_OFFSET: u32 = ICC_PAN_OFFSET + PAN_BYTE_LEN;
global ICC_SERIAL_OFFSET: u32 = ICC_EXPIRY_OFFSET + EXPIRY_BYTE_LEN;
global ICC_HASH_ALG_OFFSET: u32 = ICC_SERIAL_OFFSET + SERIAL_BYTE_LEN;
global ICC_PK_ALG_OFFSET: u32 = ICC_HASH_ALG_OFFSET + ALGORITHM_ID_BYTE_LEN;
global ICC_KEY_BYTE_LEN_OFFSET: u32 = ICC_PK_ALG_OFFSET + ALGORITHM_ID_BYTE_LEN;
global ICC_EXPONENT_BYTE_LEN_OFFSET: u32 = ICC_KEY_BYTE_LEN_OFFSET + LENGTH_FIELD_BYTE_LEN;
global ICC_KEY_OFFSET: u32 = ICC_EXPONENT_BYTE_LEN_OFFSET + LENGTH_FIELD_BYTE_LEN;

/// Book 2 table 17.
global SDAD_HASH_ALG_OFFSET: u32 = FIELDS_OFFSET;
global DYNAMIC_DATA_BYTE_LEN_OFFSET: u32 = SDAD_HASH_ALG_OFFSET + ALGORITHM_ID_BYTE_LEN;
global DYNAMIC_DATA_OFFSET: u32 = DYNAMIC_DATA_BYTE_LEN_OFFSET + LENGTH_FIELD_BYTE_LEN;

fn assert_envelope<let L: u32>(m: [u8; L], format: u8) {
    assert_eq(m[HEADER_OFFSET], RECOVERED_DATA_HEADER, "recovered data header is not 6A");
    assert_eq(m[FORMAT_OFFSET], format, "unexpected recovered data format");
    assert_eq(m[L - TRAILER_BYTE_LEN], RECOVERED_DATA_TRAILER, "recovered data trailer is not BC");
}

/// Compares the embedded hash word by word: `m`'s bytes are range-checked, so each packed word is
/// below 2^32, as are the digest's.
fn assert_hash<let L: u32>(m: [u8; L], digest: [Field; HASH_WORD_COUNT]) {
    let embedded: [u8; HASH_BYTE_LEN] = bytes::read(m, L - HASH_AND_TRAILER_BYTE_LEN);
    for k in 0..HASH_WORD_COUNT {
        let word: [u8; HASH_WORD_BYTE_LEN] = bytes::read(embedded, HASH_WORD_BYTE_LEN * k);
        assert_eq(bytes::be_bytes_to_field(word), digest[k], "recovered hash mismatch");
    }
}

/// Everything between the header and the hash.
fn hashed_body<let L: u32>(m: [u8; L]) -> [u8; L - HEADER_BYTE_LEN - HASH_AND_TRAILER_BYTE_LEN] {
    bytes::read(m, BODY_OFFSET)
}

/// Book 2, 5.1 and 6.1.
fn assemble_modulus<let L: u32, let K: u32, let REM: u32, let OFFSET: u32>(m: [u8; L], remainder: [u8; REM]) -> [u8; K] {
    let space = L - OFFSET - HASH_AND_TRAILER_BYTE_LEN;
    if K > space {
        std::static_assert(
            REM == K - space,
            "remainder length does not match key length",
        );
    } else {
        std::static_assert(REM == 0, "key fits in certificate, remainder must be empty");
        for i in K..space {
            assert_eq(m[OFFSET + i], PAD_BYTE, "certificate padding is not BB");
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

pub struct IssuerCertFields<let K: u32> {
    pub modulus: [u8; K],
    /// Leftmost 3-8 PAN digits, BCD, `F`-padded.
    pub issuer_id: [u8; ISSUER_ID_BYTE_LEN],
    /// MMYY, BCD.
    pub expiry: [u8; EXPIRY_BYTE_LEN],
}

/// Book 2 table 6.
pub fn verify_issuer_cert<let L: u32, let K: u32, let REM: u32>(m: [u8; L], remainder: [u8; REM], exponent: u8) -> IssuerCertFields<K> {
    assert_envelope(m, FMT_ISSUER_CERT);
    assert_eq(m[ISSUER_HASH_ALG_OFFSET], HASH_ALG_SHA1, "issuer certificate hash algorithm is not SHA-1");
    assert_eq(m[ISSUER_PK_ALG_OFFSET], PK_ALG_RSA, "issuer key algorithm is not RSA");
    assert_eq(m[ISSUER_KEY_BYTE_LEN_OFFSET] as u32, K, "issuer key length does not match this circuit");
    assert_eq(m[ISSUER_EXPONENT_BYTE_LEN_OFFSET], EXPONENT_BYTE_LEN as u8, "issuer exponent must be one byte");
    assert_eq(exponent, RSA_EXPONENT, "issuer exponent must be 3");

    let input = bytes::concat(bytes::concat(hashed_body(m), remainder), [exponent]);
    assert_hash(m, sha1::digest_words(input));

    IssuerCertFields {
        modulus: assemble_modulus::<_, K, REM, ISSUER_KEY_OFFSET>(m, remainder),
        issuer_id: bytes::read(m, ISSUER_ID_OFFSET),
        expiry: bytes::read(m, ISSUER_EXPIRY_OFFSET),
    }
}

pub struct IccCertFields<let K: u32> {
    pub modulus: [u8; K],
    /// BCD, `F`-padded.
    pub pan: [u8; PAN_BYTE_LEN],
    /// MMYY, BCD.
    pub expiry: [u8; EXPIRY_BYTE_LEN],
}

/// Book 2 table 14. With no static data (`S = 0`, as on Visa) the cheaper fixed-length hash is used.
pub fn verify_icc_cert<let L: u32, let K: u32, let REM: u32, let S: u32>(
    m: [u8; L],
    remainder: [u8; REM],
    exponent: u8,
    static_data: BoundedVec<u8, S>,
) -> IccCertFields<K> {
    assert_envelope(m, FMT_ICC_CERT);
    assert_eq(m[ICC_HASH_ALG_OFFSET], HASH_ALG_SHA1, "ICC certificate hash algorithm is not SHA-1");
    assert_eq(m[ICC_PK_ALG_OFFSET], PK_ALG_RSA, "ICC key algorithm is not RSA");
    assert_eq(m[ICC_KEY_BYTE_LEN_OFFSET] as u32, K, "ICC key length does not match this circuit");
    assert_eq(m[ICC_EXPONENT_BYTE_LEN_OFFSET], EXPONENT_BYTE_LEN as u8, "ICC exponent must be one byte");
    assert_eq(exponent, RSA_EXPONENT, "ICC exponent must be 3");

    let input = bytes::concat(bytes::concat(hashed_body(m), remainder), [exponent]);
    let digest = if S == 0 {
        sha1::digest_words(input)
    } else {
        sha1::digest_words_var(input, static_data)
    };
    assert_hash(m, digest);

    IccCertFields {
        modulus: assemble_modulus::<_, K, REM, ICC_KEY_OFFSET>(m, remainder),
        pan: bytes::read(m, ICC_PAN_OFFSET),
        expiry: bytes::read(m, ICC_EXPIRY_OFFSET),
    }
}

/// Book 2 table 17. The verifier's nonce enters through `terminal_data`. The hashed span is fixed,
/// so the dynamic data length is only bounds-checked.
pub fn verify_sdad<let L: u32, let T: u32>(m: [u8; L], format: u8, terminal_data: [u8; T]) {
    assert_envelope(m, format);
    assert_eq(m[SDAD_HASH_ALG_OFFSET], HASH_ALG_SHA1, "signed data hash algorithm is not SHA-1");
    assert((m[DYNAMIC_DATA_BYTE_LEN_OFFSET] as u32) <= L - DYNAMIC_DATA_OFFSET - HASH_AND_TRAILER_BYTE_LEN, "ICC dynamic data overruns signed data");

    assert_hash(
        m,
        sha1::digest_words(bytes::concat(hashed_body(m), terminal_data)),
    );
}
