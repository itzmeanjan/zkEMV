use crate::{
    bin_table::{bin_attributes, BinMembership},
    bytes::{self, BITS_PER_BYTE},
    interface::{Challenge, Revealed},
    nullifier::nullifier,
    policy::{assert_issuer_id_matches_pan, assert_not_expired},
    rsa::{LIMB_BYTE_LEN, RsaKey},
    sha1,
};

pub global CA_PUBKEY_BIT_LEN: u32 = 1984;
pub global CA_PUBKEY_BYTE_LEN: u32 = CA_PUBKEY_BIT_LEN / BITS_PER_BYTE;
pub global CA_PUBKEY_LIMB_COUNT: u32 = (CA_PUBKEY_BYTE_LEN + LIMB_BYTE_LEN - 1) / LIMB_BYTE_LEN;

global RECOVERED_DATA_HEADER: u8 = 0x6A;
global RECOVERED_DATA_TRAILER: u8 = 0xBC;
global PAD_BYTE: u8 = 0xBB;

global FMT_ISSUER_CERT: u8 = 0x02;
global FMT_ICC_CERT: u8 = 0x04;
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
global HASH_BYTE_LEN: u32 = sha1::DIGEST_BYTE_LEN;
global HASH_WORD_BYTE_LEN: u32 = sha1::WORD_BYTE_LEN;
global HASH_WORD_COUNT: u32 = sha1::DIGEST_WORD_COUNT;

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
global ISSUER_CERT_OVERHEAD_BYTE_LEN: u32 = ISSUER_KEY_OFFSET + HASH_AND_TRAILER_BYTE_LEN;
pub global ISSUER_CERT_KEY_SPACE_BYTE_LEN: u32 = CA_PUBKEY_BYTE_LEN - ISSUER_CERT_OVERHEAD_BYTE_LEN;

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

pub struct CaKey {
    key: RsaKey<CA_PUBKEY_BYTE_LEN>,
}

pub struct RecoveredIssuerCert {
    bytes: [u8; CA_PUBKEY_BYTE_LEN],
}

pub struct IssuerCert<let K: u32> {
    modulus: [u8; K],
    issuer_id: [u8; ISSUER_ID_BYTE_LEN],
}

pub struct IssuerKey<let K: u32> {
    key: RsaKey<K>,
    issuer_id: [u8; ISSUER_ID_BYTE_LEN],
}

pub struct RecoveredIccCert<let L: u32> {
    bytes: [u8; L],
    issuer_id: [u8; ISSUER_ID_BYTE_LEN],
}

pub struct IccCert<let K: u32> {
    modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

pub struct IccKey<let K: u32> {
    key: RsaKey<K>,
    modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

pub struct RecoveredSdad<let K: u32> {
    bytes: [u8; K],
    icc_modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

pub struct AuthenticatedCard<let K: u32> {
    icc_modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

impl CaKey {
    /// The public CA modulus, which the verifier compares with its CA table.
    pub fn from_limbs(n: [Field; CA_PUBKEY_LIMB_COUNT]) -> Self {
        CaKey { key: RsaKey::<CA_PUBKEY_BYTE_LEN>::from_limbs(n) }
    }

    pub fn recover_issuer_cert(self, cert: [u8; CA_PUBKEY_BYTE_LEN]) -> RecoveredIssuerCert {
        RecoveredIssuerCert { bytes: self.key.recover(cert) }
    }
}

impl RecoveredIssuerCert {
    /// Book 2 table 6.
    pub fn verify<let K: u32, let REM: u32>(self, remainder: [u8; REM], exponent: u8, today: u32) -> IssuerCert<K> {
        let m = self.bytes;
        assert_envelope(m, FMT_ISSUER_CERT);
        assert_eq(m[ISSUER_HASH_ALG_OFFSET], HASH_ALG_SHA1, "issuer certificate hash algorithm is not SHA-1");
        assert_eq(m[ISSUER_PK_ALG_OFFSET], PK_ALG_RSA, "issuer key algorithm is not RSA");
        assert_eq(m[ISSUER_KEY_BYTE_LEN_OFFSET] as u32, K, "issuer key length does not match this circuit");
        assert_eq(m[ISSUER_EXPONENT_BYTE_LEN_OFFSET], EXPONENT_BYTE_LEN as u8, "issuer exponent must be one byte");
        assert_eq(exponent, RSA_EXPONENT, "issuer exponent must be 3");

        let input = bytes::concat(bytes::concat(hashed_body(m), remainder), [exponent]);
        assert_hash(m, sha1::digest_words(input));

        assert_not_expired(bytes::read(m, ISSUER_EXPIRY_OFFSET), today);
        IssuerCert { modulus: assemble_modulus::<_, K, REM, ISSUER_KEY_OFFSET>(m, remainder), issuer_id: bytes::read(m, ISSUER_ID_OFFSET) }
    }
}

impl<let K: u32> IssuerCert<K> {
    pub fn key(self) -> IssuerKey<K> {
        IssuerKey { key: RsaKey::from_be_bytes(self.modulus), issuer_id: self.issuer_id }
    }
}

impl<let K: u32> IssuerKey<K> {
    pub fn recover_icc_cert(self, cert: [u8; K]) -> RecoveredIccCert<K> {
        RecoveredIccCert { bytes: self.key.recover(cert), issuer_id: self.issuer_id }
    }
}

impl<let L: u32> RecoveredIccCert<L> {
    /// Book 2 table 14. With no static data (`S = 0`) the cheaper fixed-length hash is used.
    pub fn verify<let K: u32, let REM: u32, let S: u32>(self, remainder: [u8; REM], exponent: u8, static_data: BoundedVec<u8, S>, today: u32) -> IccCert<K> {
        let m = self.bytes;
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

        let pan = bytes::read(m, ICC_PAN_OFFSET);
        assert_issuer_id_matches_pan(self.issuer_id, pan);
        assert_not_expired(bytes::read(m, ICC_EXPIRY_OFFSET), today);
        IccCert { modulus: assemble_modulus::<_, K, REM, ICC_KEY_OFFSET>(m, remainder), pan }
    }
}

impl<let K: u32> IccCert<K> {
    pub fn key(self) -> IccKey<K> {
        IccKey { key: RsaKey::from_be_bytes(self.modulus), modulus: self.modulus, pan: self.pan }
    }
}

impl<let K: u32> IccKey<K> {
    pub fn recover_sdad(self, sdad: [u8; K]) -> RecoveredSdad<K> {
        RecoveredSdad { bytes: self.key.recover(sdad), icc_modulus: self.modulus, pan: self.pan }
    }
}

impl<let K: u32> RecoveredSdad<K> {
    /// Book 2 table 17. The hashed span is fixed, so the dynamic data length is only bounds-checked.
    pub fn verify<let T: u32>(self, format: u8, terminal_data: [u8; T]) -> AuthenticatedCard<K> {
        let m = self.bytes;
        assert_envelope(m, format);
        assert_eq(m[SDAD_HASH_ALG_OFFSET], HASH_ALG_SHA1, "signed data hash algorithm is not SHA-1");
        assert((m[DYNAMIC_DATA_BYTE_LEN_OFFSET] as u32) <= K - DYNAMIC_DATA_OFFSET - HASH_AND_TRAILER_BYTE_LEN, "ICC dynamic data overruns signed data");
        assert_hash(
            m,
            sha1::digest_words(bytes::concat(hashed_body(m), terminal_data)),
        );

        AuthenticatedCard { icc_modulus: self.icc_modulus, pan: self.pan }
    }
}

impl<let K: u32> AuthenticatedCard<K> {
    pub fn reveal(self, bin_root: Field, challenge: Challenge, bin_membership: BinMembership) -> Revealed {
        Revealed {
            bin_attributes: bin_attributes(self.pan, bin_root, challenge.disclosure, bin_membership),
            nullifier: nullifier(self.icc_modulus, challenge.scope),
        }
    }
}
