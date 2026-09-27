//! Mastercard contactless card, DDA: proves a genuine Mastercard chip signed the verifier's nonce.

mod tests;

use emv::{
    assert_issuer_id_matches_pan, assert_not_expired, BigNumParams, DoubledKey, FMT_SDAD_DDA, key_from_be_bytes, rsa_recover, verify_icc_cert,
    verify_issuer_cert, verify_sdad,
};

global CA_BITS: u32 = 1984;
global CA_N: u32 = 17;
global ISSUER_BITS: u32 = 1920;
/// 1920 = 16 x 120 leaves bignum no limb headroom, so the issuer key is held as
/// arithmetic modulo 2n: 1921 bits in 17 limbs. See `emv::DoubledKey`.
global ISSUER_DOUBLED_BITS: u32 = ISSUER_BITS + 1;
global ISSUER_N: u32 = 17;
global ICC_BITS: u32 = 1152;
global ICC_N: u32 = 10;

/// Issuer key bytes that do not fit in the CA-signed certificate: 240 - (248 - 36).
global ISSUER_REMAINDER_LEN: u32 = 28;
/// Headroom over the 131 B observed.
global MAX_STATIC_DATA_LEN: u32 = 256;

pub struct Inputs {
    pub ca_modulus: [u128; CA_N],
    pub nonce: [u8; 4],
    pub today: u32,
    pub ca_redc: [u128; CA_N],
    pub issuer_redc: [u128; ISSUER_N],
    pub icc_redc: [u128; ICC_N],
    pub issuer_cert: [u8; CA_BITS / 8],
    pub issuer_remainder: [u8; ISSUER_REMAINDER_LEN],
    pub issuer_exponent: u8,
    pub icc_cert: [u8; ISSUER_BITS / 8],
    pub icc_exponent: u8,
    pub static_data: BoundedVec<u8, MAX_STATIC_DATA_LEN>,
    pub sdad: [u8; ICC_BITS / 8],
}

fn main(
    // The verifier must check this is in its CA table.
    ca_modulus: pub [u128; CA_N],
    // Unpredictable Number (9F37): the verifier's challenge, and the whole DDOL.
    nonce: pub [u8; 4],
    // YYMM
    today: pub u32,
    // Barrett hints; they affect witness generation only.
    ca_redc: [u128; CA_N],
    issuer_redc: [u128; ISSUER_N],
    icc_redc: [u128; ICC_N],
    issuer_cert: [u8; CA_BITS / 8], // 90
    issuer_remainder: [u8; ISSUER_REMAINDER_LEN], // 92
    issuer_exponent: u8, // 9F32
    icc_cert: [u8; ISSUER_BITS / 8], // 9F46
    icc_exponent: u8, // 9F47
    static_data: BoundedVec<u8, MAX_STATIC_DATA_LEN>, // AFL-flagged records || AIP
    sdad: [u8; ICC_BITS / 8], // 9F4B
) {
    verify(
        Inputs {
            ca_modulus,
            nonce,
            today,
            ca_redc,
            issuer_redc,
            icc_redc,
            issuer_cert,
            issuer_remainder,
            issuer_exponent,
            icc_cert,
            icc_exponent,
            static_data,
            sdad,
        },
    );
}

fn verify(x: Inputs) {
    let ca_key: BigNumParams<CA_N, CA_BITS> = BigNumParams::new(false, x.ca_modulus, x.ca_redc);

    let issuer = verify_issuer_cert::<_, ISSUER_BITS / 8, _>(
        rsa_recover(ca_key, x.issuer_cert),
        x.issuer_remainder,
        x.issuer_exponent,
    );
    let issuer_key: DoubledKey<ISSUER_N, ISSUER_DOUBLED_BITS> = DoubledKey::from_be_bytes(issuer.modulus, x.issuer_redc);

    let icc = verify_icc_cert::<_, ICC_BITS / 8, _, _>(
        issuer_key.recover(x.icc_cert),
        [],
        x.icc_exponent,
        x.static_data,
    );
    let icc_key: BigNumParams<ICC_N, ICC_BITS> = key_from_be_bytes::<ICC_N, ICC_BITS>(icc.modulus, x.icc_redc);

    assert_issuer_id_matches_pan(issuer.issuer_id, icc.pan);
    assert_not_expired(issuer.expiry, x.today);
    assert_not_expired(icc.expiry, x.today);

    verify_sdad(rsa_recover(icc_key, x.sdad), FMT_SDAD_DDA, x.nonce);
}
