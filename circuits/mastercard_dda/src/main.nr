//! Mastercard contactless card, DDA: proves a genuine Mastercard chip signed the verifier's nonce.

mod tests;

use emv::{
    assert_issuer_id_matches_pan, assert_not_expired, bin_attributes, BinAttributes, BinMembership, FMT_SDAD_DDA, nullifier, RsaKey, verify_icc_cert,
    verify_issuer_cert, verify_sdad,
};

global CA_BITS: u32 = 1984;
/// 120-bit limbs of the CA modulus.
global CA_N: u32 = 17;
global ISSUER_BITS: u32 = 1920;
global ICC_BITS: u32 = 1152;

/// Issuer key bytes that do not fit in the CA-signed certificate: 240 - (248 - 36).
global ISSUER_REMAINDER_LEN: u32 = 28;
/// Headroom over the 131 B observed.
global MAX_STATIC_DATA_LEN: u32 = 256;

pub struct Inputs {
    pub ca_modulus: [Field; CA_N],
    pub nonce: [u8; 4],
    pub today: u32,
    pub scope: Field,
    pub bin_root: Field,
    pub disclose: u8,
    pub issuer_cert: [u8; CA_BITS / 8],
    pub issuer_remainder: [u8; ISSUER_REMAINDER_LEN],
    pub issuer_exponent: u8,
    pub icc_cert: [u8; ISSUER_BITS / 8],
    pub icc_exponent: u8,
    pub static_data: BoundedVec<u8, MAX_STATIC_DATA_LEN>,
    pub sdad: [u8; ICC_BITS / 8],
    pub bin: BinMembership,
}

fn main(
    // The verifier must check this is in its CA table.
    ca_modulus: pub [Field; CA_N],
    // Nonce (9F37): the verifier's challenge, and the whole DDOL.
    nonce: pub [u8; 4],
    // YYMM
    today: pub u32,
    // Chosen by the verifier, or at random by the prover when the verifier needs no nullifier.
    scope: pub Field,
    // Root of the verifier's BIN table (emv crate's `BinTable`).
    bin_root: pub Field,
    // Attributes to reveal, see `emv::bin_attributes`.
    disclose: pub u8,
    issuer_cert: [u8; CA_BITS / 8], // 90
    issuer_remainder: [u8; ISSUER_REMAINDER_LEN], // 92
    issuer_exponent: u8, // 9F32
    icc_cert: [u8; ISSUER_BITS / 8], // 9F46
    icc_exponent: u8, // 9F47
    static_data: BoundedVec<u8, MAX_STATIC_DATA_LEN>, // AFL-flagged records || AIP
    sdad: [u8; ICC_BITS / 8], // 9F4B
    bin: BinMembership,
) -> pub (BinAttributes, Field) {
    verify(
        Inputs {
            ca_modulus,
            nonce,
            today,
            scope,
            bin_root,
            disclose,
            issuer_cert,
            issuer_remainder,
            issuer_exponent,
            icc_cert,
            icc_exponent,
            static_data,
            sdad,
            bin,
        },
    )
}

fn verify(x: Inputs) -> (BinAttributes, Field) {
    let ca_key = RsaKey::<CA_BITS / 8>::from_limbs(x.ca_modulus);

    let issuer = verify_issuer_cert::<_, ISSUER_BITS / 8, _>(
        ca_key.recover(x.issuer_cert),
        x.issuer_remainder,
        x.issuer_exponent,
    );
    let issuer_key: RsaKey<ISSUER_BITS / 8> = RsaKey::from_be_bytes(issuer.modulus);

    let icc = verify_icc_cert::<_, ICC_BITS / 8, _, _>(
        issuer_key.recover(x.icc_cert),
        [],
        x.icc_exponent,
        x.static_data,
    );
    let icc_key: RsaKey<ICC_BITS / 8> = RsaKey::from_be_bytes(icc.modulus);

    assert_issuer_id_matches_pan(issuer.issuer_id, icc.pan);
    assert_not_expired(issuer.expiry, x.today);
    assert_not_expired(icc.expiry, x.today);

    verify_sdad(icc_key.recover(x.sdad), FMT_SDAD_DDA, x.nonce);

    (bin_attributes(icc.pan, x.bin_root, x.disclose, x.bin), nullifier(icc.modulus, x.scope))
}
