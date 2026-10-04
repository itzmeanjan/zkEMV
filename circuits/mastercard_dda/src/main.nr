//! Mastercard contactless card, DDA: proves a genuine Mastercard chip signed the verifier's nonce.

mod tests;

use emv::{
    BinAttributes, BinMembership, BITS_PER_BYTE, CA_PUBKEY_BYTE_LEN, CA_PUBKEY_LIMB_COUNT, CaKey, FMT_SDAD_DDA, ISSUER_CERT_KEY_SPACE_BYTE_LEN, NONCE_BYTE_LEN,
};

global ISSUER_PUBKEY_BIT_LEN: u32 = 1920;
global ISSUER_PUBKEY_BYTE_LEN: u32 = ISSUER_PUBKEY_BIT_LEN / BITS_PER_BYTE;
global ISSUER_PUBKEY_REMAINDER_BYTE_LEN: u32 = ISSUER_PUBKEY_BYTE_LEN - ISSUER_CERT_KEY_SPACE_BYTE_LEN;

global ICC_PUBKEY_BIT_LEN: u32 = 1152;
global ICC_PUBKEY_BYTE_LEN: u32 = ICC_PUBKEY_BIT_LEN / BITS_PER_BYTE;

global STATIC_DATA_MAX_BYTE_LEN: u32 = 256;

pub struct Inputs {
    pub ca_modulus: [Field; CA_PUBKEY_LIMB_COUNT],
    pub nonce: [u8; NONCE_BYTE_LEN],
    pub today: u32,
    pub scope: Field,
    pub bin_root: Field,
    pub disclose: u8,
    pub issuer_cert: [u8; CA_PUBKEY_BYTE_LEN],
    pub issuer_remainder: [u8; ISSUER_PUBKEY_REMAINDER_BYTE_LEN],
    pub issuer_exponent: u8,
    pub icc_cert: [u8; ISSUER_PUBKEY_BYTE_LEN],
    pub icc_exponent: u8,
    pub static_data: BoundedVec<u8, STATIC_DATA_MAX_BYTE_LEN>,
    pub sdad: [u8; ICC_PUBKEY_BYTE_LEN],
    pub bin: BinMembership,
}

fn main(
    ca_modulus: pub [Field; CA_PUBKEY_LIMB_COUNT],
    nonce: pub [u8; NONCE_BYTE_LEN],
    today: pub u32,
    scope: pub Field,
    bin_root: pub Field,
    disclose: pub u8,
    issuer_cert: [u8; CA_PUBKEY_BYTE_LEN], // 90
    issuer_remainder: [u8; ISSUER_PUBKEY_REMAINDER_BYTE_LEN], // 92
    issuer_exponent: u8, // 9F32
    icc_cert: [u8; ISSUER_PUBKEY_BYTE_LEN], // 9F46
    icc_exponent: u8, // 9F47
    static_data: BoundedVec<u8, STATIC_DATA_MAX_BYTE_LEN>, // AFL-flagged records || AIP
    sdad: [u8; ICC_PUBKEY_BYTE_LEN], // 9F4B
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
    let card = CaKey::from_limbs(x.ca_modulus)
        .recover_issuer_cert(x.issuer_cert)
        .verify::<ISSUER_PUBKEY_BYTE_LEN, _>(x.issuer_remainder, x.issuer_exponent, x.today)
        .key()
        .recover_icc_cert(x.icc_cert)
        .verify::<ICC_PUBKEY_BYTE_LEN, _, _>([], x.icc_exponent, x.static_data, x.today)
        .key()
        .recover_sdad(x.sdad)
        .verify(FMT_SDAD_DDA, x.nonce);

    (card.bin_attributes(x.bin_root, x.disclose, x.bin), card.nullifier(x.scope))
}
