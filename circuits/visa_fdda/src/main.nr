//! Visa contactless card, fast Dynamic Data Authentication (fDDA): proves a genuine Visa chip signed the verifier's nonce.

mod tests;

use emv::{
    AMOUNT_AUTHORISED_BYTE_LEN, assert_issuer_id_matches_pan, assert_not_expired, bin_attributes, BinAttributes, BinMembership, BITS_PER_BYTE, concat,
    CURRENCY_CODE_BYTE_LEN, FMT_SDAD_FDDA, LIMB_BYTE_LEN, NONCE_BYTE_LEN, nullifier, RsaKey, verify_icc_cert, verify_issuer_cert, verify_sdad,
};

global CA_PUBKEY_BIT_LEN: u32 = 1984;
global CA_PUBKEY_BYTE_LEN: u32 = CA_PUBKEY_BIT_LEN / BITS_PER_BYTE;
global CA_PUBKEY_LIMB_COUNT: u32 = (CA_PUBKEY_BYTE_LEN + LIMB_BYTE_LEN - 1) / LIMB_BYTE_LEN;

global ISSUER_PUBKEY_BIT_LEN: u32 = 1408;
global ISSUER_PUBKEY_BYTE_LEN: u32 = ISSUER_PUBKEY_BIT_LEN / BITS_PER_BYTE;

global ICC_PUBKEY_BIT_LEN: u32 = 1024;
global ICC_PUBKEY_BYTE_LEN: u32 = ICC_PUBKEY_BIT_LEN / BITS_PER_BYTE;

global CARD_AUTH_DATA_BYTE_LEN: u32 = 7;
global STATIC_DATA_MAX_BYTE_LEN: u32 = 0;

pub struct Inputs {
    pub ca_modulus: [Field; CA_PUBKEY_LIMB_COUNT],
    pub nonce: [u8; NONCE_BYTE_LEN],
    pub amount: [u8; AMOUNT_AUTHORISED_BYTE_LEN],
    pub currency: [u8; CURRENCY_CODE_BYTE_LEN],
    pub today: u32,
    pub scope: Field,
    pub bin_root: Field,
    pub disclose: u8,
    pub issuer_cert: [u8; CA_PUBKEY_BYTE_LEN],
    pub issuer_exponent: u8,
    pub icc_cert: [u8; ISSUER_PUBKEY_BYTE_LEN],
    pub icc_exponent: u8,
    pub sdad: [u8; ICC_PUBKEY_BYTE_LEN],
    pub card_auth_data: [u8; CARD_AUTH_DATA_BYTE_LEN],
    pub bin: BinMembership,
}

fn main(
    ca_modulus: pub [Field; CA_PUBKEY_LIMB_COUNT],
    nonce: pub [u8; NONCE_BYTE_LEN],
    amount: pub [u8; AMOUNT_AUTHORISED_BYTE_LEN],
    currency: pub [u8; CURRENCY_CODE_BYTE_LEN],
    today: pub u32,
    scope: pub Field,
    bin_root: pub Field,
    disclose: pub u8,
    issuer_cert: [u8; CA_PUBKEY_BYTE_LEN], // 90
    issuer_exponent: u8, // 9F32
    icc_cert: [u8; ISSUER_PUBKEY_BYTE_LEN], // 9F46
    icc_exponent: u8, // 9F47
    sdad: [u8; ICC_PUBKEY_BYTE_LEN], // 9F4B
    card_auth_data: [u8; CARD_AUTH_DATA_BYTE_LEN], // 9F69
    bin: BinMembership,
) -> pub (BinAttributes, Field) {
    verify(
        Inputs {
            ca_modulus,
            nonce,
            amount,
            currency,
            today,
            scope,
            bin_root,
            disclose,
            issuer_cert,
            issuer_exponent,
            icc_cert,
            icc_exponent,
            sdad,
            card_auth_data,
            bin,
        },
    )
}

fn verify(x: Inputs) -> (BinAttributes, Field) {
    let ca_key = RsaKey::<CA_PUBKEY_BYTE_LEN>::from_limbs(x.ca_modulus);

    let issuer = verify_issuer_cert::<_, ISSUER_PUBKEY_BYTE_LEN, _>(ca_key.recover(x.issuer_cert), [], x.issuer_exponent);
    let issuer_key = RsaKey::<ISSUER_PUBKEY_BYTE_LEN>::from_be_bytes(issuer.modulus);

    let icc = verify_icc_cert::<_, ICC_PUBKEY_BYTE_LEN, _, _>(
        issuer_key.recover(x.icc_cert),
        [],
        x.icc_exponent,
        BoundedVec::<u8, STATIC_DATA_MAX_BYTE_LEN>::new(),
    );
    let icc_key = RsaKey::<ICC_PUBKEY_BYTE_LEN>::from_be_bytes(icc.modulus);

    assert_issuer_id_matches_pan(issuer.issuer_id, icc.pan);
    assert_not_expired(issuer.expiry, x.today);
    assert_not_expired(icc.expiry, x.today);

    let terminal_data = concat(
        concat(concat(x.nonce, x.amount), x.currency),
        x.card_auth_data,
    );
    verify_sdad(icc_key.recover(x.sdad), FMT_SDAD_FDDA, terminal_data);

    (bin_attributes(icc.pan, x.bin_root, x.disclose, x.bin), nullifier(icc.modulus, x.scope))
}
