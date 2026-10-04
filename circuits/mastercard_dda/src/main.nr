//! Mastercard contactless card, DDA: proves a genuine Mastercard chip signed the verifier's nonce.

mod tests;

use emv::{BinMembership, BITS_PER_BYTE, CA_PUBKEY_BYTE_LEN, CaKey, Challenge, FMT_SDAD_DDA, ISSUER_CERT_KEY_SPACE_BYTE_LEN, Revealed, TrustAnchors};

global ISSUER_PUBKEY_BIT_LEN: u32 = 1920;
global ISSUER_PUBKEY_BYTE_LEN: u32 = ISSUER_PUBKEY_BIT_LEN / BITS_PER_BYTE;
global ISSUER_PUBKEY_REMAINDER_BYTE_LEN: u32 = ISSUER_PUBKEY_BYTE_LEN - ISSUER_CERT_KEY_SPACE_BYTE_LEN;

global ICC_PUBKEY_BIT_LEN: u32 = 1152;
global ICC_PUBKEY_BYTE_LEN: u32 = ICC_PUBKEY_BIT_LEN / BITS_PER_BYTE;

global STATIC_DATA_MAX_BYTE_LEN: u32 = 256;

/// The card's data from the tap.
pub struct Card {
    pub issuer_pubkey_cert: [u8; CA_PUBKEY_BYTE_LEN],
    pub issuer_pubkey_remainder: [u8; ISSUER_PUBKEY_REMAINDER_BYTE_LEN],
    pub issuer_pubkey_exponent: u8,
    pub icc_pubkey_cert: [u8; ISSUER_PUBKEY_BYTE_LEN],
    pub icc_pubkey_exponent: u8,
    pub static_data_to_authenticate: BoundedVec<u8, STATIC_DATA_MAX_BYTE_LEN>,
    pub signed_dynamic_app_data: [u8; ICC_PUBKEY_BYTE_LEN],
}

fn main(trust_anchors: pub TrustAnchors, challenge: pub Challenge, card: Card, bin_membership: BinMembership) -> pub Revealed {
    CaKey::from_limbs(trust_anchors.ca_modulus)
        .recover_issuer_cert(card.issuer_pubkey_cert)
        .verify::<ISSUER_PUBKEY_BYTE_LEN, _>(card.issuer_pubkey_remainder, card.issuer_pubkey_exponent, challenge.today_yymm)
        .key()
        .recover_icc_cert(card.icc_pubkey_cert)
        .verify::<ICC_PUBKEY_BYTE_LEN, _, _>([], card.icc_pubkey_exponent, card.static_data_to_authenticate, challenge.today_yymm)
        .key()
        .recover_sdad(card.signed_dynamic_app_data)
        .verify(FMT_SDAD_DDA, challenge.nonce)
        .reveal(trust_anchors.bin_root, challenge, bin_membership)
}
