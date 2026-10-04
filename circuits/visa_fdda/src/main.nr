//! Visa contactless card, fast Dynamic Data Authentication (fDDA): proves a genuine Visa chip signed the verifier's nonce.

mod tests;

use emv::{BinMembership, BITS_PER_BYTE, CA_PUBKEY_BYTE_LEN, CaKey, Challenge, concat, Revealed, Transaction, TrustAnchors, VISA_FMT_SDAD_FDDA};

global ISSUER_PUBKEY_BIT_LEN: u32 = 1408;
global ISSUER_PUBKEY_BYTE_LEN: u32 = ISSUER_PUBKEY_BIT_LEN / BITS_PER_BYTE;

global ICC_PUBKEY_BIT_LEN: u32 = 1024;
global ICC_PUBKEY_BYTE_LEN: u32 = ICC_PUBKEY_BIT_LEN / BITS_PER_BYTE;

global CARD_AUTH_RELATED_DATA_BYTE_LEN: u32 = 7;
global STATIC_DATA_MAX_BYTE_LEN: u32 = 0;

/// The card's data from the tap.
pub struct Card {
    pub issuer_pubkey_cert: [u8; CA_PUBKEY_BYTE_LEN],
    pub issuer_pubkey_exponent: u8,
    pub icc_pubkey_cert: [u8; ISSUER_PUBKEY_BYTE_LEN],
    pub icc_pubkey_exponent: u8,
    pub signed_dynamic_app_data: [u8; ICC_PUBKEY_BYTE_LEN],
    pub card_auth_related_data: [u8; CARD_AUTH_RELATED_DATA_BYTE_LEN],
}

fn main(trust_anchors: pub TrustAnchors, challenge: pub Challenge, transaction: pub Transaction, card: Card, bin_membership: BinMembership) -> pub Revealed {
    let terminal_data = concat(
        concat(
            concat(challenge.nonce, transaction.amount_authorised),
            transaction.currency_code,
        ),
        card.card_auth_related_data,
    );

    CaKey::from_limbs(trust_anchors.ca_modulus)
        .recover_issuer_cert(card.issuer_pubkey_cert)
        .verify::<ISSUER_PUBKEY_BYTE_LEN, _>([], card.issuer_pubkey_exponent, challenge.today_yymm)
        .key()
        .recover_icc_cert(card.icc_pubkey_cert)
        .verify::<ICC_PUBKEY_BYTE_LEN, _, _>([], card.icc_pubkey_exponent, BoundedVec::<u8, STATIC_DATA_MAX_BYTE_LEN>::new(), challenge.today_yymm)
        .key()
        .recover_sdad(card.signed_dynamic_app_data)
        .verify(VISA_FMT_SDAD_FDDA, terminal_data)
        .reveal(trust_anchors.bin_root, challenge, bin_membership)
}
