//! The circuits' public inputs and output.

use crate::{bin_table::BinAttributes, card_chain::{AMOUNT_AUTHORISED_BYTE_LEN, CA_PUBKEY_LIMB_COUNT, CURRENCY_CODE_BYTE_LEN, NONCE_BYTE_LEN}};

/// What the verifier trusts: its CA key for the card's scheme, and its BIN table.
pub struct TrustAnchors {
    pub ca_modulus: [Field; CA_PUBKEY_LIMB_COUNT],
    pub bin_root: Field,
}

/// What the verifier asks in this session.
pub struct Challenge {
    pub nonce: [u8; NONCE_BYTE_LEN],
    pub today_yymm: u32,
    pub scope: Field,
    pub disclosure: u8,
}

/// Visa fDDA's card also signs these.
pub struct Transaction {
    pub amount_authorised: [u8; AMOUNT_AUTHORISED_BYTE_LEN],
    pub currency_code: [u8; CURRENCY_CODE_BYTE_LEN],
}

/// What the verifier learns.
pub struct Revealed {
    pub bin_attributes: BinAttributes,
    pub nullifier: Field,
}
