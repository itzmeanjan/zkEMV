//! EMV Book 2 offline data authentication:
//! CA key -> issuer cert `90` -> ICC cert `9F46` -> SDAD `9F4B`
//!
//! Each RSA (e = 3) with ISO/IEC 9796-2 scheme 1 recovery and SHA-1.
//!
//! `CaKey` starts the chain of states in `card_chain`. Each key width is a type parameter, so a
//! circuit is built per key-width profile.

mod bin_table;
mod bytes;
mod card_chain;
mod interface;
mod nullifier;
mod policy;
mod rsa;
mod sha1;
mod tests;

pub use bin_table::{BinAttributes, BinMembership};
pub use bytes::{BITS_PER_BYTE, concat};
pub use card_chain::{
    AMOUNT_AUTHORISED_BYTE_LEN, AuthenticatedCard, CA_PUBKEY_BYTE_LEN, CA_PUBKEY_LIMB_COUNT, CaKey, CURRENCY_CODE_BYTE_LEN, FMT_SDAD_DDA, IccCert, IccKey,
    ISSUER_CERT_KEY_SPACE_BYTE_LEN, IssuerCert, IssuerKey, NONCE_BYTE_LEN, RecoveredIccCert, RecoveredIssuerCert, RecoveredSdad, VISA_FMT_SDAD_FDDA,
};
pub use interface::{Challenge, Revealed, Transaction, TrustAnchors};
pub use nullifier::nullifier;
