//! Sizes shared across the crate, named as in the circuits.

pub(crate) const BITS_PER_BYTE: usize = 8;
pub(crate) const BYTE_TOP_BIT: u8 = 1 << (BITS_PER_BYTE - 1);
pub(crate) const NIBBLE_BIT_LEN: usize = 4;
pub(crate) const NIBBLES_PER_BYTE: usize = BITS_PER_BYTE / NIBBLE_BIT_LEN;
pub(crate) const NIBBLE_MASK: u8 = (1 << NIBBLE_BIT_LEN) - 1;
pub(crate) const BINARY_BASE: u64 = 2;
pub(crate) const DECIMAL_BASE: u64 = 10;
pub(crate) const MAX_DECIMAL_DIGIT: u64 = DECIMAL_BASE - 1;

pub(crate) const RSA_EXPONENT: u8 = 3;
pub(crate) const RID_BYTE_LEN: usize = 5;
pub(crate) const NONCE_BYTE_LEN: usize = 4;
pub(crate) const AMOUNT_AUTHORISED_BYTE_LEN: usize = 6;
pub(crate) const CURRENCY_CODE_BYTE_LEN: usize = 2;

/// A BN254 scalar, big-endian.
pub(crate) const FIELD_BYTE_LEN: usize = 32;
