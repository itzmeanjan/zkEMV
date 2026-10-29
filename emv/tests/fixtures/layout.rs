//! EMV sizes and the Book 2 recovered-data values, named as in `circuits/emv/src/card_chain.nr`.

pub(crate) const BITS_PER_BYTE: usize = 8;
pub(crate) const NIBBLES_PER_BYTE: usize = 2;
pub(crate) const NIBBLE_PAD: char = 'F';
pub(crate) const DECIMAL_BASE: u32 = 10;

pub(crate) const RSA_EXPONENT: u8 = 3;
pub(crate) const HASH_ALG_SHA1: u8 = 0x01;
pub(crate) const PK_ALG_RSA: u8 = 0x01;

pub(crate) const RECOVERED_DATA_HEADER: u8 = 0x6A;
pub(crate) const RECOVERED_DATA_TRAILER: u8 = 0xBC;
pub(crate) const PAD_BYTE: u8 = 0xBB;
pub(crate) const FMT_ISSUER_CERT: u8 = 0x02;
pub(crate) const FMT_ICC_CERT: u8 = 0x04;
pub(crate) const FMT_SDAD_DDA: u8 = 0x05;
pub(crate) const VISA_FMT_SDAD_FDDA: u8 = 0x95;

pub(crate) const NONCE_BYTE_LEN: usize = 4;
pub(crate) const AMOUNT_AUTHORISED_BYTE_LEN: usize = 6;
pub(crate) const ISSUER_ID_BYTE_LEN: usize = 4;
pub(crate) const SERIAL_BYTE_LEN: usize = 3;
pub(crate) const PAN_BYTE_LEN: usize = 10;

const HEADER_BYTE_LEN: usize = 1;
const HASH_BYTE_LEN: usize = 20;
const TRAILER_BYTE_LEN: usize = 1;
pub(crate) const ENVELOPE_BYTE_LEN: usize = HEADER_BYTE_LEN + HASH_BYTE_LEN + TRAILER_BYTE_LEN;

// BER-TLV.
pub(crate) const RECORD_TEMPLATE_TAG: u8 = 0x70;
pub(crate) const BER_LONG_LENGTH_FLAG: u8 = 0x80;
pub(crate) const STATUS_WORD_SUCCESS: [u8; 2] = [0x90, 0x00];
pub(crate) const AIP_TAG_LIST: [u8; 1] = [0x82];
