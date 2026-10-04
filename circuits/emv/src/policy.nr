use crate::{bytes::{DECIMAL_BASE, MAX_DECIMAL_DIGIT, NIBBLE_MASK, nibbles, NIBBLES_PER_BYTE}, EXPIRY_BYTE_LEN, ISSUER_ID_BYTE_LEN, PAN_BYTE_LEN};

global NIBBLE_PAD: u8 = NIBBLE_MASK;
global MIN_ISSUER_ID_DIGIT_COUNT: u32 = 3;
global EXPIRY_MONTH_OFFSET: u32 = 0;
global EXPIRY_YEAR_OFFSET: u32 = EXPIRY_MONTH_OFFSET + 1;
global FIRST_MONTH: u32 = 1;
global MONTHS_PER_YEAR: u32 = 12;
global BCD_BYTE_BASE: u32 = DECIMAL_BASE * DECIMAL_BASE;

fn bcd(b: u8) -> u32 {
    let (hi, lo) = nibbles(b);
    assert(hi <= MAX_DECIMAL_DIGIT, "invalid BCD digit");
    assert(lo <= MAX_DECIMAL_DIGIT, "invalid BCD digit");
    (hi as u32) * DECIMAL_BASE + (lo as u32)
}

/// `expiry` is MMYY BCD, `today` the integer YYMM. Valid through the expiry month
/// (Book 2); two-digit years hold until 2100.
pub fn assert_not_expired(expiry: [u8; EXPIRY_BYTE_LEN], today: u32) {
    let month = bcd(expiry[EXPIRY_MONTH_OFFSET]);
    let year = bcd(expiry[EXPIRY_YEAR_OFFSET]);
    assert((month >= FIRST_MONTH) & (month <= MONTHS_PER_YEAR), "invalid expiry month");
    assert(year * BCD_BYTE_BASE + month >= today, "certificate expired");
}

/// Book 2, 6.3 step 6.
pub fn assert_issuer_id_matches_pan(issuer_id: [u8; ISSUER_ID_BYTE_LEN], pan: [u8; PAN_BYTE_LEN]) {
    let mut padding = false;
    for i in 0..ISSUER_ID_BYTE_LEN {
        let (id_hi, id_lo) = nibbles(issuer_id[i]);
        let (pan_hi, pan_lo) = nibbles(pan[i]);

        let id = [id_hi, id_lo];
        let digits = [pan_hi, pan_lo];

        for j in 0..NIBBLES_PER_BYTE {
            let digit = NIBBLES_PER_BYTE * i + j;
            if id[j] == NIBBLE_PAD {
                assert(digit >= MIN_ISSUER_ID_DIGIT_COUNT, "issuer identifier is shorter than 3 digits");
                padding = true;
            } else {
                assert(!padding, "issuer identifier has digits after its padding");
                assert_eq(id[j], digits[j], "issuer identifier does not match PAN");
            }
        }
    }
}
