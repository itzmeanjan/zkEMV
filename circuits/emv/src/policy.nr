global NIBBLE_PAD: u8 = 0xF;

pub(crate) fn nibbles(b: u8) -> (u8, u8) {
    (b >> 4, b & 0xF)
}

fn bcd(b: u8) -> u32 {
    let (hi, lo) = nibbles(b);
    assert(hi <= 9, "invalid BCD digit");
    assert(lo <= 9, "invalid BCD digit");
    (hi as u32) * 10 + (lo as u32)
}

/// `expiry` is MMYY BCD, `today` the integer YYMM. Valid through the expiry month
/// (Book 2); two-digit years hold until 2100.
pub fn assert_not_expired(expiry: [u8; 2], today: u32) {
    let month = bcd(expiry[0]);
    let year = bcd(expiry[1]);
    assert((month >= 1) & (month <= 12), "invalid expiry month");
    assert(year * 100 + month >= today, "certificate expired");
}

/// Book 2, 6.3 step 6.
pub fn assert_issuer_id_matches_pan(issuer_id: [u8; 4], pan: [u8; 10]) {
    let mut padding = false;
    for i in 0..4 {
        let (id_hi, id_lo) = nibbles(issuer_id[i]);
        let (pan_hi, pan_lo) = nibbles(pan[i]);

        let id = [id_hi, id_lo];
        let digits = [pan_hi, pan_lo];

        for j in 0..2 {
            let digit = 2 * i + j;
            if id[j] == NIBBLE_PAD {
                assert(digit >= 3, "issuer identifier is shorter than 3 digits");
                padding = true;
            } else {
                assert(!padding, "issuer identifier has digits after its padding");
                assert_eq(id[j], digits[j], "issuer identifier does not match PAN");
            }
        }
    }
}
