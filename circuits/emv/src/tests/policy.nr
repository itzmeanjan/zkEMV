use crate::policy::{assert_issuer_id_matches_pan, assert_not_expired};

// Expiry is MMYY BCD; today is YYMM.

#[test]
fn expiry_later_year_ok() {
    assert_not_expired([0x10, 0x30], 2609);
}

#[test]
fn expiry_same_month_ok() {
    assert_not_expired([0x09, 0x26], 2609);
}

#[test(should_fail_with = "certificate expired")]
fn expiry_previous_month_fails() {
    assert_not_expired([0x08, 0x26], 2609);
}

#[test(should_fail_with = "certificate expired")]
fn expiry_later_month_earlier_year_fails() {
    assert_not_expired([0x12, 0x25], 2609);
}

#[test(should_fail_with = "invalid expiry month")]
fn expiry_month_13_fails() {
    assert_not_expired([0x13, 0x30], 2609);
}

#[test(should_fail_with = "invalid BCD digit")]
fn expiry_non_bcd_fails() {
    assert_not_expired([0x0A, 0x30], 2609);
}

global PAN: [u8; 10] = [0x43, 0x35, 0x87, 0x12, 0x34, 0x56, 0x78, 0x90, 0xFF, 0xFF];

#[test]
fn issuer_id_six_digits_ok() {
    assert_issuer_id_matches_pan([0x43, 0x35, 0x87, 0xFF], PAN);
}

#[test]
fn issuer_id_eight_digits_ok() {
    assert_issuer_id_matches_pan([0x43, 0x35, 0x87, 0x12], PAN);
}

#[test]
fn issuer_id_three_digits_ok() {
    assert_issuer_id_matches_pan([0x43, 0x3F, 0xFF, 0xFF], PAN);
}

#[test(should_fail_with = "issuer identifier does not match PAN")]
fn issuer_id_wrong_bin_fails() {
    assert_issuer_id_matches_pan([0x43, 0x35, 0x88, 0xFF], PAN);
}

#[test(should_fail_with = "issuer identifier is shorter than 3 digits")]
fn issuer_id_two_digits_fails() {
    assert_issuer_id_matches_pan([0x43, 0xFF, 0xFF, 0xFF], PAN);
}

#[test(should_fail_with = "issuer identifier has digits after its padding")]
fn issuer_id_digit_after_padding_fails() {
    assert_issuer_id_matches_pan([0x43, 0x35, 0xF7, 0xFF], PAN);
}
