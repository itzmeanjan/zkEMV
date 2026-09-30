//! Visa contactless card, fast Dynamic Data Authentication (fDDA): proves a genuine Visa chip signed the verifier's nonce.

mod tests;

use emv::{assert_issuer_id_matches_pan, assert_not_expired, FMT_SDAD_FDDA, nullifier, RsaKey, verify_icc_cert, verify_issuer_cert, verify_sdad};

global CA_BITS: u32 = 1984;
/// 120-bit limbs of the CA modulus.
global CA_N: u32 = 17;
global ISSUER_BITS: u32 = 1408;
global ICC_BITS: u32 = 1024;

/// Card Authentication Related Data (`9F69`) on the Visa cards in the corpus.
global CARD_AUTH_LEN: u32 = 7;
/// fDDA terminal data: `9F37 || 9F02 || 5F2A || 9F69`.
global TERMINAL_DATA_LEN: u32 = 4 + 6 + 2 + CARD_AUTH_LEN;

pub struct Inputs {
    pub ca_modulus: [Field; CA_N],
    pub nonce: [u8; 4],
    pub amount: [u8; 6],
    pub currency: [u8; 2],
    pub today: u32,
    pub scope: Field,
    pub issuer_cert: [u8; CA_BITS / 8],
    pub issuer_exponent: u8,
    pub icc_cert: [u8; ISSUER_BITS / 8],
    pub icc_exponent: u8,
    pub sdad: [u8; ICC_BITS / 8],
    pub card_auth_data: [u8; CARD_AUTH_LEN],
}

fn main(
    // The verifier must check this is in its CA table.
    ca_modulus: pub [Field; CA_N],
    // Unpredictable Number (9F37): the verifier's challenge.
    nonce: pub [u8; 4],
    // Amount Authorised (9F02) and Transaction Currency Code (5F2A) sent in the PDOL.
    amount: pub [u8; 6],
    currency: pub [u8; 2],
    // YYMM
    today: pub u32,
    // Chosen by the verifier, or at random by the prover when the verifier needs no nullifier.
    scope: pub Field,
    issuer_cert: [u8; CA_BITS / 8], // 90
    issuer_exponent: u8, // 9F32
    icc_cert: [u8; ISSUER_BITS / 8], // 9F46
    icc_exponent: u8, // 9F47
    sdad: [u8; ICC_BITS / 8], // 9F4B
    card_auth_data: [u8; CARD_AUTH_LEN], // 9F69
) -> pub Field {
    verify(
        Inputs { ca_modulus, nonce, amount, currency, today, scope, issuer_cert, issuer_exponent, icc_cert, icc_exponent, sdad, card_auth_data },
    )
}

fn verify(x: Inputs) -> Field {
    let ca_key = RsaKey::<CA_BITS / 8>::from_limbs(x.ca_modulus);

    let issuer = verify_issuer_cert::<_, ISSUER_BITS / 8, _>(ca_key.recover(x.issuer_cert), [], x.issuer_exponent);
    let issuer_key: RsaKey<ISSUER_BITS / 8> = RsaKey::from_be_bytes(issuer.modulus);

    let icc = verify_icc_cert::<_, ICC_BITS / 8, _, _>(
        issuer_key.recover(x.icc_cert),
        [],
        x.icc_exponent,
        BoundedVec::<u8, 0>::new(),
    );
    let icc_key: RsaKey<ICC_BITS / 8> = RsaKey::from_be_bytes(icc.modulus);

    assert_issuer_id_matches_pan(issuer.issuer_id, icc.pan);
    assert_not_expired(issuer.expiry, x.today);
    assert_not_expired(icc.expiry, x.today);

    let mut terminal_data = [0; TERMINAL_DATA_LEN];
    for i in 0..4 {
        terminal_data[i] = x.nonce[i];
    }
    for i in 0..6 {
        terminal_data[4 + i] = x.amount[i];
    }
    for i in 0..2 {
        terminal_data[10 + i] = x.currency[i];
    }
    for i in 0..CARD_AUTH_LEN {
        terminal_data[12 + i] = x.card_auth_data[i];
    }
    verify_sdad(icc_key.recover(x.sdad), FMT_SDAD_FDDA, terminal_data);

    nullifier(icc.modulus, x.scope)
}
