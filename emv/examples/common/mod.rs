//! Shared by the examples: `visa_fdda` keys, the test CA table, a phone that proves with the
//! mock card, and the verifier's check.

#[path = "../../tests/common/mock.rs"]
mod mock;

use emv::{CaTable, Challenge, Issued, Nullifier, Proof, ProvingKey, Scheme, Transaction, VerifyingKey, YearMonth, prepare};
use time::OffsetDateTime;

/// The verifier's origin: it issues challenges under it, and the phone authenticates it.
pub(crate) const ORIGIN: &str = "verifier.example";

/// Zero USD: no money moves.
pub(crate) const ZERO_USD: Transaction = Transaction {
    amount: [0; 6],
    currency: [0x08, 0x40],
};

/// The current month, UTC.
pub(crate) fn today() -> emv::Result<YearMonth> {
    let now = OffsetDateTime::now_utc();
    YearMonth::new(u16::try_from(now.year()).expect("the year is positive"), now.month().into())
}

/// Keys from `circuits/target/visa_fdda.json`, prepared once per deployment. The test CA
/// table, which the mock card chains to; a real verifier loads a table of real keys.
pub(crate) fn setup() -> emv::Result<(ProvingKey, VerifyingKey, CaTable)> {
    let (pk, vk) = prepare(&mock::compiled(Scheme::VisaFdda))?;
    Ok((pk, vk, mock::test_ca_table()))
}

/// What the phone sends back: the proof, and the CA key the card names.
pub(crate) struct Response {
    proof: Vec<u8>,
    rid: [u8; 5],
    index: u8,
}

/// The phone: reads the challenge from the verifier it authenticated as `origin`, taps the
/// card with the challenge's nonce, and proves. The mock card stands in for the tap.
pub(crate) fn phone(pk: &ProvingKey, challenge: &[u8], origin: &str) -> emv::Result<Response> {
    let challenge = Challenge::from_bytes(challenge, origin)?;
    let (ca, card) = mock::tap(&challenge);
    Ok(Response {
        proof: pk.prove(&challenge, &ca, &card)?.to_bytes()?,
        rid: Scheme::VisaFdda.rid(),
        // The mock card's `8F`: the test CA key in `circuits/fixtures/test-ca-keys.json`.
        index: 0xEE,
    })
}

/// The verifier: looks up the CA key the card names in its own table, then verifies.
pub(crate) fn check(vk: &VerifyingKey, table: &CaTable, challenge: Challenge<Issued>, response: &Response) -> emv::Result<Option<Nullifier>> {
    let ca = table.lookup(&challenge, response.rid, response.index)?;
    vk.verify(challenge, &ca, &Proof::from_bytes(&response.proof)?)
}
