//! Use case 4, card attributes from a BIN table: a free trial for consumer cards that aren't
//! prepaid. The verifier asks only for the card type and whether the card is commercial; it
//! learns neither the country, nor the brand, nor the BIN.
//!
//! `cargo run --release --example bin_attributes`, after `nargo compile --workspace` in
//! `circuits/`.

mod common;

use common::{ORIGIN, ZERO_USD, bins, check, phone, setup, today};
use emv::{CardType, Challenge, Disclosure, Scheme, Scope, Verified};

fn main() -> emv::Result<()> {
    // The verifier pins the root of a table it trusts; the phone holds the table itself.
    let root = bins()?.root();
    println!("BIN table root 0x{}", const_hex::encode(&root.to_bytes()));

    for scheme in [Scheme::VisaFdda, Scheme::MastercardDda] {
        let (pk, vk, table) = setup(scheme)?;
        let challenge = match scheme {
            Scheme::VisaFdda => Challenge::visa_fdda(ORIGIN, Scope::Verifier, today()?, ZERO_USD)?,
            Scheme::MastercardDda => Challenge::mastercard_dda(ORIGIN, Scope::Verifier, today()?)?,
        }
        .disclose(root, Disclosure::CARD_TYPE | Disclosure::COMMERCIAL);

        let response = phone(&pk, &challenge.to_bytes(), ORIGIN)?;
        let Verified { bin, .. } = check(&vk, &table, challenge, &response)?;
        assert_eq!((bin.country, bin.brand), (None, None));

        let outcome = match (bin.card_type, bin.commercial) {
            (Some(CardType::Prepaid), _) => "❗ refused: prepaid",
            (_, Some(true)) => "❗ refused: commercial",
            _ => "✅ trial granted",
        };
        let card_type = match bin.card_type {
            Some(CardType::Credit) => "credit",
            Some(CardType::Debit) => "debit",
            Some(CardType::Prepaid) => "prepaid",
            None => "unknown",
        };
        let holder = if bin.commercial == Some(true) { "commercial" } else { "consumer" };
        println!("{scheme:?}: {card_type}, {holder} card, country and brand undisclosed. {outcome}");
    }

    Ok(())
}
