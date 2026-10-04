//! Use case 2, once per card per verifier: a free trial one card can claim once.
//! Another verifier sees an unrelated nullifier, so the two can't link the card.
//!
//! `cargo run --release --example per_verifier`, after `nargo compile --workspace` in
//! `circuits/`.

mod common;

use std::collections::HashSet;

use common::{ORIGIN, ZERO_USD, check, phone, setup, today};
use emv::{Challenge, Nullifier, Scheme, Scope};

fn short(n: Nullifier) -> String {
    const_hex::encode(&n.to_bytes()[..8])
}

fn main() -> emv::Result<()> {
    let (pk, vk, table) = setup(Scheme::VisaFdda)?;
    // The verifier's record of claimed trials; in production, a unique database column.
    let mut claimed = HashSet::new();

    for attempt in 1..=2 {
        let challenge = Challenge::visa_fdda(ORIGIN, Scope::Verifier, today()?, ZERO_USD)?;
        let response = phone(&pk, &challenge.to_bytes(), ORIGIN)?;
        let nullifier = check(&vk, &table, challenge, &response)?.nullifier.expect("a verifier scope gives a nullifier");

        let outcome = if claimed.insert(nullifier) {
            "trial granted"
        } else {
            "refused: this card already claimed it"
        };

        println!("attempt {attempt}: nullifier {}.. {outcome}", short(nullifier));
    }

    // The same card at another verifier.
    let other = "other.example";
    let challenge = Challenge::visa_fdda(other, Scope::Verifier, today()?, ZERO_USD)?;
    let response = phone(&pk, &challenge.to_bytes(), other)?;
    let nullifier = check(&vk, &table, challenge, &response)?.nullifier.expect("a verifier scope gives a nullifier");

    assert!(!claimed.contains(&nullifier));
    println!("{other}: nullifier {}.., unrelated to {ORIGIN}'s", short(nullifier));

    Ok(())
}
