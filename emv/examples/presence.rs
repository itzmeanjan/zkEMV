//! Use case 1, card presence: a genuine card was tapped just now, and nothing links one
//! visit to another. For anti-bot friction or a step-up check.
//!
//! `cargo run --release --example presence`, after `nargo compile --workspace` in `circuits/`.

mod common;

use common::{ORIGIN, ZERO_USD, check, phone, setup, today};
use emv::{Challenge, Scope};

fn main() -> emv::Result<()> {
    let (pk, vk, table) = setup()?;

    for visit in 1..=2 {
        let challenge = Challenge::visa_fdda(ORIGIN, Scope::Unlinkable, today()?, ZERO_USD)?;
        let response = phone(&pk, &challenge.to_bytes(), ORIGIN)?;

        // The phone drew the scope, so the verifier gets no nullifier.
        let nullifier = check(&vk, &table, challenge, &response)?;
        assert!(nullifier.is_none());
        println!("visit {visit}: a genuine card was tapped");
    }

    println!("The verifier learnt that a card was present twice, and nothing linking the visits.");
    Ok(())
}
