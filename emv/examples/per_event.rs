//! Use case 3, once per card per event: a vote per card in each poll. Votes in different
//! polls carry unrelated nullifiers, so they don't link.
//!
//! `cargo run --release --example per_event`, after `nargo compile --workspace` in
//! `circuits/`.

mod common;

use std::collections::HashSet;

use common::{ORIGIN, ZERO_USD, check, phone, setup, today};
use emv::{Challenge, Nullifier, Scope};

fn short(n: Nullifier) -> String {
    const_hex::encode(&n.to_bytes()[..8])
}

/// The event's identifier: here its name, zero-padded; a hash of it works as well.
fn poll(name: &str) -> Scope {
    let mut id = [0; 32];
    id[..name.len()].copy_from_slice(name.as_bytes());
    Scope::Event(id)
}

fn main() -> emv::Result<()> {
    let (pk, vk, table) = setup()?;
    // In production, a unique database column over (poll, nullifier).
    let mut voted = HashSet::new();

    for name in ["poll-2026-10", "poll-2026-10", "poll-2026-11"] {
        let challenge = Challenge::visa_fdda(ORIGIN, poll(name), today()?, ZERO_USD)?;
        let response = phone(&pk, &challenge.to_bytes(), ORIGIN)?;
        let nullifier = check(&vk, &table, challenge, &response)?.expect("an event scope gives a nullifier");

        let outcome = if voted.insert((name, nullifier)) {
            "vote counted"
        } else {
            "refused: this card already voted"
        };

        println!("{name}: nullifier {}.. {outcome}", short(nullifier));
    }

    Ok(())
}
