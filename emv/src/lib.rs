//! Proves, in zero knowledge, that a genuine EMV contactless card signed a challenge nonce,
//! using the Noir circuits in this repository's `circuits/` and the ProveKit proving system.
//!
//! ```text
//! verifier                                   prover (holds the card)
//! --------                                   -----------------------
//! picks nonce, today (YYMM), CA key  ----->  taps the card with that nonce
//!                                            ProvingKey::prove(&statement, &card) -> Proof
//! VerifyingKey::verify(&statement, &proof) <-----  Proof::to_bytes()
//! ```
//!
//! If [`VerifyingKey::verify`] succeeds, then, without revealing card data:
//!
//! - `ca_modulus` signed the issuer certificate, the issuer key signed the ICC certificate,
//!   and the ICC key signed the nonce (for Visa, also the amount and currency);
//! - neither certificate expired before `today`;
//! - the issuer identifier matches the start of the PAN.
//!
//! Not checked: CA key expiry and revocation, issuer certificate revocation. A proof doesn't
//! identify the card, so one card can produce any number of accepted proofs.
//!
//! # Usage
//!
//! 1. Once per [`Scheme`]: call [`prepare`]. Give the proving key to provers and the
//!    verifying key to verifiers.
//! 2. Verifier: send a fresh random nonce, `today`, and for Visa the transaction.
//! 3. Prover: tap the card with the nonce as `9F37`, then call [`ProvingKey::prove`]. Send
//!    the proof, the scheme, and the card's RID and `8F`.
//! 4. Verifier: get the CA modulus from its trusted table, build the [`Statement`], and call
//!    [`VerifyingKey::verify`].
//!
//! Disable debug assertions for dependencies; see [`Proof::to_bytes`].
//!
//! No function panics. A panic inside ProveKit is returned as [`Error::ProveKit`], which
//! requires `panic = "unwind"` (Cargo's default).
//!
//! ```no_run
//! use emv::{Card, Proof, ProvingKey, Statement, VerifyingKey};
//!
//! fn prover(pk: &ProvingKey, statement: &Statement, card: &Card) -> emv::Result<Vec<u8>> {
//!     pk.prove(statement, card)?.to_bytes()
//! }
//!
//! fn verifier(vk: &VerifyingKey, statement: &Statement, proof: &[u8]) -> emv::Result<()> {
//!     vk.verify(statement, &Proof::from_bytes(proof)?)
//! }
//! ```

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod card;
mod error;
mod keys;
mod scheme;
mod witness;

pub use card::{Card, MastercardDda, Statement, Transaction, VisaFastDda};
pub use error::{Error, Result};
pub use keys::{Proof, ProvingKey, VerifyingKey, prepare};
pub use scheme::Scheme;
