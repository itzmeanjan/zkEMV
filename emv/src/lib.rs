//! Proves, in zero knowledge, that a genuine EMV contactless card signed a challenge nonce,
//! using the Noir circuits in this repository's `circuits/` and the ProveKit proving system.
//!
//! ```text
//! verifier                                     prover (holds the card)
//! --------                                     -----------------------
//! Challenge::visa_fdda / mastercard_dda
//! keeps it, sends Challenge::to_bytes  ----->  Challenge::from_bytes
//!                                              taps the card with the challenge's nonce
//!                                              ProvingKey::prove(&challenge, ca, &card)
//! VerifyingKey::verify(challenge, ca, &proof) <-----  Proof::to_bytes()
//! ```
//!
//! If [`VerifyingKey::verify`] succeeds, then, without revealing card data:
//!
//! - `ca` signed the issuer certificate, the issuer key signed the ICC certificate, and
//!   the ICC key signed the challenge's nonce (for Visa, also the amount and currency);
//! - neither certificate expired before the challenge's month;
//! - the issuer identifier matches the start of the PAN.
//!
//! Not checked: CA key expiry and revocation, issuer certificate revocation. A proof doesn't
//! identify the card, so one card can produce any number of accepted proofs.
//!
//! # Usage
//!
//! 1. Once per [`Scheme`]: call [`prepare`]. Give the proving key to provers and the
//!    verifying key to verifiers.
//! 2. Verifier: issue a [`Challenge`] for the current month, keep it, and send its bytes.
//! 3. Prover: tap the card with the challenge's nonce as `9F37` (for Visa, also its amount
//!    and currency in the PDOL), then call [`ProvingKey::prove`]. Send the proof and the
//!    card's RID and `8F`.
//! 4. Verifier: get the CA modulus from its trusted table by that RID and `8F`, and call
//!    [`VerifyingKey::verify`] with the issued challenge.
//!
//! Disable debug assertions for dependencies; see [`Proof::to_bytes`].
//!
//! No function panics. A panic inside ProveKit is returned as [`Error::ProveKit`], which
//! requires `panic = "unwind"` (Cargo's default).
//!
//! ```no_run
//! use emv::{Card, Challenge, Issued, Proof, ProvingKey, VerifyingKey, YearMonth};
//!
//! fn issue(today: YearMonth) -> emv::Result<(Challenge<Issued>, Vec<u8>)> {
//!     let challenge = Challenge::mastercard_dda(today)?;
//!     let bytes = challenge.to_bytes();
//!     Ok((challenge, bytes))
//! }
//!
//! fn prover(pk: &ProvingKey, challenge: &[u8], ca_modulus: &[u8], card: &Card) -> emv::Result<Vec<u8>> {
//!     pk.prove(&Challenge::from_bytes(challenge)?, ca_modulus, card)?.to_bytes()
//! }
//!
//! fn verifier(vk: &VerifyingKey, challenge: Challenge<Issued>, ca_modulus: &[u8], proof: &[u8]) -> emv::Result<()> {
//!     vk.verify(challenge, ca_modulus, &Proof::from_bytes(proof)?)
//! }
//! ```

#![forbid(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod card;
mod challenge;
mod error;
mod keys;
mod scheme;
mod witness;

pub use card::{Card, MastercardDda, VisaFdda};
pub use challenge::{Challenge, Issued, Received, Transaction, YearMonth};
pub use error::{Error, Result};
pub use keys::{Proof, ProvingKey, VerifyingKey, prepare};
pub use scheme::Scheme;
