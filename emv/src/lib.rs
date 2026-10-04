//! Proves, in zero knowledge, that a genuine EMV contactless card signed a challenge nonce,
//! using the Noir circuits in this repository's `circuits/` and the ProveKit proving system.
//!
//! ```text
//! verifier (origin)                            prover (holds the card)
//! -----------------                            -----------------------
//! Challenge::visa_fdda / mastercard_dda
//! [.disclose(bin_root, disclosure)]
//! keeps it, sends Challenge::to_bytes  ----->  Challenge::from_bytes(bytes, origin)
//!                                              taps the card with the challenge's nonce
//!                                              CaTable::lookup(&challenge, rid, 8F) -> ca
//!                                              ProvingKey::prove(&challenge, &ca, &card, bins)
//! CaTable::lookup(&challenge, rid, 8F) -> ca  <-----  Proof::to_bytes(), rid, 8F
//! VerifyingKey::verify(challenge, &ca, &proof) -> nullifier, BIN attributes
//! ```
//!
//! If [`VerifyingKey::verify`] succeeds, then, without revealing card data:
//!
//! - the trusted CA key `ca` signed the issuer certificate, the issuer key signed the ICC
//!   certificate, and the ICC key signed the challenge's nonce (for Visa, also the amount
//!   and currency);
//! - neither certificate expired before the challenge's month;
//! - the issuer identifier matches the start of the PAN;
//! - the returned [`Nullifier`] is the card's in the challenge's [`Scope`]: the same for
//!   every proof of that card in that scope, and unrelated otherwise;
//! - if the challenge asks for BIN attributes ([`Challenge::disclose`]), the PAN's first 12
//!   digits are in a range of the [`BinTable`] with the challenge's root, and the returned
//!   [`Disclosed`] holds that range's attributes the challenge asked for.
//!
//! Not checked: CA key and issuer certificate revocation.
//!
//! # Usage
//!
//! 1. Once per [`Scheme`]: call [`prepare`]. Give the proving key to provers and the
//!    verifying key to verifiers.
//! 2. Verifier: issue a [`Challenge`] for its origin, a [`Scope`] and the current month, and
//!    optionally ask for BIN attributes under the root of a table it trusts; keep it, and
//!    send its bytes.
//! 3. Prover: read the challenge with the origin it authenticated the verifier by. Tap the
//!    card with the challenge's nonce as `9F37` (for Visa, also its amount and currency in
//!    the PDOL), look up the CA key the card names, then call [`ProvingKey::prove`] with
//!    the BIN table of the challenge's root, if it has one. Send the proof and the card's
//!    RID and `8F`.
//! 4. Verifier: look up that RID and `8F` in its [`CaTable`] for the issued challenge, and
//!    call [`VerifyingKey::verify`] with both. The table decides which CA keys are trusted.
//!
//! Disable debug assertions for dependencies; see [`Proof::to_bytes`].
//!
//! No function panics. A panic inside ProveKit is returned as [`Error::ProveKit`], which
//! requires `panic = "unwind"` (Cargo's default).
//!
//! ```no_run
//! use emv::{BinRoot, BinTable, CaTable, Card, Challenge, Disclosure, Issued, Proof, ProvingKey, Scope, Verified, VerifyingKey, YearMonth};
//!
//! fn issue(today: YearMonth, bin_root: BinRoot) -> emv::Result<(Challenge<Issued>, Vec<u8>)> {
//!     let challenge = Challenge::mastercard_dda("verifier.example", Scope::Verifier, today)?
//!         .disclose(bin_root, Disclosure::COUNTRY | Disclosure::CARD_TYPE);
//!     let bytes = challenge.to_bytes();
//!     Ok((challenge, bytes))
//! }
//!
//! fn prover(pk: &ProvingKey, table: &CaTable, bins: &BinTable, challenge: &[u8], rid: [u8; 5], index: u8, card: &Card) -> emv::Result<Vec<u8>> {
//!     let challenge = Challenge::from_bytes(challenge, "verifier.example")?;
//!     let ca = table.lookup(&challenge, rid, index)?;
//!     pk.prove(&challenge, &ca, card, Some(bins))?.to_bytes()
//! }
//!
//! fn verifier(vk: &VerifyingKey, table: &CaTable, challenge: Challenge<Issued>, rid: [u8; 5], index: u8, proof: &[u8]) -> emv::Result<Verified> {
//!     let ca = table.lookup(&challenge, rid, index)?;
//!     vk.verify(challenge, &ca, &Proof::from_bytes(proof)?)
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

mod bin_table;
mod ca;
mod card;
mod challenge;
mod disclosure;
mod error;
mod keys;
mod layout;
mod nullifier;
mod pan;
mod scheme;
mod witness;

pub use bin_table::{Attributes, BinRoot, BinTable, CardType, Change, PAN_PREFIX_DIGIT_COUNT, Range};
pub use ca::{CaKey, CaTable};
pub use card::{Card, MastercardDda, VisaFdda};
pub use challenge::{Challenge, Issued, Received, Scope, Transaction, YearMonth};
pub use disclosure::{Disclosed, Disclosure};
pub use error::{Error, Result};
pub use keys::{Proof, ProvingKey, Verified, VerifyingKey, prepare};
pub use nullifier::Nullifier;
pub use scheme::Scheme;
