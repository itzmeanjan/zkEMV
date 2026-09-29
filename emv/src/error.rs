use crate::Scheme;

/// Result of this crate's functions.
pub type Result<T> = std::result::Result<T, Error>;

/// Error of this crate's functions.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The card or challenge is for a different scheme than the key.
    #[error("{key:?} key used with {data:?} data")]
    SchemeMismatch {
        /// The key's scheme.
        key: Scheme,
        /// The card's or challenge's scheme.
        data: Scheme,
    },

    /// Not a month of the years 2000 to 2099.
    #[error("{year}-{month:02} is not a month of the years 2000 to 2099")]
    YearMonth {
        /// The given year.
        year: u16,
        /// The given month.
        month: u8,
    },

    /// The bytes are not a challenge from [`Challenge::to_bytes`](crate::Challenge::to_bytes).
    #[error("malformed challenge: {0}")]
    Challenge(&'static str),

    /// The OS random number generator failed to draw a nonce.
    #[error("OS random number generator failed")]
    Rng(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A byte field has the wrong length for the scheme.
    #[error("{field} must be {expected} bytes, got {actual}")]
    Length {
        /// Field name.
        field: &'static str,
        /// Required length in bytes.
        expected: usize,
        /// Given length in bytes.
        actual: usize,
    },

    /// The card data can't be proved: a certificate doesn't recover to a key of the
    /// scheme's width, or the static data is too long.
    #[error("invalid card data: {0}")]
    Card(&'static str),

    /// A CA key table is malformed, or a key's checksum doesn't match.
    #[error("invalid CA key table: {0}")]
    CaTable(&'static str),

    /// No trusted CA key fits: unknown, of another scheme, width or exponent, or expired.
    #[error("CA key: {0}")]
    CaKey(&'static str),

    /// The proof is for another challenge or CA key.
    #[error("the proof's public inputs are not this challenge and CA key")]
    PublicInputsMismatch,

    /// The circuit or key is not for any [`Scheme`].
    #[error("not an emv circuit, its parameters are {0:?}")]
    UnknownCircuit(Vec<String>),

    /// The input to [`prepare`](crate::prepare) is not a compiled circuit.
    #[error("reading compiled circuit: {0}")]
    Artifact(#[from] serde_json::Error),

    /// ProveKit failed. In `prove`: the inputs fail a circuit constraint, e.g. wrong nonce,
    /// expired certificate, invalid signature, wrong exponent, or wrong field length. In
    /// `verify`: the proof is invalid. In `from_bytes`: unknown format or version.
    #[error("{0:#}")]
    ProveKit(#[from] anyhow::Error),
}
