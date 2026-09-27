use crate::Scheme;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The card is for a different scheme than the key.
    #[error("{key:?} key used with {data:?} data")]
    SchemeMismatch { key: Scheme, data: Scheme },

    /// A byte field has the wrong length for the scheme.
    #[error("{field} must be {expected} bytes, got {actual}")]
    Length {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    /// The card data can't be proved: a certificate doesn't recover to a key of the
    /// scheme's width, or the static data is too long.
    #[error("invalid card data: {0}")]
    Card(&'static str),

    /// The transaction is missing for Visa or present for Mastercard.
    #[error("invalid statement: {0}")]
    Statement(&'static str),

    /// The proof is for different public inputs than the statement.
    #[error("the proof's public inputs are not this statement")]
    StatementMismatch,

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
