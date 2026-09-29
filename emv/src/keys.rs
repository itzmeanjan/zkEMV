use std::panic::{AssertUnwindSafe, catch_unwind};

use noirc_artifacts::program::ProgramArtifact;
use provekit_common::{
    NoirProof, NoirProofScheme, Prover, Verifier,
    file::{deserialize, serialize},
};
use provekit_prover::Prove;
use provekit_r1cs_compiler::NoirProofSchemeBuilder;
use provekit_verifier::Verify;

use crate::{
    Card, Challenge, Error, Issued, Received, Result, Scheme,
    witness::{input_map, public_input_map, public_inputs},
};

/// Builds the key pair for a compiled circuit.
///
/// `compiled_circuit` is the JSON that `nargo compile` (nargo 1.0.0-beta.26) writes to
/// `target/<pkg>.json` for the `visa_fdda` or `mastercard_dda` package. The scheme is detected from the circuit's parameters.
///
/// Deterministic and slow. Run it once and distribute the keys with `to_bytes`.
///
/// # Errors
///
/// - [`Error::Artifact`]: not a compiled circuit.
/// - [`Error::UnknownCircuit`]: not a circuit of any [`Scheme`].
/// - [`Error::ProveKit`]: ProveKit can't compile the circuit.
pub fn prepare(compiled_circuit: &[u8]) -> Result<(ProvingKey, VerifyingKey)> {
    let program: ProgramArtifact = serde_json::from_slice(compiled_circuit)?;
    let scheme = Scheme::from_abi(&program.abi)?;
    let noir_scheme = provekit(|| NoirProofScheme::from_program(program))?;
    Ok((
        ProvingKey {
            scheme,
            prover: Prover::from_noir_proof_scheme(noir_scheme.clone()),
        },
        VerifyingKey {
            scheme,
            verifier: Verifier::from_noir_proof_scheme(noir_scheme),
        },
    ))
}

/// Proving key for one [`Scheme`]. Public.
#[derive(Clone, Debug)]
pub struct ProvingKey {
    scheme: Scheme,
    prover: Prover,
}

impl ProvingKey {
    /// The scheme this key proves.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Proves that `card` signed `challenge`.
    ///
    /// `ca_modulus` is the CA RSA modulus, big-endian, 248 bytes, that the card names by
    /// RID (first 5 bytes of the AID) and index `8F`.
    ///
    /// Blocking and CPU-bound. Runs on rayon's global thread pool. Clones the key.
    ///
    /// # Errors
    ///
    /// - [`Error::SchemeMismatch`]: `challenge` or `card` is for another scheme.
    /// - [`Error::Length`]: `ca_modulus`, `issuer_cert` or `icc_cert` has the wrong length.
    /// - [`Error::Card`]: a certificate doesn't recover to a key of the scheme's width, or
    ///   the static data is too long.
    /// - [`Error::ProveKit`]: the inputs fail a circuit constraint.
    pub fn prove(&self, challenge: &Challenge<Received>, ca_modulus: &[u8], card: &Card) -> Result<Proof> {
        for data in [challenge.scheme(), card.scheme()] {
            if data != self.scheme {
                return Err(Error::SchemeMismatch { key: self.scheme, data });
            }
        }
        let inputs = input_map(challenge.fields(), ca_modulus, card)?;
        provekit(|| self.prover.clone().prove(inputs)).map(Proof)
    }

    /// Serializes to ProveKit's `.pkp` format.
    ///
    /// # Errors
    ///
    /// [`Error::ProveKit`]: encoding failed.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        provekit(|| serialize(&self.prover))
    }

    /// Deserializes the output of [`ProvingKey::to_bytes`] or of `provekit-cli prepare`
    /// 1.0.x.
    ///
    /// # Errors
    ///
    /// - [`Error::ProveKit`]: not a ProveKit prover key of a compatible version.
    /// - [`Error::UnknownCircuit`]: not a key for any [`Scheme`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let prover: Prover = provekit(|| deserialize(bytes))?;
        let scheme = Scheme::from_abi(prover.witness_generator.abi())?;
        Ok(Self { scheme, prover })
    }
}

/// Verifying key for one [`Scheme`]. Public.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    scheme: Scheme,
    verifier: Verifier,
}

impl VerifyingKey {
    /// The scheme this key verifies.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Verifies that `proof` answers `challenge` under `ca_modulus`. `Ok(())` means accept.
    ///
    /// Consumes `challenge`, so it verifies at most one proof. Take `ca_modulus` from a
    /// trusted table, by the RID and `8F` the prover sends.
    ///
    /// ProveKit checks a proof only against the public inputs inside it, so this function
    /// first compares them with `challenge` and `ca_modulus`.
    ///
    /// # Errors
    ///
    /// - [`Error::SchemeMismatch`]: `challenge` is for another scheme.
    /// - [`Error::Length`]: `ca_modulus` has the wrong length.
    /// - [`Error::PublicInputsMismatch`]: the proof is for another challenge or CA key.
    /// - [`Error::ProveKit`]: the proof is invalid.
    pub fn verify(&self, challenge: Challenge<Issued>, ca_modulus: &[u8], proof: &Proof) -> Result<()> {
        if challenge.scheme() != self.scheme {
            return Err(Error::SchemeMismatch {
                key: self.scheme,
                data: challenge.scheme(),
            });
        }
        let expected = public_inputs(&self.verifier.abi, &public_input_map(&challenge.into_fields(), ca_modulus)?)?;
        if proof.0.public_inputs.0 != expected {
            return Err(Error::PublicInputsMismatch);
        }
        // A `Verifier` is consumed by one verification.
        provekit(|| self.verifier.clone().verify(&proof.0))
    }

    /// Serializes to ProveKit's `.pkv` format.
    ///
    /// # Errors
    ///
    /// [`Error::ProveKit`]: encoding failed.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        provekit(|| serialize(&self.verifier))
    }

    /// Deserializes the output of [`VerifyingKey::to_bytes`] or of `provekit-cli prepare`
    /// 1.0.x.
    ///
    /// # Errors
    ///
    /// - [`Error::ProveKit`]: not a ProveKit verifier key of a compatible version.
    /// - [`Error::UnknownCircuit`]: not a key for any [`Scheme`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let verifier: Verifier = provekit(|| deserialize(bytes))?;
        let scheme = Scheme::from_abi(&verifier.abi)?;
        Ok(Self { scheme, verifier })
    }
}

/// A proof. Contains the public inputs and no card data.
#[derive(Clone, Debug, PartialEq)]
pub struct Proof(NoirProof);

impl Proof {
    /// Serializes to ProveKit's `.np` format. The bytes don't identify the scheme; send the
    /// scheme separately.
    ///
    /// If `provekit-common` is built with debug assertions (the default in Cargo's `dev`
    /// and `test` profiles), [`Proof::from_bytes`] fails on every proof. Disable them for
    /// dependencies:
    ///
    /// ```toml
    /// [profile.dev.package."*"]
    /// debug-assertions = false
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::ProveKit`]: encoding failed.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        provekit(|| serialize(&self.0))
    }

    /// Deserializes the output of [`Proof::to_bytes`] or of `provekit-cli prove` 1.0.x.
    /// Doesn't verify the proof.
    ///
    /// # Errors
    ///
    /// [`Error::ProveKit`]: not a ProveKit proof of a compatible version.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        provekit(|| deserialize(bytes)).map(Self)
    }
}

/// Runs a ProveKit call, returning its panics as errors.
fn provekit<T>(f: impl FnOnce() -> anyhow::Result<T>) -> Result<T> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => Ok(result?),
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(ToString::to_string)
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            Err(Error::ProveKit(anyhow::anyhow!("ProveKit panicked: {message}")))
        }
    }
}
