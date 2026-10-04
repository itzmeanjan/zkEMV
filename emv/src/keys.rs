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
    BinTable, CaKey, Card, Challenge, Disclosed, Error, Issued, Nullifier, Received, Result, Scheme,
    bin_table::Membership,
    pan,
    witness::{input_map, public_input_map, public_inputs, scope_offset},
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

    /// Proves that `card` signed `challenge`, under `ca`: the key the card names, from
    /// [`CaTable::lookup`](crate::CaTable::lookup). If the challenge asks for BIN attributes,
    /// `bins` must be the table with its root; otherwise it is ignored.
    ///
    /// Blocking and CPU-bound. Runs on rayon's global thread pool. Clones the key.
    ///
    /// # Errors
    ///
    /// - [`Error::SchemeMismatch`]: `challenge` or `card` is for another scheme.
    /// - [`Error::CaKey`]: `ca` is for another scheme, or expired before the challenge's
    ///   month.
    /// - [`Error::Length`]: `issuer_pubkey_cert` or `icc_pubkey_cert` has the wrong length.
    /// - [`Error::Card`]: the static data is too long, or, when BIN attributes are asked for,
    ///   a certificate doesn't recover or the PAN has fewer than 12 digits.
    /// - [`Error::BinTable`]: BIN attributes are asked for, but `bins` is `None` or has
    ///   another root.
    /// - [`Error::UnknownBin`]: no range of `bins` holds the card's PAN.
    /// - [`Error::ProveKit`]: the inputs fail a circuit constraint, e.g. a certificate doesn't
    ///   recover to a key of the scheme's width.
    pub fn prove(&self, challenge: &Challenge<Received>, ca: &CaKey, card: &Card, bins: Option<&BinTable>) -> Result<Proof> {
        for data in [challenge.scheme(), card.scheme()] {
            if data != self.scheme {
                return Err(Error::SchemeMismatch { key: self.scheme, data });
            }
        }
        ca.check(challenge.fields())?;
        let scope = challenge.fields().scope_value.ok_or(Error::Challenge("received without a scope"))?;
        let membership = match challenge.bin_root() {
            None => Membership::empty(),
            Some(root) => {
                let table = bins.filter(|t| t.root() == root).ok_or(Error::BinTable("not the challenge's table"))?;
                table.membership(pan::prefix(card, ca.modulus())?).ok_or(Error::UnknownBin)?
            }
        };
        let inputs = input_map(self.prover.witness_generator.abi(), challenge.fields(), ca.modulus(), scope, card, &membership)?;
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

    /// Verifies that `proof` answers `challenge` under `ca`. `Ok` means accept, with what the
    /// proof shows beyond the signature.
    ///
    /// Recognising a repeated nullifier is the caller's job, e.g. a unique database column.
    ///
    /// Consumes `challenge`, so it verifies at most one proof. Get `ca` from
    /// [`CaTable::lookup`](crate::CaTable::lookup) with the RID and `8F` the prover sends.
    ///
    /// ProveKit checks a proof only against the public inputs inside it, so this function
    /// first compares them with `challenge` and `ca`.
    ///
    /// # Errors
    ///
    /// - [`Error::SchemeMismatch`]: `challenge` is for another scheme.
    /// - [`Error::CaKey`]: `ca` is for another scheme, or expired before the challenge's
    ///   month.
    /// - [`Error::PublicInputsMismatch`]: the proof is for another challenge or CA key.
    /// - [`Error::ProveKit`]: the proof is invalid.
    pub fn verify(&self, challenge: Challenge<Issued>, ca: &CaKey, proof: &Proof) -> Result<Verified> {
        if challenge.scheme() != self.scheme {
            return Err(Error::SchemeMismatch {
                key: self.scheme,
                data: challenge.scheme(),
            });
        }
        let challenge = challenge.into_fields();
        ca.check(&challenge)?;
        let carried = &proof.0.public_inputs.0;
        let scope = match challenge.scope_value {
            Some(scope) => scope,
            // The prover drew it; any value is fine.
            None => *carried.get(scope_offset(&self.verifier.abi)?).ok_or(Error::PublicInputsMismatch)?,
        };
        let expected = public_inputs(&self.verifier.abi, &public_input_map(&challenge, ca.modulus(), scope)?)?;
        // `main`'s parameters, then its return value: the BIN attributes and the nullifier.
        let (parameters, outputs) = carried.split_at_checked(expected.len()).ok_or(Error::PublicInputsMismatch)?;
        let &[country, card_type, brand, commercial, nullifier] = outputs else {
            return Err(Error::PublicInputsMismatch);
        };
        if parameters != expected {
            return Err(Error::PublicInputsMismatch);
        }
        let disclosure = challenge.bin.map(|(_, d)| d).unwrap_or_default();
        let bin = Disclosed::from_outputs(disclosure, [country, card_type, brand, commercial]).ok_or(Error::PublicInputsMismatch)?;
        // A `Verifier` is consumed by one verification.
        provekit(|| self.verifier.clone().verify(&proof.0))?;
        Ok(Verified {
            nullifier: challenge.scope_value.map(|_| Nullifier::from_field(nullifier)),
            bin,
        })
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

/// What a verified proof shows beyond the card's signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Verified {
    /// The card's nullifier in the challenge's [`Scope`](crate::Scope); `None` for
    /// [`Scope::Unlinkable`](crate::Scope::Unlinkable).
    pub nullifier: Option<Nullifier>,
    /// The BIN table attributes the challenge asked for.
    pub bin: Disclosed,
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
