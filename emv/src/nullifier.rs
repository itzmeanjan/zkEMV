use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use taceo_poseidon2::bn254::t4::permutation_in_place;

/// `circuits/emv/src/nullifier.nr`'s `DOMAIN_SEPARATOR`.
const NULLIFIER_DOMAIN_SEPARATOR: &[u8] = b"zkEMV nullifier v1";
/// Scopes are derived on the host only.
const SCOPE_DOMAIN_SEPARATOR: &[u8] = b"zkEMV scope v1";
/// Bytes per lane: 31 bytes always fit in a field element.
const CHUNK: usize = 31;
/// The circuit packs the ICC modulus into six lanes.
const LANES: usize = 6;
const RATE: usize = 3;
const TWO_POW_64: u128 = 1 << 64;

/// A card's identifier in one scope, from a proof.
///
/// The same card in the same scope always gives the same nullifier; different cards or
/// scopes give unrelated ones. It hashes the card's ICC public key, so anyone who has read
/// the card, such as a terminal or the issuer, can compute it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nullifier([u8; 32]);

impl Nullifier {
    /// The field element, big-endian.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn from_field(f: Fr) -> Self {
        Self(to_be_bytes(f))
    }
}

pub(crate) fn to_be_bytes(f: Fr) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(&f.into_bigint().to_bytes_be());
    out
}

/// The circuit's nullifier: Poseidon2 of `[NULLIFIER_DOMAIN_SEPARATOR, scope, m₀, …, m₅]`,
/// the modulus in 31-byte lanes. `None` if the modulus exceeds the six lanes.
pub(crate) fn nullifier(icc_modulus: &[u8], scope: Fr) -> Option<Fr> {
    let mut input = vec![domain_separator(NULLIFIER_DOMAIN_SEPARATOR), scope];
    input.extend(lanes(icc_modulus));
    (input.len() <= 2 + LANES).then(|| {
        input.resize(2 + LANES, Fr::zero());
        hash(&input)
    })
}

/// Lane values: 0 for [`Scope::Unlinkable`](crate::Scope::Unlinkable), which is never
/// derived, 1 for a verifier, 2 for an event. The lengths make the encoding injective.
pub(crate) fn scope(kind: u8, origin: &str, event: Option<&[u8; 32]>) -> Fr {
    let mut input = vec![
        domain_separator(SCOPE_DOMAIN_SEPARATOR),
        Fr::from(kind),
        Fr::from_be_bytes_mod_order(&origin.len().to_be_bytes()),
    ];
    input.extend(lanes(origin.as_bytes()));
    input.extend(event.into_iter().flat_map(|e| lanes(e)));
    hash(&input)
}

fn domain_separator(ascii: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(ascii)
}

fn lanes(bytes: &[u8]) -> impl Iterator<Item = Fr> + '_ {
    bytes.chunks(CHUNK).map(Fr::from_be_bytes_mod_order)
}

/// noir-lang/poseidon's `Poseidon2::hash`: t = 4, rate 3, the input length times 2^64 in
/// the capacity lane, a permutation per block including a final partial one, output lane 0.
pub(crate) fn hash(input: &[Fr]) -> Fr {
    let mut state = [Fr::zero(); 4];
    if let Some(capacity) = state.last_mut() {
        *capacity = Fr::from_be_bytes_mod_order(&input.len().to_be_bytes()) * Fr::from(TWO_POW_64);
    }
    for block in input.chunks(RATE) {
        for (lane, x) in state.iter_mut().zip(block) {
            *lane += x;
        }
        permutation_in_place(&mut state);
    }
    if input.is_empty() {
        permutation_in_place(&mut state);
    }
    let [out, ..] = state;
    out
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};

    use super::{Nullifier, hash, nullifier};

    fn hex(f: Fr) -> String {
        const_hex::encode(f.into_bigint().to_bytes_be())
    }

    /// noir-lang/poseidon v0.3.0's own vectors (`test_poseidon2_1` and `_3`), one partial
    /// and one full block.
    #[test]
    fn hash_matches_the_circuits() {
        assert_eq!(
            hex(hash(&[Fr::from(1000u16)])),
            "16433a80e26a23547e25d61dd95fd5793d1ca2dcd78ae64cd146d3b99a35fa7c"
        );
        let full = [1000u16, 2000, 3000].map(Fr::from);
        assert_eq!(hex(hash(&full)), "0f1badcd0d52ced816fb6e6826fdf66ada038135d53cbb993f320ca6529223cd");
    }

    /// `circuits/emv/src/tests/nullifier.nr` checks the same value.
    #[test]
    fn nullifier_known_answer() {
        let modulus: Vec<u8> = (1..=128).collect();
        let n = nullifier(&modulus, Fr::from(7u8)).map(|n| Nullifier::from_field(n).to_bytes());
        assert_eq!(
            n.map(const_hex::encode),
            Some("10bea8dfa6f518e8c2f41fd4bec8efbbb0932081fb73a04a9a6b7d71aa0c48ba".to_owned())
        );
    }

    #[test]
    fn modulus_longer_than_six_lanes_has_no_nullifier() {
        assert!(nullifier(&[1; 186], Fr::from(1u8)).is_some());
        assert!(nullifier(&[1; 187], Fr::from(1u8)).is_none());
    }
}
