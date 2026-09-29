use std::sync::OnceLock;

use emv::{Card, Challenge, Error, MastercardDda, Proof, ProvingKey, Received, Scheme, VerifyingKey, YearMonth, prepare};
use provekit_common::{FieldElement, NoirProof, file};

mod common;
use common::{issue, receive, tap, today};

const SCHEMES: [Scheme; 2] = [Scheme::VisaFdda, Scheme::MastercardDda];

/// Keys go through a bytes round trip, so every test also covers key serialization.
fn keys(scheme: Scheme) -> &'static (ProvingKey, VerifyingKey) {
    static VISA: OnceLock<(ProvingKey, VerifyingKey)> = OnceLock::new();
    static MASTERCARD: OnceLock<(ProvingKey, VerifyingKey)> = OnceLock::new();

    let cell = match scheme {
        Scheme::VisaFdda => &VISA,
        Scheme::MastercardDda => &MASTERCARD,
    };
    cell.get_or_init(|| {
        let (pk, vk) = prepare(&common::compiled(scheme)).unwrap();

        let pk = ProvingKey::from_bytes(&pk.to_bytes().unwrap()).unwrap();
        let vk = VerifyingKey::from_bytes(&vk.to_bytes().unwrap()).unwrap();

        assert_eq!((pk.scheme(), vk.scheme()), (scheme, scheme));
        (pk, vk)
    })
}

/// Proofs go through a bytes round trip, so every test also covers proof serialization.
fn prove(challenge: &Challenge<Received>) -> emv::Result<Proof> {
    let (ca, card) = tap(challenge);
    let proof = keys(challenge.scheme()).0.prove(challenge, &ca, &card)?;
    Proof::from_bytes(&proof.to_bytes()?)
}

/// A proof whose issued challenge is gone, so no challenge can verify it.
fn stale_proof(scheme: Scheme) -> &'static (Challenge<Received>, Proof) {
    static VISA: OnceLock<(Challenge<Received>, Proof)> = OnceLock::new();
    static MASTERCARD: OnceLock<(Challenge<Received>, Proof)> = OnceLock::new();
    let cell = match scheme {
        Scheme::VisaFdda => &VISA,
        Scheme::MastercardDda => &MASTERCARD,
    };
    cell.get_or_init(|| {
        let challenge = receive(&issue(scheme, today()));
        let proof = prove(&challenge).unwrap();
        (challenge, proof)
    })
}

#[test]
fn fresh_challenge_proves_and_verifies() {
    for scheme in SCHEMES {
        let issued = issue(scheme, today());
        let received = receive(&issued);
        let proof = prove(&received).unwrap();
        keys(scheme).1.verify(issued, &tap(&received).0, &proof).unwrap();
    }
}

/// Both synthetic certificates expire in December 2049 (`gen_synthetic.py`'s
/// `CERT_EXPIRY_MMYY`).
#[test]
fn certificates_are_valid_through_their_expiry_month() {
    for scheme in SCHEMES {
        let issued = issue(scheme, YearMonth::new(2049, 12).unwrap());
        let received = receive(&issued);
        let proof = prove(&received).unwrap();
        keys(scheme).1.verify(issued, &tap(&received).0, &proof).unwrap();

        let err = prove(&receive(&issue(scheme, YearMonth::new(2050, 1).unwrap()))).unwrap_err();
        assert!(matches!(err, Error::ProveKit(_)), "{err}");
    }
}

#[test]
fn proof_for_another_challenge_is_rejected() {
    for scheme in SCHEMES {
        let (challenge, proof) = stale_proof(scheme);
        let err = keys(scheme).1.verify(issue(scheme, today()), &tap(challenge).0, proof).unwrap_err();
        assert!(matches!(err, Error::PublicInputsMismatch), "{err}");
    }
}

/// The card signs whatever the prover sends it, so a prover can answer an altered
/// challenge; the verifier must reject that proof.
#[test]
fn altered_challenge_is_rejected() {
    // Offsets in `Challenge::to_bytes`: nonce 1..5, year 5, month 6, and for Visa amount
    // 7..13 and currency 13..15. Each alteration keeps the bytes a valid challenge.
    let alterations = [
        (Scheme::VisaFdda, 1),
        (Scheme::VisaFdda, 6),
        (Scheme::VisaFdda, 12),
        (Scheme::VisaFdda, 14),
        (Scheme::MastercardDda, 4),
        (Scheme::MastercardDda, 5),
    ];
    for (scheme, at) in alterations {
        let issued = issue(scheme, today());
        let mut bytes = issued.to_bytes();
        bytes[at] ^= 1;
        let altered = Challenge::from_bytes(&bytes).unwrap();
        let proof = prove(&altered).unwrap();
        let err = keys(scheme).1.verify(issued, &tap(&altered).0, &proof).unwrap_err();
        assert!(matches!(err, Error::PublicInputsMismatch), "{scheme:?} byte {at}: {err}");
    }
}

#[test]
fn other_ca_key_is_rejected() {
    let issued = issue(Scheme::MastercardDda, today());
    let received = receive(&issued);
    let proof = prove(&received).unwrap();
    let mut ca = tap(&received).0;
    ca[100] ^= 1;
    let err = keys(Scheme::MastercardDda).1.verify(issued, &ca, &proof).unwrap_err();
    assert!(matches!(err, Error::PublicInputsMismatch), "{err}");
}

#[test]
fn proof_is_rejected_by_other_schemes_key() {
    let issued = issue(Scheme::VisaFdda, today());
    let received = receive(&issued);
    let proof = prove(&received).unwrap();
    let ca = tap(&received).0;
    let mastercard = issue(Scheme::MastercardDda, today());
    assert!(keys(Scheme::MastercardDda).1.verify(mastercard, &ca, &proof).is_err());
}

/// Rewriting the public inputs a proof carries, to match another challenge, must break
/// the proof itself: ProveKit binds them into the transcript.
#[test]
fn forged_public_inputs_are_rejected() {
    let (challenge, proof) = stale_proof(Scheme::MastercardDda);
    let issued = issue(Scheme::MastercardDda, today());
    let nonce_at = 17;
    let mut forged: NoirProof = file::deserialize(&proof.to_bytes().unwrap()).unwrap();
    for (i, &b) in issued.nonce().iter().enumerate() {
        forged.public_inputs.0[nonce_at + i] = FieldElement::from(b);
    }
    let forged = Proof::from_bytes(&file::serialize(&forged).unwrap()).unwrap();

    let err = keys(Scheme::MastercardDda).1.verify(issued, &tap(challenge).0, &forged).unwrap_err();
    assert!(matches!(err, Error::ProveKit(_)), "{err}");
}

#[test]
fn challenge_of_other_scheme_is_refused() {
    let (challenge, proof) = stale_proof(Scheme::MastercardDda);
    let (ca, card) = tap(challenge);
    let err = keys(Scheme::VisaFdda).0.prove(challenge, &ca, &card).unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }), "{err}");

    let err = keys(Scheme::VisaFdda).1.verify(issue(Scheme::MastercardDda, today()), &ca, proof).unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }), "{err}");
}

#[test]
fn card_of_other_scheme_is_refused() {
    let visa = receive(&issue(Scheme::VisaFdda, today()));
    let (ca, card) = tap(&receive(&issue(Scheme::MastercardDda, today())));
    let err = keys(Scheme::VisaFdda).0.prove(&visa, &ca, &card).unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }), "{err}");
}

#[test]
fn tampered_card_cannot_be_proved() {
    let challenge = receive(&issue(Scheme::VisaFdda, today()));
    let (ca, mut card) = tap(&challenge);
    let Card::VisaFdda(c) = &mut card else { unreachable!() };
    c.sdad[64] ^= 1;
    assert!(keys(Scheme::VisaFdda).0.prove(&challenge, &ca, &card).is_err());
}

#[test]
fn zero_ca_modulus_is_an_error() {
    let challenge = receive(&issue(Scheme::MastercardDda, today()));
    let (ca, card) = tap(&challenge);
    let err = keys(Scheme::MastercardDda).0.prove(&challenge, &vec![0; ca.len()], &card).unwrap_err();
    assert!(matches!(err, Error::Card(_)), "{err}");
}

#[test]
fn malformed_bytes_are_errors() {
    for bytes in [&[][..], &[0; 64][..], &stale_proof(Scheme::VisaFdda).1.to_bytes().unwrap()[..100]] {
        assert!(ProvingKey::from_bytes(bytes).is_err());
        assert!(VerifyingKey::from_bytes(bytes).is_err());
        assert!(Proof::from_bytes(bytes).is_err());
    }
}

#[test]
fn wrong_length_card_fields_are_errors() {
    let challenge = receive(&issue(Scheme::MastercardDda, today()));
    let (ca, card) = tap(&challenge);
    let Card::MastercardDda(c) = card else { unreachable!() };
    let mutations: [fn(&mut MastercardDda); 5] = [
        |c| c.issuer_cert.truncate(10),
        |c| c.icc_cert.clear(),
        |c| c.issuer_remainder.clear(),
        |c| c.sdad.truncate(100),
        |c| c.static_data = vec![0; 300],
    ];
    for mutate in mutations {
        let mut c = c.clone();
        mutate(&mut c);
        assert!(keys(Scheme::MastercardDda).0.prove(&challenge, &ca, &Card::MastercardDda(c)).is_err());
    }
}
