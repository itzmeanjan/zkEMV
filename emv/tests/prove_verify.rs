use std::sync::OnceLock;

use emv::{Card, Error, MastercardDda, Proof, ProvingKey, Scheme, VerifyingKey, prepare};
use provekit_common::{FieldElement, NoirProof, file};

mod common;
use common::tap;

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

fn proof(scheme: Scheme) -> &'static Proof {
    static VISA: OnceLock<Proof> = OnceLock::new();
    static MASTERCARD: OnceLock<Proof> = OnceLock::new();
    let cell = match scheme {
        Scheme::VisaFdda => &VISA,
        Scheme::MastercardDda => &MASTERCARD,
    };
    cell.get_or_init(|| {
        let (statement, card) = tap(scheme);
        let proof = keys(scheme).0.prove(&statement, &card).unwrap();
        Proof::from_bytes(&proof.to_bytes().unwrap()).unwrap()
    })
}

#[test]
fn visa_proves_and_verifies() {
    let (statement, _) = tap(Scheme::VisaFdda);
    keys(Scheme::VisaFdda).1.verify(&statement, proof(Scheme::VisaFdda)).unwrap();
}

#[test]
fn mastercard_proves_and_verifies() {
    let (statement, _) = tap(Scheme::MastercardDda);
    keys(Scheme::MastercardDda).1.verify(&statement, proof(Scheme::MastercardDda)).unwrap();
}

#[test]
fn other_nonce_is_rejected() {
    for scheme in [Scheme::VisaFdda, Scheme::MastercardDda] {
        let (mut statement, _) = tap(scheme);
        statement.nonce[0] ^= 1;
        assert!(matches!(keys(scheme).1.verify(&statement, proof(scheme)), Err(Error::StatementMismatch)));
    }
}

#[test]
fn other_ca_key_is_rejected() {
    let (mut statement, _) = tap(Scheme::MastercardDda);
    statement.ca_modulus[100] ^= 1;
    assert!(matches!(
        keys(Scheme::MastercardDda).1.verify(&statement, proof(Scheme::MastercardDda)),
        Err(Error::StatementMismatch)
    ));
}

#[test]
fn other_amount_or_date_is_rejected() {
    let (statement, _) = tap(Scheme::VisaFdda);
    let mut amount = statement.clone();
    amount.transaction.as_mut().unwrap().amount[5] ^= 1;
    let mut today = statement.clone();
    today.today += 1;
    for s in [amount, today] {
        assert!(matches!(
            keys(Scheme::VisaFdda).1.verify(&s, proof(Scheme::VisaFdda)),
            Err(Error::StatementMismatch)
        ));
    }
}

#[test]
fn proof_is_rejected_by_other_schemes_key() {
    let (statement, _) = tap(Scheme::VisaFdda);
    assert!(keys(Scheme::MastercardDda).1.verify(&statement, proof(Scheme::VisaFdda)).is_err());
}

/// Rewriting the public inputs a proof carries, to match another statement, must break
/// the proof itself: ProveKit binds them into the transcript.
#[test]
fn forged_public_inputs_are_rejected() {
    let (mut statement, _) = tap(Scheme::MastercardDda);
    let nonce_at = 17;
    let mut forged: NoirProof = file::deserialize(&proof(Scheme::MastercardDda).to_bytes().unwrap()).unwrap();
    statement.nonce[0] ^= 1;
    forged.public_inputs.0[nonce_at] = FieldElement::from(statement.nonce[0]);
    let forged = Proof::from_bytes(&file::serialize(&forged).unwrap()).unwrap();

    let err = keys(Scheme::MastercardDda).1.verify(&statement, &forged).unwrap_err();
    assert!(matches!(err, Error::ProveKit(_)), "{err}");
}

#[test]
fn card_of_other_scheme_is_refused() {
    let (statement, card) = tap(Scheme::MastercardDda);
    let err = keys(Scheme::VisaFdda).0.prove(&statement, &card).unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }));
}

#[test]
fn tampered_card_cannot_be_proved() {
    let (statement, mut card) = tap(Scheme::VisaFdda);
    let Card::VisaFdda(c) = &mut card else { unreachable!() };
    c.sdad[64] ^= 1;
    assert!(keys(Scheme::VisaFdda).0.prove(&statement, &card).is_err());
}

#[test]
fn transaction_must_match_scheme() {
    let (mut statement, card) = tap(Scheme::VisaFdda);
    statement.transaction = None;
    assert!(matches!(keys(Scheme::VisaFdda).0.prove(&statement, &card), Err(Error::Statement(_))));
}

#[test]
fn zero_ca_modulus_is_an_error() {
    let (mut statement, card) = tap(Scheme::MastercardDda);
    statement.ca_modulus = vec![0; statement.ca_modulus.len()];
    let err = keys(Scheme::MastercardDda).0.prove(&statement, &card).unwrap_err();
    assert!(matches!(err, Error::Card(_)), "{err}");
}

#[test]
fn malformed_bytes_are_errors() {
    for bytes in [&[][..], &[0; 64][..], &proof(Scheme::VisaFdda).to_bytes().unwrap()[..100]] {
        assert!(ProvingKey::from_bytes(bytes).is_err());
        assert!(VerifyingKey::from_bytes(bytes).is_err());
        assert!(Proof::from_bytes(bytes).is_err());
    }
}

#[test]
fn wrong_length_card_fields_are_errors() {
    let (statement, card) = tap(Scheme::MastercardDda);
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
        assert!(keys(Scheme::MastercardDda).0.prove(&statement, &Card::MastercardDda(c)).is_err());
    }
}
