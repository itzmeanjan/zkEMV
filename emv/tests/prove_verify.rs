use std::sync::OnceLock;

use emv::{
    BinTable, CaTable, Card, CardType, Challenge, Disclosed, Disclosure, Error, Issued, MastercardDda, Nullifier, Proof, ProvingKey, Received, Scheme, Scope,
    VerifyingKey, YearMonth, prepare,
};
use provekit_common::{FieldElement, NoirProof, file};

mod common;
use common::{issue, mock::tap, receive, today};

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
        let (pk, vk) = prepare(&common::mock::compiled(scheme)).unwrap();

        let pk = ProvingKey::from_bytes(&pk.to_bytes().unwrap()).unwrap();
        let vk = VerifyingKey::from_bytes(&vk.to_bytes().unwrap()).unwrap();

        assert_eq!((pk.scheme(), vk.scheme()), (scheme, scheme));
        (pk, vk)
    })
}

/// `fixtures/bin-table.json`: one range per synthetic tap's BIN.
fn bins() -> &'static BinTable {
    static TABLE: OnceLock<BinTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        let path = format!("{}/fixtures/bin-table.json", common::mock::circuits());
        BinTable::from_json(&std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
    })
}

/// Proofs go through a bytes round trip, so every test also covers proof serialization.
fn prove(challenge: &Challenge<Received>) -> emv::Result<Proof> {
    let (ca, card) = tap(challenge);
    let proof = keys(challenge.scheme()).0.prove(challenge, &ca, &card, Some(bins()))?;
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
        let challenge = receive(&issue(scheme, Scope::Verifier, today()));
        let proof = prove(&challenge).unwrap();
        (challenge, proof)
    })
}

#[test]
fn fresh_challenge_proves_and_verifies() {
    for scheme in SCHEMES {
        let issued = issue(scheme, Scope::Verifier, today());
        let received = receive(&issued);
        let proof = prove(&received).unwrap();
        keys(scheme).1.verify(issued, &tap(&received).0, &proof).unwrap();
    }
}

fn icc_modulus(scheme: Scheme) -> Vec<u8> {
    let path = format!("{}/fixtures/{}.json", common::mock::circuits(), common::mock::package(scheme));
    common::mock::unhex(&common::mock::read_json(&path)["testIccKey"]["modulus"])
}

fn session(scheme: Scheme, scope: Scope) -> Option<Nullifier> {
    let issued = issue(scheme, scope, today());
    let received = receive(&issued);
    let proof = prove(&received).unwrap();
    keys(scheme).1.verify(issued, &tap(&received).0, &proof).unwrap().nullifier
}

/// The circuit's nullifier equals the host's.
#[test]
fn nullifier_is_the_cards_in_the_scope() {
    for scheme in SCHEMES {
        for scope in [Scope::Verifier, Scope::Event([7; 32])] {
            let issued = issue(scheme, scope, today());
            let expected = issued.nullifier_of(&icc_modulus(scheme)).unwrap();
            let received = receive(&issued);
            let proof = prove(&received).unwrap();
            assert_eq!(keys(scheme).1.verify(issued, &tap(&received).0, &proof).unwrap().nullifier, Some(expected));
        }
    }
}

#[test]
fn nullifier_repeats_only_within_a_scope() {
    let session = |scope| session(Scheme::VisaFdda, scope).unwrap();
    let verifier = session(Scope::Verifier);
    assert_eq!(session(Scope::Verifier), verifier);

    let (poll_a, poll_b) = (session(Scope::Event([1; 32])), session(Scope::Event([2; 32])));
    assert_eq!(session(Scope::Event([1; 32])), poll_a);
    assert_ne!(poll_a, poll_b);
    assert_ne!(poll_a, verifier);
}

#[test]
fn unlinkable_scope_gives_no_nullifier() {
    let icc = icc_modulus(Scheme::VisaFdda);
    let issued = issue(Scheme::VisaFdda, Scope::Unlinkable, today());
    assert_eq!(issued.nullifier_of(&icc), None);
    assert_ne!(receive(&issued).nullifier_of(&icc), receive(&issued).nullifier_of(&icc));
    assert_eq!(session(Scheme::VisaFdda, Scope::Unlinkable), None);
}

/// E.g. a prover relaying another verifier's challenge.
#[test]
fn proof_in_another_scope_is_rejected() {
    let issued = issue(Scheme::VisaFdda, Scope::Verifier, today());
    let elsewhere = Challenge::from_bytes(&issued.to_bytes(), "other.example").unwrap();
    let proof = prove(&elsewhere).unwrap();
    let err = keys(Scheme::VisaFdda).1.verify(issued, &tap(&elsewhere).0, &proof).unwrap_err();
    assert!(matches!(err, Error::PublicInputsMismatch), "{err}");
}

/// The nullifier is the proof's last public input; ProveKit binds it like the others.
#[test]
fn forged_nullifier_is_rejected() {
    let issued = issue(Scheme::VisaFdda, Scope::Verifier, today());
    let received = receive(&issued);
    let mut forged: NoirProof = file::deserialize(&prove(&received).unwrap().to_bytes().unwrap()).unwrap();
    if let Some(n) = forged.public_inputs.0.last_mut() {
        *n += FieldElement::from(1u8);
    }
    let forged = Proof::from_bytes(&file::serialize(&forged).unwrap()).unwrap();
    let err = keys(Scheme::VisaFdda).1.verify(issued, &tap(&received).0, &forged).unwrap_err();
    assert!(matches!(err, Error::ProveKit(_)), "{err}");
}

/// Both synthetic certificates expire in December 2049 (`gen_synthetic.py`'s
/// `CERT_EXPIRY_MMYY`).
#[test]
fn certificates_are_valid_through_their_expiry_month() {
    for scheme in SCHEMES {
        let issued = issue(scheme, Scope::Verifier, YearMonth::new(2049, 12).unwrap());
        let received = receive(&issued);
        let proof = prove(&received).unwrap();
        keys(scheme).1.verify(issued, &tap(&received).0, &proof).unwrap();

        let err = prove(&receive(&issue(scheme, Scope::Verifier, YearMonth::new(2050, 1).unwrap()))).unwrap_err();
        assert!(matches!(err, Error::ProveKit(_)), "{err}");
    }
}

#[test]
fn proof_for_another_challenge_is_rejected() {
    for scheme in SCHEMES {
        let (challenge, proof) = stale_proof(scheme);
        let err = keys(scheme)
            .1
            .verify(issue(scheme, Scope::Verifier, today()), &tap(challenge).0, proof)
            .unwrap_err();
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
        let issued = issue(scheme, Scope::Verifier, today());
        let mut bytes = issued.to_bytes();
        bytes[at] ^= 1;
        let altered = Challenge::from_bytes(&bytes, common::ORIGIN).unwrap();
        let proof = prove(&altered).unwrap();
        let err = keys(scheme).1.verify(issued, &tap(&altered).0, &proof).unwrap_err();
        assert!(matches!(err, Error::PublicInputsMismatch), "{scheme:?} byte {at}: {err}");
    }
}

/// Real keys from `data/`, which the synthetic taps don't chain to.
fn data_table() -> CaTable {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../data/certificate-authority-public-keys.json");
    CaTable::from_json(&std::fs::read(path).unwrap()).unwrap()
}

/// The proof is under the test CA key; the verifier's table maps the card's RID and `8F`
/// to Visa's real key `09` instead.
#[test]
fn other_ca_key_is_rejected() {
    let issued = issue(Scheme::VisaFdda, Scope::Verifier, today());
    let received = receive(&issued);
    let proof = prove(&received).unwrap();
    let visa_09 = data_table().lookup(&issued, Scheme::VisaFdda.rid(), 0x09).unwrap();
    let err = keys(Scheme::VisaFdda).1.verify(issued, &visa_09, &proof).unwrap_err();
    assert!(matches!(err, Error::PublicInputsMismatch), "{err}");
}

/// `verify` re-checks the key against its own challenge, whatever challenge it was looked
/// up for.
#[test]
fn ca_key_must_fit_the_verified_challenge() {
    let (_, proof) = stale_proof(Scheme::MastercardDda);
    let data = data_table();
    let mastercard_06 = |today| {
        data.lookup(&issue(Scheme::MastercardDda, Scope::Verifier, today), Scheme::MastercardDda.rid(), 0x06)
            .unwrap()
    };
    let visa_09 = data
        .lookup(&issue(Scheme::VisaFdda, Scope::Verifier, today()), Scheme::VisaFdda.rid(), 0x09)
        .unwrap();
    let cases = [
        (visa_09, today()),
        // Mastercard `06` expires 2028-12-31 in `data/`.
        (mastercard_06(YearMonth::new(2028, 12).unwrap()), YearMonth::new(2029, 1).unwrap()),
    ];
    for (ca, month) in cases {
        let err = keys(Scheme::MastercardDda)
            .1
            .verify(issue(Scheme::MastercardDda, Scope::Verifier, month), &ca, proof)
            .unwrap_err();
        assert!(matches!(err, Error::CaKey(_)), "{err}");

        let challenge = receive(&issue(Scheme::MastercardDda, Scope::Verifier, month));
        let card = tap(&challenge).1;
        let err = keys(Scheme::MastercardDda).0.prove(&challenge, &ca, &card, None).unwrap_err();
        assert!(matches!(err, Error::CaKey(_)), "{err}");
    }
}

#[test]
fn proof_is_rejected_by_other_schemes_key() {
    let issued = issue(Scheme::VisaFdda, Scope::Verifier, today());
    let received = receive(&issued);
    let proof = prove(&received).unwrap();
    let ca = tap(&received).0;
    let mastercard = issue(Scheme::MastercardDda, Scope::Verifier, today());
    assert!(keys(Scheme::MastercardDda).1.verify(mastercard, &ca, &proof).is_err());
}

/// Rewriting the public inputs a proof carries, to match another challenge, must break
/// the proof itself: ProveKit binds them into the transcript.
#[test]
fn forged_public_inputs_are_rejected() {
    let (challenge, proof) = stale_proof(Scheme::MastercardDda);
    let issued = issue(Scheme::MastercardDda, Scope::Verifier, today());
    // After `trust_anchors`: the CA modulus's 17 limbs and the BIN root.
    let nonce_at = 18;
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
    let err = keys(Scheme::VisaFdda).0.prove(challenge, &ca, &card, None).unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }), "{err}");

    let err = keys(Scheme::VisaFdda)
        .1
        .verify(issue(Scheme::MastercardDda, Scope::Verifier, today()), &ca, proof)
        .unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }), "{err}");
}

#[test]
fn card_of_other_scheme_is_refused() {
    let visa = receive(&issue(Scheme::VisaFdda, Scope::Verifier, today()));
    let (ca, card) = tap(&receive(&issue(Scheme::MastercardDda, Scope::Verifier, today())));
    let err = keys(Scheme::VisaFdda).0.prove(&visa, &ca, &card, None).unwrap_err();
    assert!(matches!(err, Error::SchemeMismatch { .. }), "{err}");
}

#[test]
fn tampered_card_cannot_be_proved() {
    let challenge = receive(&issue(Scheme::VisaFdda, Scope::Verifier, today()));
    let (ca, mut card) = tap(&challenge);
    let Card::VisaFdda(c) = &mut card else { unreachable!() };
    c.signed_dynamic_app_data[64] ^= 1;
    assert!(keys(Scheme::VisaFdda).0.prove(&challenge, &ca, &card, None).is_err());
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
    let challenge = receive(&issue(Scheme::MastercardDda, Scope::Verifier, today()));
    let (ca, card) = tap(&challenge);
    let Card::MastercardDda(c) = card else { unreachable!() };
    let mutations: [fn(&mut MastercardDda); 5] = [
        |c| c.issuer_pubkey_cert.truncate(10),
        |c| c.icc_pubkey_cert.clear(),
        |c| c.issuer_pubkey_remainder.clear(),
        |c| c.signed_dynamic_app_data.truncate(100),
        |c| c.static_data_to_authenticate = vec![0; 300],
    ];
    for mutate in mutations {
        let mut c = c.clone();
        mutate(&mut c);
        assert!(keys(Scheme::MastercardDda).0.prove(&challenge, &ca, &Card::MastercardDda(c), None).is_err());
    }
}

fn disclosing(scheme: Scheme, disclosure: Disclosure) -> Challenge<Issued> {
    issue(scheme, Scope::Verifier, today()).disclose(bins().root(), disclosure)
}

/// `gen_synthetic.py`'s `BIN_ATTRIBUTES`; brand codes index the fixture's brand list.
fn synthetic_attributes(scheme: Scheme) -> (Disclosed, &'static str) {
    match scheme {
        Scheme::VisaFdda => (
            Disclosed {
                country: Some(999),
                card_type: Some(CardType::Credit),
                brand: Some(2),
                commercial: Some(false),
            },
            "VISA",
        ),
        Scheme::MastercardDda => (
            Disclosed {
                country: Some(998),
                card_type: Some(CardType::Prepaid),
                brand: Some(1),
                commercial: Some(true),
            },
            "MASTERCARD",
        ),
    }
}

#[test]
fn bin_attributes_are_disclosed() {
    for scheme in SCHEMES {
        let issued = disclosing(scheme, Disclosure::ALL);
        let received = receive(&issued);
        assert_eq!((received.disclosure(), received.bin_root()), (Disclosure::ALL, Some(bins().root())));
        let proof = prove(&received).unwrap();
        let verified = keys(scheme).1.verify(issued, &tap(&received).0, &proof).unwrap();
        let (expected, brand) = synthetic_attributes(scheme);
        assert_eq!(verified.bin, expected);
        assert_eq!(bins().brand(verified.bin.brand.unwrap()), Some(brand));
        assert!(verified.nullifier.is_some());
    }
}

#[test]
fn only_asked_attributes_are_disclosed() {
    let cases = [
        (
            Disclosure::CARD_TYPE | Disclosure::COMMERCIAL,
            Disclosed {
                card_type: Some(CardType::Credit),
                commercial: Some(false),
                ..Disclosed::default()
            },
        ),
        (Disclosure::NONE, Disclosed::default()),
    ];
    for (disclosure, expected) in cases {
        let issued = disclosing(Scheme::VisaFdda, disclosure);
        let received = receive(&issued);
        let proof = prove(&received).unwrap();
        assert_eq!(keys(Scheme::VisaFdda).1.verify(issued, &tap(&received).0, &proof).unwrap().bin, expected);
    }
}

#[test]
fn disclosure_needs_the_challenges_bin_table() {
    let pk = &keys(Scheme::VisaFdda).0;
    let received = receive(&disclosing(Scheme::VisaFdda, Disclosure::ALL));
    let (ca, card) = tap(&received);
    let err = pk.prove(&received, &ca, &card, None).unwrap_err();
    assert!(matches!(err, Error::BinTable(_)), "{err}");

    // Without the Visa tap's range, in slot 0.
    let mut other = bins().clone();
    other.remove(0).unwrap();
    let err = pk.prove(&received, &ca, &card, Some(&other)).unwrap_err();
    assert!(matches!(err, Error::BinTable(_)), "{err}");

    let received = receive(&issue(Scheme::VisaFdda, Scope::Verifier, today()).disclose(other.root(), Disclosure::COUNTRY));
    let (ca, card) = tap(&received);
    let err = pk.prove(&received, &ca, &card, Some(&other)).unwrap_err();
    assert!(matches!(err, Error::UnknownBin), "{err}");
}

/// The prover answers a challenge that asks for less.
#[test]
fn altered_disclosure_is_rejected() {
    let issued = disclosing(Scheme::VisaFdda, Disclosure::ALL);
    let mut bytes = issued.to_bytes();
    // The disclosure byte precedes the 32-byte root; bit 0 is the country.
    let at = bytes.len() - 33;
    bytes[at] = 1;
    let altered = Challenge::from_bytes(&bytes, common::ORIGIN).unwrap();
    assert_eq!(altered.disclosure(), Disclosure::COUNTRY);
    let proof = prove(&altered).unwrap();
    let err = keys(Scheme::VisaFdda).1.verify(issued, &tap(&altered).0, &proof).unwrap_err();
    assert!(matches!(err, Error::PublicInputsMismatch), "{err}");
}

/// The circuit's outputs are the last five public inputs: country, card type, brand,
/// commercial, nullifier.
#[test]
fn forged_bin_attributes_are_rejected() {
    let forge = |disclosure, add: u8| {
        let issued = disclosing(Scheme::VisaFdda, disclosure);
        let received = receive(&issued);
        let mut forged: NoirProof = file::deserialize(&prove(&received).unwrap().to_bytes().unwrap()).unwrap();
        let inputs = &mut forged.public_inputs.0;
        let country = inputs.len() - 5;
        inputs[country] += FieldElement::from(add);
        let forged = Proof::from_bytes(&file::serialize(&forged).unwrap()).unwrap();
        keys(Scheme::VisaFdda).1.verify(issued, &tap(&received).0, &forged).unwrap_err()
    };
    let err = forge(Disclosure::ALL, 1);
    assert!(matches!(err, Error::ProveKit(_)), "{err}");
    // An attribute not asked for must be 0.
    let err = forge(Disclosure::NONE, 5);
    assert!(matches!(err, Error::PublicInputsMismatch), "{err}");
}
