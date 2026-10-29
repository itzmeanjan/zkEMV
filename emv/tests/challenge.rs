use std::collections::HashSet;

use emv::{BinRoot, Challenge, Disclosure, Error, Issued, Received, Scheme, Scope, Transaction, YearMonth};

const ORIGIN: &str = "verifier.example";

const TRANSACTION: Transaction = Transaction {
    amount_authorised: [0, 0, 0, 0, 0x12, 0x34],
    currency_code: [0x09, 0x78],
};

fn today() -> YearMonth {
    YearMonth::new(2026, 9).unwrap()
}

fn issue_scoped(scheme: Scheme, scope: Scope) -> Challenge<Issued> {
    match scheme {
        Scheme::VisaFdda => Challenge::visa_fdda(ORIGIN, scope, today(), TRANSACTION),
        Scheme::MastercardDda => Challenge::mastercard_dda(ORIGIN, scope, today()),
    }
    .unwrap()
}

fn issue(scheme: Scheme) -> Challenge<Issued> {
    issue_scoped(scheme, Scope::Verifier)
}

fn receive(challenge: &Challenge<Issued>, origin: &str) -> Challenge<Received> {
    Challenge::from_bytes(&challenge.to_bytes(), origin).unwrap()
}

#[test]
fn year_month_accepts_2000_to_2099() {
    for (year, month) in [(2000, 1), (2026, 9), (2049, 12), (2099, 12)] {
        let ym = YearMonth::new(year, month).unwrap();
        assert_eq!((ym.year(), ym.month()), (year, month));
    }
}

#[test]
fn year_month_rejects_other_years_and_months() {
    let invalid = [(1999, 12), (2100, 1), (2255, 1), (0, 1), (u16::MAX, 1), (2026, 0), (2026, 13), (2026, u8::MAX)];
    for (year, month) in invalid {
        let err = YearMonth::new(year, month).unwrap_err();
        assert!(matches!(err, Error::YearMonth { year: y, month: m } if (y, m) == (year, month)), "{err}");
    }
}

#[test]
fn challenge_round_trips() {
    for scheme in [Scheme::VisaFdda, Scheme::MastercardDda] {
        let issued = issue(scheme);
        let received = receive(&issued, ORIGIN);
        assert_eq!(received.scheme(), scheme);
        assert_eq!(received.nonce(), issued.nonce());
        assert_eq!(received.today(), today());
        assert_eq!(received.transaction(), (scheme == Scheme::VisaFdda).then_some(TRANSACTION));
    }
}

#[test]
fn scope_round_trips() {
    for scheme in [Scheme::VisaFdda, Scheme::MastercardDda] {
        for scope in [Scope::Unlinkable, Scope::Verifier, Scope::Event([9; 32])] {
            assert_eq!(receive(&issue_scoped(scheme, scope), ORIGIN).scope(), scope);
        }
    }
}

#[test]
fn scope_derives_from_origin_scope_and_event() {
    let icc = [0x80; 128];
    let nullifier = |c: &Challenge<Issued>, origin| receive(c, origin).nullifier_of(&icc).unwrap();

    let verifier = issue_scoped(Scheme::VisaFdda, Scope::Verifier);
    assert_eq!(verifier.nullifier_of(&icc), Some(nullifier(&verifier, ORIGIN)));
    assert_ne!(nullifier(&verifier, ORIGIN), nullifier(&verifier, "other.example"));

    let (poll_a, poll_b) = (
        issue_scoped(Scheme::VisaFdda, Scope::Event([1; 32])),
        issue_scoped(Scheme::VisaFdda, Scope::Event([2; 32])),
    );
    assert_eq!(poll_a.nullifier_of(&icc), Some(nullifier(&poll_a, ORIGIN)));
    assert_ne!(nullifier(&poll_a, ORIGIN), nullifier(&poll_b, ORIGIN));
    assert_ne!(nullifier(&poll_a, ORIGIN), nullifier(&verifier, ORIGIN));

    // The scheme doesn't enter the scope: one card has one application per scheme anyway.
    let mastercard = issue_scoped(Scheme::MastercardDda, Scope::Verifier);
    assert_eq!(mastercard.nullifier_of(&icc), verifier.nullifier_of(&icc));
}

#[test]
fn unlinkable_scope_is_drawn_by_the_prover() {
    let icc = [0x80; 128];
    let issued = issue_scoped(Scheme::MastercardDda, Scope::Unlinkable);
    assert_eq!(issued.nullifier_of(&icc), None);
    let (a, b) = (receive(&issued, ORIGIN).nullifier_of(&icc), receive(&issued, ORIGIN).nullifier_of(&icc));
    assert!(a.is_some() && a != b);
}

#[test]
fn nonces_are_fresh() {
    let nonces: HashSet<[u8; 4]> = (0..16).map(|_| issue(Scheme::MastercardDda).nonce()).collect();
    assert_eq!(nonces.len(), 16);
}

#[test]
fn malformed_challenges_are_errors() {
    let visa = issue(Scheme::VisaFdda).to_bytes();
    let mastercard = issue(Scheme::MastercardDda).to_bytes();
    let with = |bytes: &[u8], at: usize, value: u8| {
        let mut bytes = bytes.to_vec();
        bytes[at] = value;
        bytes
    };

    let malformed = [
        vec![],
        with(&mastercard, 0, 0x00),
        with(&mastercard, 0, 0x03),
        visa[..visa.len() - 1].to_vec(),
        mastercard[..3].to_vec(),
        [&mastercard[..], &[0]].concat(),
        with(&visa, 0, mastercard[0]),
        with(&mastercard, 0, visa[0]),
        // Scope kind: the second-to-last byte of a `Scope::Verifier` challenge.
        with(&mastercard, mastercard.len() - 2, 3),
        [&mastercard[..mastercard.len() - 2], &[2], &[0; 31]].concat(),
        // Disclosure: the last byte when nothing is asked.
        with(&mastercard, mastercard.len() - 1, 0x10),
        with(&mastercard, mastercard.len() - 1, 1),
    ];
    for bytes in malformed {
        let err = Challenge::from_bytes(&bytes, ORIGIN).unwrap_err();
        assert!(matches!(err, Error::Challenge(_)), "{bytes:02x?}: {err}");
    }

    // Year at byte 5 (years since 2000), month at byte 6.
    for bytes in [with(&mastercard, 6, 0), with(&mastercard, 6, 13), with(&visa, 5, 100)] {
        let err = Challenge::from_bytes(&bytes, ORIGIN).unwrap_err();
        assert!(matches!(err, Error::YearMonth { .. }), "{bytes:02x?}: {err}");
    }
}

fn root(last: u8) -> BinRoot {
    let mut bytes = [0; 32];
    bytes[31] = last;
    BinRoot::from_bytes(bytes).unwrap()
}

#[test]
fn disclosure_round_trips() {
    for scheme in [Scheme::VisaFdda, Scheme::MastercardDda] {
        let none = receive(&issue(scheme), ORIGIN);
        assert_eq!((none.disclosure(), none.bin_root()), (Disclosure::NONE, None));

        let asked = Disclosure::COUNTRY | Disclosure::COMMERCIAL;
        let received = receive(&issue(scheme).disclose(root(7), asked), ORIGIN);
        assert_eq!((received.disclosure(), received.bin_root()), (asked, Some(root(7))));
        assert!(received.disclosure().contains(Disclosure::COUNTRY) && !received.disclosure().contains(Disclosure::BRAND));

        let dropped = receive(&issue(scheme).disclose(root(7), Disclosure::NONE), ORIGIN);
        assert_eq!(dropped.bin_root(), None);
    }
}

#[test]
fn bin_root_must_be_a_field_element() {
    assert!(BinRoot::from_bytes([0xFF; 32]).is_none());
    let bytes = issue(Scheme::MastercardDda).disclose(root(7), Disclosure::ALL).to_bytes();
    let malformed = [
        [&bytes[..bytes.len() - 32], &[0xFF; 32]].concat(),
        bytes[..bytes.len() - 1].to_vec(),
        [&bytes[..], &[0]].concat(),
    ];
    for bytes in malformed {
        let err = Challenge::from_bytes(&bytes, ORIGIN).unwrap_err();
        assert!(matches!(err, Error::Challenge(_)), "{bytes:02x?}: {err}");
    }
}
