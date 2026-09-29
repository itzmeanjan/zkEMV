use std::collections::HashSet;

use emv::{Challenge, Error, Issued, Received, Scheme, Transaction, YearMonth};

const TRANSACTION: Transaction = Transaction {
    amount: [0, 0, 0, 0, 0x12, 0x34],
    currency: [0x09, 0x78],
};

fn today() -> YearMonth {
    YearMonth::new(2026, 9).unwrap()
}

fn issue(scheme: Scheme) -> Challenge<Issued> {
    match scheme {
        Scheme::VisaFdda => Challenge::visa_fdda(today(), TRANSACTION),
        Scheme::MastercardDda => Challenge::mastercard_dda(today()),
    }
    .unwrap()
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
        let received = Challenge::<Received>::from_bytes(&issued.to_bytes()).unwrap();
        assert_eq!(received.scheme(), scheme);
        assert_eq!(received.nonce(), issued.nonce());
        assert_eq!(received.today(), today());
        assert_eq!(received.transaction(), (scheme == Scheme::VisaFdda).then_some(TRANSACTION));
    }
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
    ];
    for bytes in malformed {
        let err = Challenge::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::Challenge(_)), "{bytes:02x?}: {err}");
    }

    // Year at byte 5 (years since 2000), month at byte 6.
    for bytes in [with(&mastercard, 6, 0), with(&mastercard, 6, 13), with(&visa, 5, 100)] {
        let err = Challenge::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::YearMonth { .. }), "{bytes:02x?}: {err}");
    }
}
