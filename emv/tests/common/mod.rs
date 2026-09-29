use emv::{Challenge, Issued, Received, Scheme, Scope, Transaction, YearMonth};

pub(crate) mod mock;

pub(crate) const ORIGIN: &str = "verifier.example";

/// Zero USD, as a verifier asks when no money moves.
const TRANSACTION: Transaction = Transaction {
    amount: [0; 6],
    currency: [0x08, 0x40],
};

pub(crate) fn today() -> YearMonth {
    YearMonth::new(2026, 9).unwrap()
}

pub(crate) fn issue(scheme: Scheme, scope: Scope, today: YearMonth) -> Challenge<Issued> {
    match scheme {
        Scheme::VisaFdda => Challenge::visa_fdda(ORIGIN, scope, today, TRANSACTION),
        Scheme::MastercardDda => Challenge::mastercard_dda(ORIGIN, scope, today),
    }
    .unwrap()
}

pub(crate) fn receive(challenge: &Challenge<Issued>) -> Challenge<Received> {
    Challenge::from_bytes(&challenge.to_bytes(), ORIGIN).unwrap()
}
