use std::marker::PhantomData;

use crate::{Error, Result, Scheme};

const VISA_FDDA: u8 = 0x01;
const MASTERCARD_DDA: u8 = 0x02;

/// A month of the years 2000 to 2099, the range of EMV's two-digit years. A certificate
/// is valid until the end of its expiry month.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct YearMonth {
    /// Years since 2000.
    yy: u8,
    month: u8,
}

impl YearMonth {
    /// # Errors
    ///
    /// [`Error::YearMonth`]: `year` is not in 2000..=2099 or `month` is not in 1..=12.
    pub fn new(year: u16, month: u8) -> Result<Self> {
        let yy = year.checked_sub(2000).and_then(|yy| u8::try_from(yy).ok()).filter(|&yy| yy <= 99);
        match yy {
            Some(yy) if (1..=12).contains(&month) => Ok(Self { yy, month }),
            _ => Err(Error::YearMonth { year, month }),
        }
    }

    /// The year, e.g. `2026`.
    #[must_use]
    pub fn year(self) -> u16 {
        2000u16.saturating_add(self.yy.into())
    }

    /// The month, 1 to 12.
    #[must_use]
    pub fn month(self) -> u8 {
        self.month
    }

    /// The circuit's `today`: YYMM as an integer, e.g. `2609`.
    pub(crate) fn yymm(self) -> u16 {
        u16::from(self.yy).saturating_mul(100).saturating_add(self.month.into())
    }
}

/// Transaction data that Visa fDDA signs. The prover's tap must send these values in the
/// GPO PDOL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Amount, Authorised `9F02`: 12 BCD digits, minor units.
    pub amount: [u8; 6],
    /// Transaction Currency Code `5F2A`: ISO 4217 numeric code in BCD, e.g. `[0x08, 0x40]`
    /// for USD.
    pub currency: [u8; 2],
}

/// [`Challenge`] state: issued by the verifier, which keeps it.
///
/// Not `Clone`, and [`VerifyingKey::verify`](crate::VerifyingKey::verify) consumes the
/// challenge, so an issued challenge verifies at most one proof.
#[derive(Debug, PartialEq, Eq)]
pub enum Issued {}

/// [`Challenge`] state: received by the prover, from [`Challenge::from_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Received {}

/// What the verifier asks the card to sign: a random nonce, the current month and, for
/// Visa, the transaction.
///
/// The verifier creates a [`Challenge<Issued>`], keeps it in memory, and sends
/// [`Challenge::to_bytes`]. The prover reads that as a [`Challenge<Received>`], which can
/// prove but not verify. The nonce comes from the OS random number generator and can't be
/// chosen.
///
/// An issued challenge verifies once:
///
/// ```compile_fail,E0382
/// # use emv::{Challenge, Issued, Proof, VerifyingKey};
/// fn verify_twice(vk: &VerifyingKey, c: Challenge<Issued>, ca: &[u8], proof: &Proof) {
///     let _ = vk.verify(c, ca, proof);
///     let _ = vk.verify(c, ca, proof);
/// }
/// ```
///
/// ```compile_fail,E0599
/// # use emv::{Challenge, Issued};
/// fn copy(c: &Challenge<Issued>) -> Challenge<Issued> {
///     c.clone()
/// }
/// ```
///
/// A received challenge can't verify:
///
/// ```compile_fail,E0308
/// # use emv::{Challenge, Proof, Received, VerifyingKey};
/// fn verify_received(vk: &VerifyingKey, c: Challenge<Received>, ca: &[u8], proof: &Proof) {
///     let _ = vk.verify(c, ca, proof);
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge<S> {
    fields: Fields,
    state: PhantomData<S>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fields {
    pub(crate) scheme: Scheme,
    pub(crate) nonce: [u8; 4],
    pub(crate) today: YearMonth,
    /// `Some` exactly for [`Scheme::VisaFdda`].
    pub(crate) transaction: Option<Transaction>,
}

impl Challenge<Issued> {
    /// Issues a challenge for [`Scheme::VisaFdda`]. The card signs `transaction`.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`]: the OS random number generator failed.
    pub fn visa_fdda(today: YearMonth, transaction: Transaction) -> Result<Self> {
        Self::issue(Scheme::VisaFdda, today, Some(transaction))
    }

    /// Issues a challenge for [`Scheme::MastercardDda`].
    ///
    /// # Errors
    ///
    /// [`Error::Rng`]: the OS random number generator failed.
    pub fn mastercard_dda(today: YearMonth) -> Result<Self> {
        Self::issue(Scheme::MastercardDda, today, None)
    }

    fn issue(scheme: Scheme, today: YearMonth, transaction: Option<Transaction>) -> Result<Self> {
        let mut nonce = [0; 4];
        getrandom::fill(&mut nonce).map_err(|e| Error::Rng(Box::new(e)))?;
        Ok(Self::new(Fields {
            scheme,
            nonce,
            today,
            transaction,
        }))
    }

    /// Encodes the challenge for the prover.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let Fields {
            scheme,
            nonce,
            today,
            transaction,
        } = self.fields;
        let tag = match scheme {
            Scheme::VisaFdda => VISA_FDDA,
            Scheme::MastercardDda => MASTERCARD_DDA,
        };
        let mut out = vec![tag];
        out.extend(nonce);
        out.extend([today.yy, today.month]);
        if let Some(t) = transaction {
            out.extend(t.amount);
            out.extend(t.currency);
        }
        out
    }

    pub(crate) fn into_fields(self) -> Fields {
        self.fields
    }
}

impl Challenge<Received> {
    /// Decodes the output of [`Challenge::to_bytes`].
    ///
    /// # Errors
    ///
    /// - [`Error::Challenge`]: unknown scheme, or the wrong length for the scheme.
    /// - [`Error::YearMonth`]: the month is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut rest = bytes;

        let [tag] = take(&mut rest)?;
        let nonce = take(&mut rest)?;
        let [yy, month] = take(&mut rest)?;

        let today = YearMonth::new(2000u16.saturating_add(yy.into()), month)?;
        let (scheme, transaction) = match tag {
            VISA_FDDA => (
                Scheme::VisaFdda,
                Some(Transaction {
                    amount: take(&mut rest)?,
                    currency: take(&mut rest)?,
                }),
            ),
            MASTERCARD_DDA => (Scheme::MastercardDda, None),
            _ => return Err(Error::Challenge("unknown scheme")),
        };

        if !rest.is_empty() {
            return Err(Error::Challenge("trailing bytes"));
        }

        Ok(Self::new(Fields {
            scheme,
            nonce,
            today,
            transaction,
        }))
    }
}

impl<S> Challenge<S> {
    fn new(fields: Fields) -> Self {
        Self { fields, state: PhantomData }
    }

    /// The scheme whose card must answer.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.fields.scheme
    }

    /// Unpredictable Number `9F37` for the tap.
    #[must_use]
    pub fn nonce(&self) -> [u8; 4] {
        self.fields.nonce
    }

    /// The month at which both certificates must be unexpired.
    #[must_use]
    pub fn today(&self) -> YearMonth {
        self.fields.today
    }

    /// `Some` for [`Scheme::VisaFdda`], `None` for [`Scheme::MastercardDda`].
    #[must_use]
    pub fn transaction(&self) -> Option<Transaction> {
        self.fields.transaction
    }

    pub(crate) fn fields(&self) -> &Fields {
        &self.fields
    }
}

fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>().ok_or(Error::Challenge("truncated"))?;
    *rest = tail;
    Ok(*head)
}
