use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::{BinRoot, Disclosure, Error, Nullifier, Result, Scheme, nullifier};

const VISA_FDDA: u8 = 0x01;
const MASTERCARD_DDA: u8 = 0x02;

const SCOPE_UNLINKABLE: u8 = 0x00;
const SCOPE_VERIFIER: u8 = 0x01;
const SCOPE_EVENT: u8 = 0x02;

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

/// Which nullifier a proof carries.
///
/// Each side derives the circuit's scope from it and the verifier's origin, the prover from
/// the origin it authenticated, so a verifier can't ask for another verifier's scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// No nullifier: the prover draws a random scope. For card presence.
    Unlinkable,
    /// One nullifier per card at this verifier, e.g. for a free trial.
    Verifier,
    /// One nullifier per card per event of this verifier, e.g. for a poll. The bytes
    /// identify the event, e.g. a hash of its name.
    Event([u8; 32]),
}

impl Scope {
    fn kind(self) -> u8 {
        match self {
            Self::Unlinkable => SCOPE_UNLINKABLE,
            Self::Verifier => SCOPE_VERIFIER,
            Self::Event(_) => SCOPE_EVENT,
        }
    }

    /// The circuit's `scope`. `None` for [`Scope::Unlinkable`], whose scope the prover draws.
    fn derive(self, origin: &str) -> Option<Fr> {
        match self {
            Self::Unlinkable => None,
            Self::Verifier => Some(nullifier::scope(self.kind(), origin, None)),
            Self::Event(event) => Some(nullifier::scope(self.kind(), origin, Some(&event))),
        }
    }
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

/// What the verifier asks for: a card signature over a random nonce (for Visa, also the
/// transaction), certificates valid in the current month, a nullifier in a [`Scope`], and
/// optionally attributes of the card's range in a BIN table.
///
/// The verifier creates a [`Challenge<Issued>`], keeps it in memory, and sends
/// [`Challenge::to_bytes`]. The prover reads that as a [`Challenge<Received>`], which can
/// prove but not verify. The nonce comes from the OS random number generator and can't be
/// chosen.
///
/// An issued challenge verifies once:
///
/// ```compile_fail,E0382
/// # use emv::{CaKey, Challenge, Issued, Proof, VerifyingKey};
/// fn verify_twice(vk: &VerifyingKey, c: Challenge<Issued>, ca: &CaKey, proof: &Proof) {
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
/// # use emv::{CaKey, Challenge, Proof, Received, VerifyingKey};
/// fn verify_received(vk: &VerifyingKey, c: Challenge<Received>, ca: &CaKey, proof: &Proof) {
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
    pub(crate) scope: Scope,
    /// The circuit's `scope`; `None` only for an issued [`Scope::Unlinkable`].
    pub(crate) scope_value: Option<Fr>,
    /// `Some` exactly when an attribute is asked for.
    pub(crate) bin: Option<(BinRoot, Disclosure)>,
}

impl Challenge<Issued> {
    /// Issues a challenge for [`Scheme::VisaFdda`]. The card signs `transaction`.
    ///
    /// `origin` names the verifier, e.g. `example.com`, the same name the prover
    /// authenticates it by.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`]: the OS random number generator failed.
    pub fn visa_fdda(origin: &str, scope: Scope, today: YearMonth, transaction: Transaction) -> Result<Self> {
        Self::issue(origin, scope, Scheme::VisaFdda, today, Some(transaction))
    }

    /// Issues a challenge for [`Scheme::MastercardDda`]. `origin` as for
    /// [`Challenge::visa_fdda`].
    ///
    /// # Errors
    ///
    /// [`Error::Rng`]: the OS random number generator failed.
    pub fn mastercard_dda(origin: &str, scope: Scope, today: YearMonth) -> Result<Self> {
        Self::issue(origin, scope, Scheme::MastercardDda, today, None)
    }

    fn issue(origin: &str, scope: Scope, scheme: Scheme, today: YearMonth, transaction: Option<Transaction>) -> Result<Self> {
        Ok(Self::new(Fields {
            scheme,
            nonce: random()?,
            today,
            transaction,
            scope,
            scope_value: scope.derive(origin),
            bin: None,
        }))
    }

    /// Asks for `disclosure`'s attributes of the card's range in the BIN table with `root`.
    /// [`Disclosure::NONE`] asks for none.
    #[must_use]
    pub fn disclose(mut self, root: BinRoot, disclosure: Disclosure) -> Self {
        self.fields.bin = (!disclosure.is_empty()).then_some((root, disclosure));
        self
    }

    /// Encodes the challenge for the prover.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let Fields {
            scheme,
            nonce,
            today,
            transaction,
            scope,
            bin,
            ..
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
        out.push(scope.kind());
        if let Scope::Event(event) = scope {
            out.extend(event);
        }
        match bin {
            Some((root, disclosure)) => {
                out.push(disclosure.bits());
                out.extend(root.to_bytes());
            }
            None => out.push(Disclosure::NONE.bits()),
        }
        out
    }

    pub(crate) fn into_fields(self) -> Fields {
        self.fields
    }
}

impl Challenge<Received> {
    /// Decodes the output of [`Challenge::to_bytes`] from the verifier at `origin`.
    ///
    /// Pass the origin the prover authenticated the verifier by, e.g. the TLS server name,
    /// never one the verifier sent: the scope, and so the nullifier, derives from it. For
    /// [`Scope::Unlinkable`], draws a random scope instead.
    ///
    /// # Errors
    ///
    /// - [`Error::Challenge`]: unknown scheme, scope or disclosure, the wrong length for them,
    ///   or a BIN root that is not a field element.
    /// - [`Error::YearMonth`]: the month is invalid.
    /// - [`Error::Rng`]: the OS random number generator failed.
    pub fn from_bytes(bytes: &[u8], origin: &str) -> Result<Self> {
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
        let [kind] = take(&mut rest)?;
        let scope = match kind {
            SCOPE_UNLINKABLE => Scope::Unlinkable,
            SCOPE_VERIFIER => Scope::Verifier,
            SCOPE_EVENT => Scope::Event(take(&mut rest)?),
            _ => return Err(Error::Challenge("unknown scope")),
        };
        let [bits] = take(&mut rest)?;
        let disclosure = Disclosure::from_bits(bits).ok_or(Error::Challenge("unknown disclosure"))?;
        let bin = if disclosure.is_empty() {
            None
        } else {
            let root = BinRoot::from_bytes(take(&mut rest)?).ok_or(Error::Challenge("BIN root is not a field element"))?;
            Some((root, disclosure))
        };

        if !rest.is_empty() {
            return Err(Error::Challenge("trailing bytes"));
        }

        let scope_value = match scope.derive(origin) {
            Some(value) => value,
            None => Fr::from_be_bytes_mod_order(&random::<31>()?),
        };
        Ok(Self::new(Fields {
            scheme,
            nonce,
            today,
            transaction,
            scope,
            scope_value: Some(scope_value),
            bin,
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

    /// Nonce `9F37` for the tap.
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

    /// The nullifier the verifier asks for.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.fields.scope
    }

    /// The BIN table attributes the verifier asks for.
    #[must_use]
    pub fn disclosure(&self) -> Disclosure {
        self.fields.bin.map_or(Disclosure::NONE, |(_, d)| d)
    }

    /// The root of the BIN table the prover must use; `None` when no attribute is asked for.
    #[must_use]
    pub fn bin_root(&self) -> Option<BinRoot> {
        self.fields.bin.map(|(root, _)| root)
    }

    /// The nullifier a card whose ICC public key has `icc_modulus` gives for this challenge.
    /// Anyone who has read the card's ICC certificate can compute it.
    ///
    /// `None` for an issued [`Scope::Unlinkable`] challenge, whose scope the prover draws,
    /// or for a modulus longer than the circuit's 186 bytes.
    #[must_use]
    pub fn nullifier_of(&self, icc_modulus: &[u8]) -> Option<Nullifier> {
        nullifier::nullifier(icc_modulus, self.fields.scope_value?).map(Nullifier::from_field)
    }

    pub(crate) fn fields(&self) -> &Fields {
        &self.fields
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0; N];
    getrandom::fill(&mut out).map_err(|e| Error::Rng(Box::new(e)))?;
    Ok(out)
}

fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N]> {
    let (head, tail) = rest.split_first_chunk::<N>().ok_or(Error::Challenge("truncated"))?;
    *rest = tail;
    Ok(*head)
}
