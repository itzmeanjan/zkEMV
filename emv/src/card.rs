use crate::Scheme;

/// The public inputs. The verifier builds it from its own values, not from data the
/// prover sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// CA RSA modulus, big-endian, 248 bytes. The card selects its CA key by RID (first 5
    /// bytes of the AID) and index `8F`. The verifier must take it from a trusted table.
    pub ca_modulus: Vec<u8>,
    /// Unpredictable Number `9F37`. Random, one per session, chosen by the verifier.
    pub nonce: [u8; 4],
    /// Current month as the integer YYMM, e.g. `2609` for September 2026. A certificate is
    /// valid until the end of its expiry month.
    pub today: u16,
    /// `Some` for [`Scheme::VisaFdda`], `None` for [`Scheme::MastercardDda`].
    pub transaction: Option<Transaction>,
}

/// Transaction data that Visa fDDA signs. Must equal the values the terminal sent in the
/// GPO PDOL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Amount, Authorised `9F02`: 12 BCD digits, minor units.
    pub amount: [u8; 6],
    /// Transaction Currency Code `5F2A`: ISO 4217 numeric code in BCD, e.g. `[0x08, 0x40]`
    /// for USD.
    pub currency: [u8; 2],
}

/// The private inputs: the card's data from one tap. Each field is a TLV value, without
/// tag and length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Card {
    /// For [`Scheme::VisaFdda`].
    VisaFdda(VisaFdda),
    /// For [`Scheme::MastercardDda`].
    MastercardDda(MastercardDda),
}

/// Card data for [`Scheme::VisaFdda`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisaFdda {
    /// `90`, from READ RECORD. 248 bytes.
    pub issuer_cert: Vec<u8>,
    /// `9F32`, from READ RECORD. Must be 3.
    pub issuer_exponent: u8,
    /// `9F46`, from READ RECORD. 176 bytes.
    pub icc_cert: Vec<u8>,
    /// `9F47`, from READ RECORD. Must be 3.
    pub icc_exponent: u8,
    /// `9F4B`, from the GPO response. 128 bytes.
    pub sdad: Vec<u8>,
    /// `9F69`, from the GPO response. 7 bytes.
    pub card_auth_data: Vec<u8>,
}

/// Card data for [`Scheme::MastercardDda`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MastercardDda {
    /// `90`, from READ RECORD. 248 bytes.
    pub issuer_cert: Vec<u8>,
    /// `92`, from READ RECORD. 28 bytes.
    pub issuer_remainder: Vec<u8>,
    /// `9F32`, from READ RECORD. Must be 3.
    pub issuer_exponent: u8,
    /// `9F46`, from READ RECORD. 240 bytes.
    pub icc_cert: Vec<u8>,
    /// `9F47`, from READ RECORD. Must be 3.
    pub icc_exponent: u8,
    /// Static data to be authenticated (EMV Book 3, 10.3). At most 256 bytes. The template
    /// `70` value of each record that the AFL marks for offline data authentication, in AFL
    /// order, then the AIP `82` if `9F4A` is `82`.
    pub static_data: Vec<u8>,
    /// `9F4B`, from INTERNAL AUTHENTICATE with the nonce as DDOL data. 144 bytes.
    pub sdad: Vec<u8>,
}

impl Card {
    /// The scheme whose circuit proves this card.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        match self {
            Self::VisaFdda(_) => Scheme::VisaFdda,
            Self::MastercardDda(_) => Scheme::MastercardDda,
        }
    }
}
