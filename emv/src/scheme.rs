use noirc_abi::Abi;

use crate::{
    Error, Result,
    layout::{BITS_PER_BYTE, RID_BYTE_LEN},
};

/// The circuits' `CA_PUBKEY_BIT_LEN` and each one's `ISSUER_PUBKEY_BIT_LEN` and `ICC_PUBKEY_BIT_LEN`.
const CA_PUBKEY_BIT_LEN: usize = 1984;
const VISA_ISSUER_PUBKEY_BIT_LEN: usize = 1408;
const VISA_ICC_PUBKEY_BIT_LEN: usize = 1024;
const MASTERCARD_ISSUER_PUBKEY_BIT_LEN: usize = 1920;
const MASTERCARD_ICC_PUBKEY_BIT_LEN: usize = 1152;

/// A circuit package in this repository's `circuits/`. Each scheme has its own key pair and fixed key widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Visa, fDDA. The GPO response signs the nonce, amount, currency and `9F69`.
    VisaFdda,
    /// Mastercard, DDA. The INTERNAL AUTHENTICATE response signs the nonce.
    MastercardDda,
}

impl Scheme {
    /// Registered Application Provider Identifier: the first bytes of the scheme's AIDs.
    #[must_use]
    pub const fn rid(self) -> [u8; RID_BYTE_LEN] {
        match self {
            Self::VisaFdda => [0xA0, 0x00, 0x00, 0x00, 0x03],
            Self::MastercardDda => [0xA0, 0x00, 0x00, 0x00, 0x04],
        }
    }

    /// CA modulus length in bits.
    #[must_use]
    pub const fn ca_pubkey_bit_len(self) -> usize {
        CA_PUBKEY_BIT_LEN
    }

    /// Issuer modulus length in bits. Cards with another length can't be proved.
    #[must_use]
    pub const fn issuer_pubkey_bit_len(self) -> usize {
        match self {
            Self::VisaFdda => VISA_ISSUER_PUBKEY_BIT_LEN,
            Self::MastercardDda => MASTERCARD_ISSUER_PUBKEY_BIT_LEN,
        }
    }

    /// ICC modulus length in bits. Cards with another length can't be proved.
    #[must_use]
    pub const fn icc_pubkey_bit_len(self) -> usize {
        match self {
            Self::VisaFdda => VISA_ICC_PUBKEY_BIT_LEN,
            Self::MastercardDda => MASTERCARD_ICC_PUBKEY_BIT_LEN,
        }
    }

    pub(crate) const fn ca_pubkey_byte_len(self) -> usize {
        self.ca_pubkey_bit_len() / BITS_PER_BYTE
    }

    pub(crate) const fn issuer_pubkey_byte_len(self) -> usize {
        self.issuer_pubkey_bit_len() / BITS_PER_BYTE
    }

    /// `main`'s parameters, in order.
    const fn parameters(self) -> &'static [&'static str] {
        match self {
            Self::VisaFdda => &["trust_anchors", "challenge", "transaction", "card", "bin_membership"],
            Self::MastercardDda => &["trust_anchors", "challenge", "card", "bin_membership"],
        }
    }

    pub(crate) fn from_abi(abi: &Abi) -> Result<Self> {
        let names = abi.parameter_names();
        [Self::VisaFdda, Self::MastercardDda]
            .into_iter()
            .find(|s| names.iter().map(|n| n.as_str()).eq(s.parameters().iter().copied()))
            .ok_or_else(|| Error::UnknownCircuit(names.into_iter().cloned().collect()))
    }
}
