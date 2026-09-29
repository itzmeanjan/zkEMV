use noirc_abi::Abi;

use crate::{Error, Result};

/// A circuit package in this repository's `circuits/`. Each scheme has its own key pair and fixed key widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Visa, fDDA. The GPO response signs the nonce, amount, currency and `9F69`.
    VisaFdda,
    /// Mastercard, DDA. The INTERNAL AUTHENTICATE response signs the nonce.
    MastercardDda,
}

impl Scheme {
    /// Registered Application Provider Identifier: the first 5 bytes of the scheme's AIDs.
    #[must_use]
    pub const fn rid(self) -> [u8; 5] {
        match self {
            Self::VisaFdda => [0xA0, 0x00, 0x00, 0x00, 0x03],
            Self::MastercardDda => [0xA0, 0x00, 0x00, 0x00, 0x04],
        }
    }

    /// CA modulus length in bits.
    #[must_use]
    pub const fn ca_bits(self) -> usize {
        1984
    }

    /// Issuer modulus length in bits. Cards with another length can't be proved.
    #[must_use]
    pub const fn issuer_bits(self) -> usize {
        match self {
            Self::VisaFdda => 1408,
            Self::MastercardDda => 1920,
        }
    }

    /// ICC modulus length in bits. Cards with another length can't be proved.
    #[must_use]
    pub const fn icc_bits(self) -> usize {
        match self {
            Self::VisaFdda => 1024,
            Self::MastercardDda => 1152,
        }
    }

    /// `main`'s parameters, in order.
    const fn parameters(self) -> &'static [&'static str] {
        match self {
            Self::VisaFdda => &[
                "ca_modulus",
                "nonce",
                "amount",
                "currency",
                "today",
                "scope",
                "ca_redc",
                "issuer_redc",
                "icc_redc",
                "issuer_cert",
                "issuer_exponent",
                "icc_cert",
                "icc_exponent",
                "sdad",
                "card_auth_data",
            ],
            Self::MastercardDda => &[
                "ca_modulus",
                "nonce",
                "today",
                "scope",
                "ca_redc",
                "issuer_redc",
                "icc_redc",
                "issuer_cert",
                "issuer_remainder",
                "issuer_exponent",
                "icc_cert",
                "icc_exponent",
                "static_data",
                "sdad",
            ],
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
