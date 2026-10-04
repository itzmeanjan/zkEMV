use crate::Scheme;

/// The private inputs: the card's data from a tap with the challenge's nonce. Each field is
/// a TLV value, without tag and length.
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
    /// `90`, from READ RECORD. As long as the CA modulus.
    pub issuer_pubkey_cert: Vec<u8>,
    /// `9F32`, from READ RECORD. Must be 3.
    pub issuer_pubkey_exponent: u8,
    /// `9F46`, from READ RECORD. As long as the issuer modulus.
    pub icc_pubkey_cert: Vec<u8>,
    /// `9F47`, from READ RECORD. Must be 3.
    pub icc_pubkey_exponent: u8,
    /// `9F4B`, from the GPO response. As long as the ICC modulus.
    pub signed_dynamic_app_data: Vec<u8>,
    /// `9F69`, from the GPO response. The circuit's `CARD_AUTH_RELATED_DATA_BYTE_LEN` bytes.
    pub card_auth_related_data: Vec<u8>,
}

/// Card data for [`Scheme::MastercardDda`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MastercardDda {
    /// `90`, from READ RECORD. As long as the CA modulus.
    pub issuer_pubkey_cert: Vec<u8>,
    /// `92`, from READ RECORD. The issuer modulus bytes its certificate has no room for.
    pub issuer_pubkey_remainder: Vec<u8>,
    /// `9F32`, from READ RECORD. Must be 3.
    pub issuer_pubkey_exponent: u8,
    /// `9F46`, from READ RECORD. As long as the issuer modulus.
    pub icc_pubkey_cert: Vec<u8>,
    /// `9F47`, from READ RECORD. Must be 3.
    pub icc_pubkey_exponent: u8,
    /// Static data to be authenticated (EMV Book 3, 10.3). At most the circuit's `STATIC_DATA_MAX_BYTE_LEN` bytes. The template
    /// `70` value of each record that the AFL marks for offline data authentication, in AFL
    /// order, then the AIP `82` if `9F4A` is `82`.
    pub static_data_to_authenticate: Vec<u8>,
    /// `9F4B`, from INTERNAL AUTHENTICATE with the nonce as DDOL data. As long as the ICC modulus.
    pub signed_dynamic_app_data: Vec<u8>,
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
