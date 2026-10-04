use crate::{
    bin_table::{bin_attributes, BinAttributes, BinMembership},
    ISSUER_ID_BYTE_LEN,
    nullifier::nullifier,
    PAN_BYTE_LEN,
    policy::{assert_issuer_id_matches_pan, assert_not_expired},
    rsa::{LIMB_BYTE_LEN, RsaKey},
    verify_icc_cert,
    verify_issuer_cert,
    verify_sdad,
};

pub struct CaKey<let B: u32> {
    key: RsaKey<B>,
}

pub struct RecoveredIssuerCert<let L: u32> {
    bytes: [u8; L],
}

pub struct IssuerCert<let K: u32> {
    modulus: [u8; K],
    issuer_id: [u8; ISSUER_ID_BYTE_LEN],
}

pub struct IssuerKey<let K: u32> {
    key: RsaKey<K>,
    issuer_id: [u8; ISSUER_ID_BYTE_LEN],
}

pub struct RecoveredIccCert<let L: u32> {
    bytes: [u8; L],
    issuer_id: [u8; ISSUER_ID_BYTE_LEN],
}

pub struct IccCert<let K: u32> {
    modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

pub struct IccKey<let K: u32> {
    key: RsaKey<K>,
    modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

pub struct RecoveredSdad<let K: u32> {
    bytes: [u8; K],
    icc_modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

pub struct AuthenticatedCard<let K: u32> {
    icc_modulus: [u8; K],
    pan: [u8; PAN_BYTE_LEN],
}

impl<let B: u32> CaKey<B> {
    /// The public CA modulus, which the verifier compares with its CA table.
    pub fn from_limbs(n: [Field; (B + LIMB_BYTE_LEN - 1) / LIMB_BYTE_LEN]) -> Self {
        CaKey { key: RsaKey::from_limbs(n) }
    }

    pub fn recover_issuer_cert(self, cert: [u8; B]) -> RecoveredIssuerCert<B> {
        RecoveredIssuerCert { bytes: self.key.recover(cert) }
    }
}

impl<let L: u32> RecoveredIssuerCert<L> {
    pub fn verify<let K: u32, let REM: u32>(self, remainder: [u8; REM], exponent: u8, today: u32) -> IssuerCert<K> {
        let fields = verify_issuer_cert::<L, K, REM>(self.bytes, remainder, exponent);
        assert_not_expired(fields.expiry, today);
        IssuerCert { modulus: fields.modulus, issuer_id: fields.issuer_id }
    }
}

impl<let K: u32> IssuerCert<K> {
    pub fn key(self) -> IssuerKey<K> {
        IssuerKey { key: RsaKey::from_be_bytes(self.modulus), issuer_id: self.issuer_id }
    }
}

impl<let K: u32> IssuerKey<K> {
    pub fn recover_icc_cert(self, cert: [u8; K]) -> RecoveredIccCert<K> {
        RecoveredIccCert { bytes: self.key.recover(cert), issuer_id: self.issuer_id }
    }
}

impl<let L: u32> RecoveredIccCert<L> {
    pub fn verify<let K: u32, let REM: u32, let S: u32>(self, remainder: [u8; REM], exponent: u8, static_data: BoundedVec<u8, S>, today: u32) -> IccCert<K> {
        let fields = verify_icc_cert::<L, K, REM, S>(self.bytes, remainder, exponent, static_data);
        assert_issuer_id_matches_pan(self.issuer_id, fields.pan);
        assert_not_expired(fields.expiry, today);
        IccCert { modulus: fields.modulus, pan: fields.pan }
    }
}

impl<let K: u32> IccCert<K> {
    pub fn key(self) -> IccKey<K> {
        IccKey { key: RsaKey::from_be_bytes(self.modulus), modulus: self.modulus, pan: self.pan }
    }
}

impl<let K: u32> IccKey<K> {
    pub fn recover_sdad(self, sdad: [u8; K]) -> RecoveredSdad<K> {
        RecoveredSdad { bytes: self.key.recover(sdad), icc_modulus: self.modulus, pan: self.pan }
    }
}

impl<let K: u32> RecoveredSdad<K> {
    pub fn verify<let T: u32>(self, format: u8, terminal_data: [u8; T]) -> AuthenticatedCard<K> {
        verify_sdad(self.bytes, format, terminal_data);
        AuthenticatedCard { icc_modulus: self.icc_modulus, pan: self.pan }
    }
}

impl<let K: u32> AuthenticatedCard<K> {
    pub fn nullifier(self, scope: Field) -> Field {
        nullifier(self.icc_modulus, scope)
    }

    pub fn bin_attributes(self, root: Field, disclose: u8, membership: BinMembership) -> BinAttributes {
        bin_attributes(self.pan, root, disclose, membership)
    }
}
