//! Supported MAC and encryption algorithms

use crate::Error;
use const_oid::{
    ObjectIdentifier,
    db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512},
};

/// Supported MAC algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacAlgorithm {
    /// HMAC SHA256
    HmacSha256,
    /// HMAC SHA384
    HmacSha384,
    /// HMAC SHA512
    HmacSha512,
}

impl TryFrom<ObjectIdentifier> for MacAlgorithm {
    type Error = Error;

    /// Attempt to map an OID to a [`MacAlgorithm`] variant. Returns an error if the OID is not
    /// one of the supported HMAC-SHA-2 algorithms.
    fn try_from(value: ObjectIdentifier) -> Result<Self, Self::Error> {
        match value {
            ID_SHA_256 => Ok(Self::HmacSha256),
            ID_SHA_384 => Ok(Self::HmacSha384),
            ID_SHA_512 => Ok(Self::HmacSha512),
            _ => Err(Error::Pkcs12Builder(format!(
                "{} is not a recognized MAC algorithm",
                value
            ))),
        }
    }
}
impl MacAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            MacAlgorithm::HmacSha256 => ID_SHA_256,
            MacAlgorithm::HmacSha384 => ID_SHA_384,
            MacAlgorithm::HmacSha512 => ID_SHA_512,
        }
    }

    /// Return the output size of the associated digest algorithm.
    pub fn output_size(&self) -> usize {
        match self {
            MacAlgorithm::HmacSha256 => 32,
            MacAlgorithm::HmacSha384 => 48,
            MacAlgorithm::HmacSha512 => 64,
        }
    }

    /// Return DER-encoded parameters for inclusion in an `AlgorithmIdentifier`. For all supported
    /// HMAC-SHA-2 algorithms this is a DER-encoded NULL (`0x05 0x00`).
    pub fn parameters(&self) -> Vec<u8> {
        vec![0x05, 0x00]
    }
}

/// Supported encryption algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncryptionAlgorithm {
    /// AES128 CBC
    Aes128Cbc,
    /// AES-192 CBC
    Aes192Cbc,
    /// AES-256 CBC
    Aes256Cbc,
}

impl EncryptionAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            EncryptionAlgorithm::Aes128Cbc => const_oid::db::rfc5911::ID_AES_128_CBC,
            EncryptionAlgorithm::Aes192Cbc => const_oid::db::rfc5911::ID_AES_192_CBC,
            EncryptionAlgorithm::Aes256Cbc => const_oid::db::rfc5911::ID_AES_256_CBC,
        }
    }
}
