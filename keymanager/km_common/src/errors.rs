use crate::crypto;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyManagerError {
    Success = 0,
    GenericError = -1,
    InvalidArgument = -2,
    BufferTooSmall = -3,
    KeyNotFound = -4,
    DecapsulationFailed = -5,
    SealingFailed = -6,
    DecryptionFailed = -7,
    InternalError = -8,
    Panic = -9,
    InvalidKey = -10,
}

impl From<crypto::Error> for KeyManagerError {
    fn from(err: crypto::Error) -> Self {
        match err {
            crypto::Error::KeyLenMismatch => KeyManagerError::BufferTooSmall,
            crypto::Error::DecapsError => KeyManagerError::DecapsulationFailed,
            crypto::Error::HpkeDecryptionError => KeyManagerError::DecryptionFailed,
            crypto::Error::HpkeEncryptionError => KeyManagerError::SealingFailed,
            crypto::Error::UnsupportedAlgorithm => KeyManagerError::InvalidArgument,
            crypto::Error::InvalidKey => KeyManagerError::InvalidKey,
            crypto::Error::CryptoError => KeyManagerError::InternalError,
        }
    }
}

impl From<KeyManagerError> for i32 {
    fn from(err: KeyManagerError) -> Self {
        err as i32
    }
}
