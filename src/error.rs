/// Unified error type for all brigid-crypto operations.
///
/// Never includes secret material in error messages.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid master key: {0}")]
    InvalidMasterKey(&'static str),

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed")]
    Decrypt,

    #[error("signature verification failed")]
    Verify,

    #[error("KEM encapsulation failed")]
    Encapsulate,

    #[error("KEM decapsulation failed")]
    Decapsulate,

    #[error("invalid key material")]
    InvalidKey,

    #[error("hex decode failed")]
    HexDecode(#[from] hex::FromHexError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
