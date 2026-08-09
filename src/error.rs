/// Unified error type for all brigid-crypto operations.
///
/// Never includes secret material in error messages — including `Debug`.
/// `hex::FromHexError`'s own `Debug` impl embeds the offending character and
/// its byte index, which for `HexDecode` (raised while parsing
/// `BRIGID_MASTER_KEY`) would leak a fragment of the master key into any
/// `{:?}`-formatted log or panic message (e.g. `.expect()` call sites).
/// `Debug` is implemented manually below to delegate to the redacted
/// `Display` output instead of deriving it.
#[derive(thiserror::Error)]
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

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
