#[derive(Debug)]
pub enum RnsError {
    OutOfMemory,
    InvalidArgument,
    IncorrectSignature,
    IncorrectHash,
    InvalidHash,
    CryptoError,
    PacketError,
    ConnectionError,
    IoError,
    SerializationError,
    LockError,
}

impl std::fmt::Display for RnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RnsError::OutOfMemory => write!(f, "Out of memory"),
            RnsError::InvalidArgument => write!(f, "Invalid argument"),
            RnsError::IncorrectSignature => write!(f, "Incorrect signature"),
            RnsError::IncorrectHash => write!(f, "Incorrect hash"),
            RnsError::InvalidHash => write!(f, "Invalid hash"),
            RnsError::CryptoError => write!(f, "Cryptography error"),
            RnsError::PacketError => write!(f, "Packet error"),
            RnsError::ConnectionError => write!(f, "Connection error"),
            RnsError::IoError => write!(f, "I/O error"),
            RnsError::SerializationError => write!(f, "Serialization error"),
            RnsError::LockError => write!(f, "Lock error"),
        }
    }
}

impl std::error::Error for RnsError {}
