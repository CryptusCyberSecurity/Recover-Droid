use std::io;
use thiserror::Error;

/// Core error types for the recover-cli tool.
#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Device or path not found: {0}")]
    DeviceNotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Unknown or unsupported filesystem: {0}")]
    UnknownFilesystem(String),

    #[error("Invalid boot sector: {0}")]
    InvalidBootSector(String),

    #[error("Corrupted FAT structure: {0}")]
    CorruptedFat(String),

    #[error("Unexpected End of File/Device reached")]
    UnexpectedEof,

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Parallel execution error: {0}")]
    ParallelError(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("General error: {0}")]
    General(String),
}

/// Specialized Result type for recovery operations.
pub type Result<T> = std::result::Result<T, RecoveryError>;
