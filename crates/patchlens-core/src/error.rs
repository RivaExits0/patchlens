//! Patchlens error types.

use thiserror::Error;

/// Typed errors returned by Patchlens.
#[derive(Debug, Error)]
pub enum PatchlensError {
    /// The file is not a PE32+ (x64) binary.
    #[error("Not a PE file. Supported: PE x64")]
    NotPe64,

    /// Unsupported architecture.
    #[error("Unsupported architecture: {0}. Supported: PE x64")]
    UnsupportedArchitecture(String),

    /// The requested function was not found.
    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    /// The file could not be read.
    #[error("Could not read file: {0}")]
    Io(String),
}

impl From<std::io::Error> for PatchlensError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
