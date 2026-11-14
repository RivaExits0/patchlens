//! Patchlens hata tipleri.

use thiserror::Error;

/// Patchlens'in döndürdüğü tipize edilmiş hatalar.
#[derive(Debug, Error)]
pub enum PatchlensError {
    /// Dosya PE değil veya PE32 (x86).
    #[error("Dosya PE değil. Desteklenen: PE x64")]
    NotPe64,

    /// Desteklenmeyen mimari.
    #[error("Desteklenmeyen mimari: {0}. Desteklenen: PE x64")]
    UnsupportedArchitecture(String),

    /// Binary içinde aranan isim bulunamadı.
    #[error("Fonksiyon bulunamadı: {0}")]
    FunctionNotFound(String),

    /// Dosya okunamadı.
    #[error("Dosya okunamadı: {0}")]
    Io(String),
}

impl From<std::io::Error> for PatchlensError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
