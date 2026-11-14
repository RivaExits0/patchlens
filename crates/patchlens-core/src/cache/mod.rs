//! Analiz sonuçlarının önbelleğe alınması.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::binary::Binary;

/// Önbellek anahtarı: yol + boyut + değiştirilme zamanı.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    /// Normalize edilmiş dosya yolu.
    pub path: String,
    /// Dosya boyutu (byte).
    pub size: u64,
    /// Dosyanın son değiştirilme zamanı.
    pub modified: SystemTime,
}

impl CacheKey {
    /// Dosya yolundan anahtar üretir.
    pub fn from_path(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)?;
        let modified = metadata.modified()?;
        Ok(Self {
            path: normalize_path(path),
            size: metadata.len(),
            modified,
        })
    }
}

/// Yol normalizasyonu: mutlak yol + mümkünse kanonik yol.
fn normalize_path(path: &Path) -> String {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    std::fs::canonicalize(&absolute)
        .unwrap_or(absolute)
        .to_string_lossy()
        .to_string()
}

/// İş parçacığı güvenli analiz önbelleği.
pub struct AnalysisCache {
    inner: DashMap<CacheKey, Arc<Binary>>,
    max_entries: usize,
}

impl AnalysisCache {
    /// Varsayılan kapasite ile önbellek oluşturur.
    pub fn new() -> Self {
        Self::with_capacity(100)
    }

    /// Belirli kapasite ile önbellek oluşturur.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            inner: DashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Dosyayı önbellekten döndürür, yoksa yükleyip önbelleğe alır.
    pub async fn get_or_load(&self, path: &Path) -> Result<Arc<Binary>> {
        let key = CacheKey::from_path(path)?;

        if let Some(entry) = self.inner.get(&key) {
            tracing::debug!("Önbellek isabeti: {}", path.display());
            return Ok(entry.value().clone());
        }

        tracing::debug!("Önbellek ıskası, yükleniyor: {}", path.display());
        let binary = Binary::load(path)?;
        self.inner.insert(key, binary.clone());
        self.evict_if_needed();
        Ok(binary)
    }

    /// Kapasite aşılıyorsa bir girdiyi çıkarır.
    fn evict_if_needed(&self) {
        while self.inner.len() > self.max_entries {
            let Some(entry) = self.inner.iter().next() else {
                break;
            };
            self.inner.remove(entry.key());
        }
    }

    /// Önbelleği temizler.
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// Önbellek istatistikleri.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.inner.len(),
            max_entries: self.max_entries,
        }
    }

    /// Önbellekteki bir girdiyi yola göre bulur.
    pub fn get_by_path(&self, path: &Path) -> Option<Arc<Binary>> {
        let key = CacheKey::from_path(path).ok()?;
        self.inner.get(&key).map(|entry| entry.value().clone())
    }
}

impl Default for AnalysisCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Önbellek istatistikleri.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Önbellekteki girdi sayısı.
    pub entries: usize,
    /// Maksimum kapasite.
    pub max_entries: usize,
}

/// Binary için önbellek anahtarı üretme yardımcısı.
pub trait BinaryCacheExt {
    /// Binary'nin önbellek anahtarını üretir.
    fn cache_key(&self) -> Result<CacheKey>;
}

impl BinaryCacheExt for Binary {
    fn cache_key(&self) -> Result<CacheKey> {
        CacheKey::from_path(&PathBuf::from(self.path()))
    }
}
