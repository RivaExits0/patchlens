//! patchlens-core: Binary analizi, fonksiyon çıkarımı, diff ve imza motoru.
//!
//! Bu crate yalnızca **statik** analiz yapar: hiçbir zaman hedef binary'yi
//! çalıştırmaz, dosyalara yalnızca salt-okunur erişir.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod binary;
pub mod cache;
pub mod common;
pub mod diff;
pub mod error;
pub mod function;
pub mod report;
pub mod signature;

use std::path::Path;
use std::sync::Arc;

pub use binary::{Binary, BinaryFormat, BinaryInfo, ExportInfo, ImportInfo, PeImage, SectionInfo};
pub use cache::{AnalysisCache, BinaryCacheExt, CacheKey, CacheStats};
pub use common::{generate_fingerprint, Fingerprint, FunctionInfo, InstructionInfo};
pub use diff::{
    diff_binaries, DiffConfig, DiffResult, DiffTotals, FunctionMatch, MatchKind, MAX_PAGE_SIZE,
};
pub use error::PatchlensError;
pub use function::{extract_functions, FunctionFingerprinter};
pub use report::{
    BasicBlockChange, ChangeExplanation, ChangeType, CiReport, DisassemblyLine, ExportFormat,
    InstructionChange,
};
pub use signature::{
    AobPattern, Signature, SignatureCheckResult, SignatureEngine, SignatureKind, SignatureMatch,
    SignatureSet, SignatureStatus,
};

/// İki binary karşılaştırmanın ana giriş noktası.
pub struct Patchlens {
    cache: AnalysisCache,
}

impl Patchlens {
    /// Varsayılan önbellek ile yeni bir örnek oluşturur.
    pub fn new() -> Self {
        Self {
            cache: AnalysisCache::new(),
        }
    }

    /// Özel önbellek ile yeni bir örnek oluşturur.
    pub fn with_cache(cache: AnalysisCache) -> Self {
        Self { cache }
    }

    /// Binary'yi yükler ve analiz eder (önbellek kullanılır).
    pub async fn analyze_binary(&self, path: &Path) -> anyhow::Result<Arc<Binary>> {
        self.cache.get_or_load(path).await
    }

    /// İki binary arasında diff üretir.
    pub fn diff(&self, old: &Binary, new: &Binary, config: DiffConfig) -> DiffResult {
        diff::diff_binaries(old, new, config)
    }

    /// İmzaları yeni binary'ye karşı kontrol eder.
    pub fn check_signatures(
        &self,
        binary: &Binary,
        signatures: &SignatureSet,
    ) -> Vec<SignatureCheckResult> {
        SignatureEngine::new().check(binary, signatures)
    }

    /// İmzaları kontrol eder ve kırık olanlar için öneri üretir.
    pub fn check_signatures_with_suggestions(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        signatures: &SignatureSet,
    ) -> Vec<SignatureCheckResult> {
        SignatureEngine::new().check_with_suggestions(old_binary, new_binary, signatures)
    }

    /// Kırık imzalar için yeni imzalar önerir.
    pub fn suggest_signatures(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        broken_signatures: &[Signature],
    ) -> Vec<Signature> {
        SignatureEngine::new().suggest(old_binary, new_binary, broken_signatures)
    }

    /// Bir fonksiyondaki değişimi açıklar.
    pub fn explain_change(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        function_addr: u64,
        limit: usize,
        offset: usize,
    ) -> anyhow::Result<report::ChangeExplanation> {
        report::explain_change(old_binary, new_binary, function_addr, limit, offset)
    }

    /// CI raporu üretir (SARIF/JSON/header/CT).
    pub fn generate_report(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        signatures: Option<&SignatureSet>,
        format: ExportFormat,
    ) -> anyhow::Result<String> {
        let diff = self.diff(old_binary, new_binary, DiffConfig::default());
        CiReport::generate(&diff, old_binary, new_binary, signatures, format)
    }

    /// Offset'leri dışa aktarır.
    pub fn export_offsets(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        signatures: &SignatureSet,
        format: ExportFormat,
    ) -> anyhow::Result<String> {
        report::export_offsets(old_binary, new_binary, signatures, format)
    }

    /// Önbellek istatistiklerini döndürür.
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }
}

impl Default for Patchlens {
    fn default() -> Self {
        Self::new()
    }
}
