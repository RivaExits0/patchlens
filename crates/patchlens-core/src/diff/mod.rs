//! İki binary arasında fonksiyon eşleştirme (4 aşamalı).

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use rayon::prelude::*;

use crate::binary::Binary;
use crate::common::FunctionInfo;

/// Diff yapılandırması.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiffConfig {
    /// Bulanık eşleştirme için minimum benzerlik skoru (0.0 - 1.0).
    pub min_score: f64,
    /// Sayfalama için maksimum sonuç sayısı.
    pub limit: usize,
    /// Sayfalama için başlangıç offseti.
    pub offset: usize,
}

/// Sayfalamada kullanılabilecek maksimum sonuç sayısı.
pub const MAX_PAGE_SIZE: usize = 500;

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            min_score: 0.75,
            limit: 100,
            offset: 0,
        }
    }
}

impl DiffConfig {
    /// Minimum benzerlik skorunu ayarlar (0.0 - 1.0 aralığına kırpılır).
    pub fn with_min_score(mut self, score: f64) -> Self {
        self.min_score = score.clamp(0.0, 1.0);
        self
    }

    /// Sayfalama parametrelerini ayarlar.
    pub fn with_pagination(mut self, offset: usize, limit: usize) -> Self {
        self.offset = offset;
        self.limit = limit.min(MAX_PAGE_SIZE);
        self
    }

    /// Sayfalamayı tamamen kapatır; tüm sonuçlar döner.
    ///
    /// Rapor üretimi gibi "tam liste" gerektiren işlemler bunu kullanır.
    pub fn unpaginated() -> Self {
        Self {
            min_score: 0.75,
            limit: usize::MAX,
            offset: 0,
        }
    }
}

/// Sayfalama öncesi kategori toplamları.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct DiffTotals {
    /// Değişmeyen fonksiyon sayısı.
    pub unchanged: usize,
    /// Değişen fonksiyon sayısı.
    pub modified: usize,
    /// Eklenen fonksiyon sayısı.
    pub added: usize,
    /// Kaldırılan fonksiyon sayısı.
    pub removed: usize,
}

impl DiffTotals {
    /// Toplam eşleşme sayısı.
    pub fn total(&self) -> usize {
        self.unchanged + self.modified + self.added + self.removed
    }
}

/// Diff sonucu.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiffResult {
    /// Değişmeyen fonksiyonlar.
    pub unchanged: Vec<FunctionMatch>,
    /// Değişen fonksiyonlar.
    pub modified: Vec<FunctionMatch>,
    /// Yeni build'de eklenen fonksiyonlar.
    pub added: Vec<FunctionMatch>,
    /// Yeni build'de kaldırılan fonksiyonlar.
    pub removed: Vec<FunctionMatch>,
    /// Eski binary'deki toplam fonksiyon sayısı.
    pub old_total: usize,
    /// Yeni binary'deki toplam fonksiyon sayısı.
    pub new_total: usize,
    /// Sayfalama öncesi kategori toplamları.
    pub totals: DiffTotals,
    /// Diff zaman damgası (RFC3339).
    pub timestamp: String,
}

/// Eşleşen fonksiyon çifti.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionMatch {
    /// Eski fonksiyon (eklenen fonksiyonlarda `None`).
    pub old: Option<FunctionInfo>,
    /// Yeni fonksiyon (kaldırılan fonksiyonlarda `None`).
    pub new: Option<FunctionInfo>,
    /// Eşleştirme yöntemi.
    pub kind: MatchKind,
    /// Benzerlik skoru (0.0 - 1.0).
    pub score: f64,
    /// Değişen basic block sayısı (tahmini).
    pub changed_blocks: usize,
}

/// Fonksiyonun nasıl eşleştirildiği.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MatchKind {
    /// Bayt bayt aynı.
    Exact,
    /// Normalleştirilmiş opcode hash'i aynı, baytlar farklı.
    Normalized,
    /// String referansları ve import'lar üzerinden eşleşti.
    StringImport,
    /// Çağrı grafiği yayılımı ile eşleşti.
    CallGraph,
    /// Bulanık opcode benzerliği ile eşleşti.
    Fuzzy,
    /// Eşleşme bulunamadı.
    None,
}

impl MatchKind {
    /// Eşleşmenin değişiklik üretip üretmediğini döner.
    pub fn is_modified(self) -> bool {
        matches!(
            self,
            MatchKind::Normalized
                | MatchKind::StringImport
                | MatchKind::CallGraph
                | MatchKind::Fuzzy
        )
    }
}

/// İki binary'yi karşılaştırır ve diff sonucu üretir.
pub fn diff_binaries(old: &Binary, new: &Binary, config: DiffConfig) -> DiffResult {
    let old_functions = old.functions();
    let new_functions = new.functions();

    let mut old_matched = vec![false; old_functions.len()];
    let mut new_matched = vec![false; new_functions.len()];
    let mut matches: Vec<FunctionMatch> = Vec::new();

    // Aşama 1: birebir aynı baytlar.
    exact_phase(
        old_functions,
        new_functions,
        &mut old_matched,
        &mut new_matched,
        &mut matches,
    );

    // Aşama 2: aynı normalleştirilmiş opcode hash'i (baytlar değişmiş olabilir).
    normalized_phase(
        old_functions,
        new_functions,
        &mut old_matched,
        &mut new_matched,
        &mut matches,
    );

    // Aşama 3: string referansları + import çağrıları.
    string_import_phase(
        old_functions,
        new_functions,
        &mut old_matched,
        &mut new_matched,
        &mut matches,
        config.min_score,
    );

    // Aşama 4: çağrı grafiği yayılımı.
    let mut old_to_new: HashMap<u64, u64> = HashMap::new();
    for m in &matches {
        if let (Some(old_f), Some(new_f)) = (&m.old, &m.new) {
            old_to_new.insert(old_f.address, new_f.address);
        }
    }
    call_graph_phase(
        old_functions,
        new_functions,
        &mut old_matched,
        &mut new_matched,
        &mut matches,
        &old_to_new,
        config.min_score,
    );

    // Aşama 5: bulanık opcode benzerliği.
    fuzzy_phase(
        old_functions,
        new_functions,
        &mut old_matched,
        &mut new_matched,
        &mut matches,
        config.min_score,
    );

    let mut result = DiffResult {
        unchanged: Vec::new(),
        modified: Vec::new(),
        added: Vec::new(),
        removed: Vec::new(),
        old_total: old_functions.len(),
        new_total: new_functions.len(),
        totals: DiffTotals::default(),
        timestamp: Utc::now().to_rfc3339(),
    };

    for m in matches {
        if m.kind == MatchKind::Exact {
            result.unchanged.push(m);
        } else if m.kind.is_modified() {
            result.modified.push(m);
        }
    }

    for (idx, matched) in old_matched.iter().enumerate() {
        if !matched {
            result.removed.push(FunctionMatch {
                old: Some(old_functions[idx].clone()),
                new: None,
                kind: MatchKind::None,
                score: 0.0,
                changed_blocks: 0,
            });
        }
    }

    for (idx, matched) in new_matched.iter().enumerate() {
        if !matched {
            result.added.push(FunctionMatch {
                old: None,
                new: Some(new_functions[idx].clone()),
                kind: MatchKind::None,
                score: 0.0,
                changed_blocks: 0,
            });
        }
    }

    sort_matches(&mut result.unchanged);
    sort_matches(&mut result.modified);
    sort_matches(&mut result.added);
    sort_matches(&mut result.removed);

    // Sayfalama öncesi toplamları sakla (MCP/rapor katmanı bunları kullanır).
    result.totals = DiffTotals {
        unchanged: result.unchanged.len(),
        modified: result.modified.len(),
        added: result.added.len(),
        removed: result.removed.len(),
    };

    result.apply_pagination(config.offset, config.limit);
    result
}

/// Aşama 1: birebir aynı baytlar.
fn exact_phase(
    old_functions: &[FunctionInfo],
    new_functions: &[FunctionInfo],
    old_matched: &mut [bool],
    new_matched: &mut [bool],
    matches: &mut Vec<FunctionMatch>,
) {
    let mut buckets: HashMap<(u64, Vec<u8>), Vec<usize>> = HashMap::new();
    for (idx, func) in old_functions.iter().enumerate() {
        buckets
            .entry((func.opcode_hash, func.bytes.clone()))
            .or_default()
            .push(idx);
    }

    for (new_idx, new_func) in new_functions.iter().enumerate() {
        if new_matched[new_idx] {
            continue;
        }
        let key = (new_func.opcode_hash, new_func.bytes.clone());
        let Some(candidates) = buckets.get(&key) else {
            continue;
        };
        for &old_idx in candidates {
            if old_matched[old_idx] {
                continue;
            }
            old_matched[old_idx] = true;
            new_matched[new_idx] = true;
            matches.push(FunctionMatch {
                old: Some(old_functions[old_idx].clone()),
                new: Some(new_func.clone()),
                kind: MatchKind::Exact,
                score: 1.0,
                changed_blocks: 0,
            });
            break;
        }
    }
}

/// Aşama 2: aynı normalleştirilmiş opcode hash'i.
fn normalized_phase(
    old_functions: &[FunctionInfo],
    new_functions: &[FunctionInfo],
    old_matched: &mut [bool],
    new_matched: &mut [bool],
    matches: &mut Vec<FunctionMatch>,
) {
    let mut buckets: HashMap<u64, Vec<usize>> = HashMap::new();
    for (idx, func) in old_functions.iter().enumerate() {
        buckets.entry(func.opcode_hash).or_default().push(idx);
    }

    for (new_idx, new_func) in new_functions.iter().enumerate() {
        if new_matched[new_idx] {
            continue;
        }
        let Some(candidates) = buckets.get(&new_func.opcode_hash) else {
            continue;
        };
        for &old_idx in candidates {
            if old_matched[old_idx] {
                continue;
            }
            old_matched[old_idx] = true;
            new_matched[new_idx] = true;
            matches.push(FunctionMatch {
                old: Some(old_functions[old_idx].clone()),
                new: Some(new_func.clone()),
                kind: MatchKind::Normalized,
                score: 0.95,
                changed_blocks: estimate_changed_blocks(&old_functions[old_idx], new_func),
            });
            break;
        }
    }
}

/// Aşama 3: string referansları ve import çağrıları.
fn string_import_phase(
    old_functions: &[FunctionInfo],
    new_functions: &[FunctionInfo],
    old_matched: &mut [bool],
    new_matched: &mut [bool],
    matches: &mut Vec<FunctionMatch>,
    min_score: f64,
) {
    let mut string_buckets: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut import_buckets: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, func) in old_functions.iter().enumerate() {
        if old_matched[idx] {
            continue;
        }
        for &hash in &func.string_refs {
            string_buckets.entry(hash).or_default().push(idx);
        }
        for import in &func.import_calls {
            import_buckets.entry(import.as_str()).or_default().push(idx);
        }
    }

    for (new_idx, new_func) in new_functions.iter().enumerate() {
        if new_matched[new_idx] {
            continue;
        }
        let mut candidates: Vec<usize> = Vec::new();
        for &hash in &new_func.string_refs {
            if let Some(list) = string_buckets.get(&hash) {
                candidates.extend(list.iter().copied());
            }
        }
        for import in &new_func.import_calls {
            if let Some(list) = import_buckets.get(import.as_str()) {
                candidates.extend(list.iter().copied());
            }
        }
        candidates.sort_unstable();
        candidates.dedup();

        let mut best: Option<(usize, f64)> = None;
        for old_idx in candidates {
            if old_matched[old_idx] {
                continue;
            }
            let score = string_import_similarity(&old_functions[old_idx], new_func);
            if score >= min_score && best.map(|(_, b)| score > b).unwrap_or(true) {
                best = Some((old_idx, score));
            }
        }

        if let Some((old_idx, score)) = best {
            old_matched[old_idx] = true;
            new_matched[new_idx] = true;
            matches.push(FunctionMatch {
                old: Some(old_functions[old_idx].clone()),
                new: Some(new_func.clone()),
                kind: MatchKind::StringImport,
                score,
                changed_blocks: estimate_changed_blocks(&old_functions[old_idx], new_func),
            });
        }
    }
}

/// Aşama 4: çağrı grafiği yayılımı.
fn call_graph_phase(
    old_functions: &[FunctionInfo],
    new_functions: &[FunctionInfo],
    old_matched: &mut [bool],
    new_matched: &mut [bool],
    matches: &mut Vec<FunctionMatch>,
    old_to_new: &HashMap<u64, u64>,
    min_score: f64,
) {
    let old_candidates: Vec<usize> = (0..old_functions.len())
        .filter(|idx| !old_matched[*idx])
        .collect();
    let new_candidates: Vec<usize> = (0..new_functions.len())
        .filter(|idx| !new_matched[*idx])
        .collect();

    for &old_idx in &old_candidates {
        if old_matched[old_idx] {
            continue;
        }
        let old_func = &old_functions[old_idx];
        let mapped: HashSet<u64> = old_func
            .callees
            .iter()
            .filter_map(|callee| old_to_new.get(callee).copied())
            .collect();
        if mapped.is_empty() {
            continue;
        }

        let mut best: Option<(usize, f64)> = None;
        for &new_idx in &new_candidates {
            if new_matched[new_idx] {
                continue;
            }
            let new_func = &new_functions[new_idx];
            let new_callees: HashSet<u64> = new_func.callees.iter().copied().collect();
            if new_callees.is_empty() {
                continue;
            }
            let intersection = mapped.intersection(&new_callees).count();
            let union = mapped.union(&new_callees).count();
            if union == 0 {
                continue;
            }
            let score = intersection as f64 / union as f64;
            if score >= min_score && best.map(|(_, b)| score > b).unwrap_or(true) {
                best = Some((new_idx, score));
            }
        }

        if let Some((new_idx, score)) = best {
            old_matched[old_idx] = true;
            new_matched[new_idx] = true;
            matches.push(FunctionMatch {
                old: Some(old_func.clone()),
                new: Some(new_functions[new_idx].clone()),
                kind: MatchKind::CallGraph,
                score,
                changed_blocks: estimate_changed_blocks(old_func, &new_functions[new_idx]),
            });
        }
    }
}

/// Aşama 5: bulanık opcode benzerliği.
fn fuzzy_phase(
    old_functions: &[FunctionInfo],
    new_functions: &[FunctionInfo],
    old_matched: &mut [bool],
    new_matched: &mut [bool],
    matches: &mut Vec<FunctionMatch>,
    min_score: f64,
) {
    let old_candidates: Vec<usize> = (0..old_functions.len())
        .filter(|idx| !old_matched[*idx])
        .collect();
    let new_candidates: Vec<usize> = (0..new_functions.len())
        .filter(|idx| !new_matched[*idx])
        .collect();

    if old_candidates.is_empty() || new_candidates.is_empty() {
        return;
    }

    let best_matches: Vec<Option<(usize, f64)>> = old_candidates
        .par_iter()
        .map(|&old_idx| {
            let old_func = &old_functions[old_idx];
            let mut best: Option<(usize, f64)> = None;
            for &new_idx in &new_candidates {
                if new_matched[new_idx] {
                    continue;
                }
                let score = fuzzy_similarity(old_func, &new_functions[new_idx]);
                if score >= min_score && best.map(|(_, b)| score > b).unwrap_or(true) {
                    best = Some((new_idx, score));
                }
            }
            best
        })
        .collect();

    for (slot, &old_idx) in old_candidates.iter().enumerate() {
        if old_matched[old_idx] {
            continue;
        }
        let Some((new_idx, score)) = best_matches[slot] else {
            continue;
        };
        if new_matched[new_idx] {
            continue;
        }
        old_matched[old_idx] = true;
        new_matched[new_idx] = true;
        matches.push(FunctionMatch {
            old: Some(old_functions[old_idx].clone()),
            new: Some(new_functions[new_idx].clone()),
            kind: MatchKind::Fuzzy,
            score,
            changed_blocks: estimate_changed_blocks(
                &old_functions[old_idx],
                &new_functions[new_idx],
            ),
        });
    }
}

/// String ve import benzerliği (Jaccard).
fn string_import_similarity(old: &FunctionInfo, new: &FunctionInfo) -> f64 {
    let old_strings: HashSet<u64> = old.string_refs.iter().copied().collect();
    let new_strings: HashSet<u64> = new.string_refs.iter().copied().collect();
    let string_jaccard = jaccard(&old_strings, &new_strings);

    let old_imports: HashSet<&str> = old.import_calls.iter().map(|s| s.as_str()).collect();
    let new_imports: HashSet<&str> = new.import_calls.iter().map(|s| s.as_str()).collect();
    let import_jaccard = jaccard(&old_imports, &new_imports);

    0.6 * string_jaccard + 0.4 * import_jaccard
}

/// Jaccard benzerliği.
fn jaccard<T: std::hash::Hash + Eq>(a: &HashSet<T>, b: &HashSet<T>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Bulanık benzerlik skoru.
fn fuzzy_similarity(old: &FunctionInfo, new: &FunctionInfo) -> f64 {
    let max_len = old.bytes.len().max(new.bytes.len());
    let byte_score = if max_len == 0 {
        0.0
    } else {
        let common = old
            .bytes
            .iter()
            .zip(new.bytes.iter())
            .take(256)
            .filter(|(a, b)| a == b)
            .count();
        let compared = old.bytes.len().min(new.bytes.len()).min(256);
        if compared == 0 {
            0.0
        } else {
            common as f64 / compared as f64
        }
    };

    let size_score = if old.size == 0 || new.size == 0 {
        0.0
    } else {
        old.size.min(new.size) as f64 / old.size.max(new.size) as f64
    };

    let block_score = if old.block_count == 0 || new.block_count == 0 {
        0.0
    } else {
        old.block_count.min(new.block_count) as f64 / old.block_count.max(new.block_count) as f64
    };

    let hash_score = if old.opcode_hash == new.opcode_hash {
        1.0
    } else {
        0.0
    };

    0.4 * byte_score + 0.2 * size_score + 0.1 * block_score + 0.3 * hash_score
}

/// Değişen basic block sayısını tahmin eder.
fn estimate_changed_blocks(old: &FunctionInfo, new: &FunctionInfo) -> usize {
    if old.bytes == new.bytes {
        return 0;
    }
    let size_diff = (old.size as isize - new.size as isize).unsigned_abs();
    let common = old
        .bytes
        .iter()
        .zip(new.bytes.iter())
        .take(4096)
        .filter(|(a, b)| a == b)
        .count();
    let differing = old.bytes.len().min(new.bytes.len()).saturating_sub(common);
    (differing / 16).max(1).max(size_diff / 64)
}

/// Eşleşmeleri adrese göre sıralar.
fn sort_matches(matches: &mut [FunctionMatch]) {
    matches.sort_by_key(|m| {
        m.old
            .as_ref()
            .map(|f| f.address)
            .or_else(|| m.new.as_ref().map(|f| f.address))
            .unwrap_or(0)
    });
}

impl DiffResult {
    /// Sonuçlara sayfalama uygular.
    ///
    /// `limit` değeri `usize::MAX` ise sonuçlar kırpılmaz (sayfalama kapalı).
    pub fn apply_pagination(&mut self, offset: usize, limit: usize) {
        let paginate = |items: &mut Vec<FunctionMatch>| {
            let len = items.len();
            let start = offset.min(len);
            let end = start.saturating_add(limit).min(len);
            *items = items.drain(start..end).collect();
        };

        paginate(&mut self.unchanged);
        paginate(&mut self.modified);
        paginate(&mut self.added);
        paginate(&mut self.removed);
    }

    /// Sayfalama öncesi toplam eşleşme sayısı.
    pub fn total_matches(&self) -> usize {
        self.totals.total()
    }
}
