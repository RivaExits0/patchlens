//! Rapor üretimi: SARIF, JSON, C header ve Cheat Engine `.CT`.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::binary::Binary;
use crate::common::FunctionInfo;
use crate::diff::{diff_binaries, DiffConfig, DiffResult, FunctionMatch};
use crate::function::FunctionFingerprinter;
use crate::signature::{SignatureCheckResult, SignatureEngine, SignatureSet, SignatureStatus};

/// Çıktı formatı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// JSON raporu.
    Json,
    /// SARIF 2.1.0 raporu.
    Sarif,
    /// C header (`#define`).
    CHeader,
    /// Cheat Engine tablosu (`.CT`).
    CheatEngineCt,
}

impl ExportFormat {
    /// Format adını döndürür.
    pub fn as_str(self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Sarif => "sarif",
            ExportFormat::CHeader => "header",
            ExportFormat::CheatEngineCt => "ct",
        }
    }
}

/// CI rapor üreteci.
pub struct CiReport;

impl CiReport {
    /// Belirtilen formatta CI raporu üretir.
    pub fn generate(
        diff: &DiffResult,
        old_binary: &Binary,
        new_binary: &Binary,
        signatures: Option<&SignatureSet>,
        format: ExportFormat,
    ) -> Result<String> {
        match format {
            ExportFormat::Json => Self::generate_json(diff, old_binary, new_binary, signatures),
            ExportFormat::Sarif => Self::generate_sarif(diff, old_binary, new_binary, signatures),
            ExportFormat::CHeader => Ok(Self::generate_c_header(diff, old_binary, new_binary)),
            ExportFormat::CheatEngineCt => {
                Ok(Self::generate_cheat_engine(diff, old_binary, new_binary))
            }
        }
    }

    /// JSON raporu üretir.
    pub fn generate_json(
        diff: &DiffResult,
        old_binary: &Binary,
        new_binary: &Binary,
        signatures: Option<&SignatureSet>,
    ) -> Result<String> {
        let signature_results = signatures.map(|set| SignatureEngine::new().check(new_binary, set));

        let report = json!({
            "metadata": {
                "tool": "patchlens",
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": diff.timestamp,
                "old_binary": old_binary.path().to_string_lossy(),
                "new_binary": new_binary.path().to_string_lossy(),
            },
            "summary": {
                "old_total": diff.old_total,
                "new_total": diff.new_total,
                "unchanged": diff.totals.unchanged,
                "modified": diff.totals.modified,
                "added": diff.totals.added,
                "removed": diff.totals.removed,
            },
            "functions": {
                "unchanged": diff.unchanged,
                "modified": diff.modified,
                "added": diff.added,
                "removed": diff.removed,
            },
            "signatures": signature_results,
        });
        Ok(serde_json::to_string_pretty(&report)?)
    }

    /// SARIF 2.1.0 raporu üretir.
    pub fn generate_sarif(
        diff: &DiffResult,
        old_binary: &Binary,
        new_binary: &Binary,
        signatures: Option<&SignatureSet>,
    ) -> Result<String> {
        let mut results: Vec<serde_json::Value> = Vec::new();

        for m in &diff.modified {
            let (Some(old_f), Some(new_f)) = (&m.old, &m.new) else {
                continue;
            };
            results.push(json!({
                "ruleId": "function-modified",
                "level": "warning",
                "message": {
                    "text": format!(
                        "Fonksiyon {} değişti (benzerlik: {:.1}%)",
                        display_name(old_f),
                        m.score * 100.0
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": new_binary.path().to_string_lossy() },
                        "region": { "startColumn": 1, "startLine": 1 }
                    }
                }],
                "properties": {
                    "old_address": format!("0x{:X}", old_f.address),
                    "new_address": format!("0x{:X}", new_f.address),
                    "similarity": m.score,
                    "changed_blocks": m.changed_blocks,
                    "match_kind": format!("{:?}", m.kind),
                }
            }));
        }

        for m in &diff.removed {
            let Some(old_f) = &m.old else { continue };
            results.push(json!({
                "ruleId": "function-removed",
                "level": "error",
                "message": {
                    "text": format!("Fonksiyon {} yeni build'de kaldırıldı", display_name(old_f))
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": old_binary.path().to_string_lossy() },
                        "region": { "startColumn": 1, "startLine": 1 }
                    }
                }],
                "properties": { "old_address": format!("0x{:X}", old_f.address) }
            }));
        }

        for m in &diff.added {
            let Some(new_f) = &m.new else { continue };
            results.push(json!({
                "ruleId": "function-added",
                "level": "note",
                "message": {
                    "text": format!("Fonksiyon {} yeni build'de eklendi", display_name(new_f))
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": new_binary.path().to_string_lossy() },
                        "region": { "startColumn": 1, "startLine": 1 }
                    }
                }],
                "properties": { "new_address": format!("0x{:X}", new_f.address) }
            }));
        }

        if let Some(set) = signatures {
            let checks = SignatureEngine::new().check(new_binary, set);
            for check in &checks {
                let level = match check.status {
                    SignatureStatus::Broken => "error",
                    SignatureStatus::Ambiguous => "error",
                    SignatureStatus::Moved => "warning",
                    SignatureStatus::Ok => "note",
                };
                results.push(json!({
                        "ruleId": "signature-broken",
                        "level": level,
                        "message": {
                            "text": format!(
                                "İmza {} durumu: {} ({} eşleşme)",
                                check.signature.name,
                                check.status,
                                check.matches.len()
                            )
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": new_binary.path().to_string_lossy() },
                                "region": { "startColumn": 1, "startLine": 1 }
                            }
                        }],
                    "properties": {
                        "signature": check.signature.name,
                        "status": check.status.to_string(),
                        "matches": check.matches.len(),
                    }
                }));
            }
        }

        let sarif = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "patchlens",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/RivaExits0/patchlens",
                        "rules": [
                            { "id": "function-modified", "shortDescription": { "text": "Build'ler arasında değişen fonksiyon" } },
                            { "id": "function-removed", "shortDescription": { "text": "Yeni build'de kaldırılan fonksiyon" } },
                            { "id": "function-added", "shortDescription": { "text": "Yeni build'de eklenen fonksiyon" } },
                            { "id": "signature-broken", "shortDescription": { "text": "Artık eşleşmeyen imza" } },
                        ]
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": true,
                    "startTimeUtc": Utc::now().to_rfc3339(),
                }]
            }]
        });

        Ok(serde_json::to_string_pretty(&sarif)?)
    }

    /// C header üretir.
    pub fn generate_c_header(
        diff: &DiffResult,
        old_binary: &Binary,
        new_binary: &Binary,
    ) -> String {
        let mut out = String::new();
        out.push_str("// Patchlens offset export\n");
        out.push_str(&format!("// Generated: {}\n", Utc::now().to_rfc3339()));
        out.push_str(&format!("// Old: {}\n", old_binary.path().display()));
        out.push_str(&format!("// New: {}\n\n", new_binary.path().display()));
        out.push_str("#ifndef PATCHLENS_OFFSETS_H\n");
        out.push_str("#define PATCHLENS_OFFSETS_H\n\n");

        for m in &diff.modified {
            let Some(new_f) = &m.new else { continue };
            out.push_str(&format!(
                "#define {} 0x{:X} // eski: 0x{:X}, benzerlik: {:.1}%\n",
                sanitize_macro(&display_name(new_f)),
                new_f.address,
                m.old.as_ref().map(|o| o.address).unwrap_or(0),
                m.score * 100.0
            ));
        }

        for m in &diff.added {
            let Some(new_f) = &m.new else { continue };
            out.push_str(&format!(
                "#define {} 0x{:X} // eklendi\n",
                sanitize_macro(&display_name(new_f)),
                new_f.address
            ));
        }

        out.push_str("\n#endif // PATCHLENS_OFFSETS_H\n");
        out
    }

    /// Cheat Engine tablosu üretir.
    pub fn generate_cheat_engine(
        diff: &DiffResult,
        _old_binary: &Binary,
        _new_binary: &Binary,
    ) -> String {
        let mut entries = Vec::new();

        for m in &diff.modified {
            let Some(new_f) = &m.new else { continue };
            entries.push(format!(
                "<CheatEntry>\n  <Description>{}</Description>\n  <VariableType>8 Bytes</VariableType>\n  <Address>0x{:X}</Address>\n  <Comment>0x{:X} adresinden değişti (benzerlik: {:.1}%)</Comment>\n</CheatEntry>",
                display_name(new_f),
                new_f.address,
                m.old.as_ref().map(|o| o.address).unwrap_or(0),
                m.score * 100.0
            ));
        }

        for m in &diff.added {
            let Some(new_f) = &m.new else { continue };
            entries.push(format!(
                "<CheatEntry>\n  <Description>{}</Description>\n  <VariableType>8 Bytes</VariableType>\n  <Address>0x{:X}</Address>\n  <Comment>Yeni build'de eklendi</Comment>\n</CheatEntry>",
                display_name(new_f),
                new_f.address
            ));
        }

        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<CheatTable>\n  <CheatEntries>\n{}\n  </CheatEntries>\n</CheatTable>\n",
            entries.join("\n")
        )
    }
}

/// Offset'leri verilen formatta dışa aktarır.
pub fn export_offsets(
    old_binary: &Binary,
    new_binary: &Binary,
    signatures: &SignatureSet,
    format: ExportFormat,
) -> Result<String> {
    let diff = diff_binaries(old_binary, new_binary, DiffConfig::default());
    CiReport::generate(&diff, old_binary, new_binary, Some(signatures), format)
}

/// Tek bir fonksiyondaki değişimi açıklar.
pub fn explain_change(
    old_binary: &Binary,
    new_binary: &Binary,
    function_addr: u64,
    limit: usize,
    offset: usize,
) -> Result<ChangeExplanation> {
    let old_func = old_binary.function_by_va(function_addr);
    let new_func = resolve_new_function(old_binary, new_binary, function_addr);

    let mut explanation = ChangeExplanation {
        function_address: function_addr,
        old_function: old_func.cloned(),
        new_function: new_func.cloned(),
        disassembly_diff: Vec::new(),
        basic_block_changes: Vec::new(),
        instruction_changes: Vec::new(),
    };

    match (old_func, new_func) {
        (Some(old_f), Some(new_f)) => {
            explanation.disassembly_diff = diff_disassembly(old_f, new_f, limit, offset);
            explanation.basic_block_changes = diff_basic_blocks(old_f, new_f);
            explanation.instruction_changes = diff_instructions(old_f, new_f, limit, offset);
        }
        (Some(old_f), None) => {
            explanation.disassembly_diff.push(DisassemblyLine {
                address: old_f.address,
                old_bytes: Some(hex::encode(&old_f.bytes)),
                new_bytes: None,
                old_mnemonic: None,
                new_mnemonic: None,
                change_type: ChangeType::Removed,
            });
        }
        (None, Some(new_f)) => {
            explanation.disassembly_diff.push(DisassemblyLine {
                address: new_f.address,
                old_bytes: None,
                new_bytes: Some(hex::encode(&new_f.bytes)),
                old_mnemonic: None,
                new_mnemonic: None,
                change_type: ChangeType::Added,
            });
        }
        (None, None) => {}
    }

    Ok(explanation)
}

/// Eski adresi yeni build'deki karşılığına çevirir.
fn resolve_new_function<'a>(
    old_binary: &Binary,
    new_binary: &'a Binary,
    function_addr: u64,
) -> Option<&'a FunctionInfo> {
    if let Some(func) = new_binary.function_by_va(function_addr) {
        return Some(func);
    }
    let diff = diff_binaries(old_binary, new_binary, DiffConfig::default());
    for m in diff.unchanged.iter().chain(diff.modified.iter()) {
        if let (Some(old_f), Some(new_f)) = (&m.old, &m.new) {
            if old_f.address == function_addr {
                return new_binary.function_by_va(new_f.address);
            }
        }
    }
    None
}

/// Disassembly fark satırı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyLine {
    /// Adres.
    pub address: u64,
    /// Eski byte'lar (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_bytes: Option<String>,
    /// Yeni byte'lar (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_bytes: Option<String>,
    /// Eski mnemonic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_mnemonic: Option<String>,
    /// Yeni mnemonic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_mnemonic: Option<String>,
    /// Değişiklik türü.
    pub change_type: ChangeType,
}

/// Değişiklik türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    /// Değişmedi.
    Unchanged,
    /// Değişti.
    Modified,
    /// Eklendi.
    Added,
    /// Kaldırıldı.
    Removed,
}

/// Bir fonksiyondaki değişimin tam açıklaması.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeExplanation {
    /// Sorgulanan eski fonksiyon adresi.
    pub function_address: u64,
    /// Eski fonksiyon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_function: Option<FunctionInfo>,
    /// Yeni fonksiyon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_function: Option<FunctionInfo>,
    /// Disassembly farkı.
    pub disassembly_diff: Vec<DisassemblyLine>,
    /// Basic block değişiklikleri.
    pub basic_block_changes: Vec<BasicBlockChange>,
    /// Talimat değişiklikleri.
    pub instruction_changes: Vec<InstructionChange>,
}

/// Basic block değişikliği.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlockChange {
    /// Eski block başlangıcı.
    pub old_start: u64,
    /// Yeni block başlangıcı.
    pub new_start: u64,
    /// Değişiklik türü.
    pub change_type: ChangeType,
    /// Boyut farkı.
    pub size_delta: isize,
}

/// Talimat değişikliği.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionChange {
    /// Adres.
    pub address: u64,
    /// Eski byte'lar (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_bytes: Option<String>,
    /// Yeni byte'lar (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_bytes: Option<String>,
    /// Eski mnemonic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_mnemonic: Option<String>,
    /// Yeni mnemonic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_mnemonic: Option<String>,
    /// Değişiklik türü.
    pub change_type: ChangeType,
}

/// İki fonksiyonun disassembly'sini karşılaştırır.
fn diff_disassembly(
    old: &FunctionInfo,
    new: &FunctionInfo,
    limit: usize,
    offset: usize,
) -> Vec<DisassemblyLine> {
    let fingerprinter = FunctionFingerprinter::new();
    let old_insns = fingerprinter
        .disassemble(&old.bytes, old.address)
        .unwrap_or_default();
    let new_insns = fingerprinter
        .disassemble(&new.bytes, new.address)
        .unwrap_or_default();

    let mut lines = Vec::new();
    let mut old_idx = 0usize;
    let mut new_idx = 0usize;

    while old_idx < old_insns.len() || new_idx < new_insns.len() {
        match (old_insns.get(old_idx), new_insns.get(new_idx)) {
            (Some(o), Some(n)) if o.address == n.address && o.bytes == n.bytes => {
                lines.push(DisassemblyLine {
                    address: o.address,
                    old_bytes: Some(hex::encode(&o.bytes)),
                    new_bytes: Some(hex::encode(&n.bytes)),
                    old_mnemonic: Some(o.mnemonic.clone()),
                    new_mnemonic: Some(n.mnemonic.clone()),
                    change_type: ChangeType::Unchanged,
                });
                old_idx += 1;
                new_idx += 1;
            }
            (Some(o), Some(n)) if o.address <= n.address => {
                lines.push(DisassemblyLine {
                    address: o.address,
                    old_bytes: Some(hex::encode(&o.bytes)),
                    new_bytes: None,
                    old_mnemonic: Some(o.mnemonic.clone()),
                    new_mnemonic: None,
                    change_type: ChangeType::Removed,
                });
                old_idx += 1;
            }
            (Some(o), None) => {
                lines.push(DisassemblyLine {
                    address: o.address,
                    old_bytes: Some(hex::encode(&o.bytes)),
                    new_bytes: None,
                    old_mnemonic: Some(o.mnemonic.clone()),
                    new_mnemonic: None,
                    change_type: ChangeType::Removed,
                });
                old_idx += 1;
            }
            (_, Some(n)) => {
                lines.push(DisassemblyLine {
                    address: n.address,
                    old_bytes: None,
                    new_bytes: Some(hex::encode(&n.bytes)),
                    old_mnemonic: None,
                    new_mnemonic: Some(n.mnemonic.clone()),
                    change_type: ChangeType::Added,
                });
                new_idx += 1;
            }
            (None, None) => break,
        }
    }

    lines.into_iter().skip(offset).take(limit).collect()
}

/// Basic block değişikliklerini üretir.
fn diff_basic_blocks(old: &FunctionInfo, new: &FunctionInfo) -> Vec<BasicBlockChange> {
    let mut changes = Vec::new();
    let max = old.block_count.max(new.block_count);
    for index in 0..max {
        let old_start = old.address + index as u64 * 16;
        let new_start = new.address + index as u64 * 16;
        let change_type = if index < old.block_count.min(new.block_count) {
            ChangeType::Modified
        } else if index < old.block_count {
            ChangeType::Removed
        } else {
            ChangeType::Added
        };
        changes.push(BasicBlockChange {
            old_start,
            new_start,
            change_type,
            size_delta: new.size as isize - old.size as isize,
        });
    }
    changes
}

/// Talimat değişikliklerini üretir.
fn diff_instructions(
    old: &FunctionInfo,
    new: &FunctionInfo,
    limit: usize,
    offset: usize,
) -> Vec<InstructionChange> {
    let fingerprinter = FunctionFingerprinter::new();
    let old_insns = fingerprinter
        .disassemble(&old.bytes, old.address)
        .unwrap_or_default();
    let new_insns = fingerprinter
        .disassemble(&new.bytes, new.address)
        .unwrap_or_default();

    let mut changes = Vec::new();
    let mut old_idx = 0usize;
    let mut new_idx = 0usize;

    while old_idx < old_insns.len() || new_idx < new_insns.len() {
        match (old_insns.get(old_idx), new_insns.get(new_idx)) {
            (Some(o), Some(n)) if o.address == n.address && o.bytes == n.bytes => {
                old_idx += 1;
                new_idx += 1;
            }
            (Some(o), Some(n)) if o.address <= n.address => {
                changes.push(InstructionChange {
                    address: o.address,
                    old_bytes: Some(hex::encode(&o.bytes)),
                    new_bytes: None,
                    old_mnemonic: Some(o.mnemonic.clone()),
                    new_mnemonic: None,
                    change_type: ChangeType::Removed,
                });
                old_idx += 1;
            }
            (Some(o), None) => {
                changes.push(InstructionChange {
                    address: o.address,
                    old_bytes: Some(hex::encode(&o.bytes)),
                    new_bytes: None,
                    old_mnemonic: Some(o.mnemonic.clone()),
                    new_mnemonic: None,
                    change_type: ChangeType::Removed,
                });
                old_idx += 1;
            }
            (_, Some(n)) => {
                changes.push(InstructionChange {
                    address: n.address,
                    old_bytes: None,
                    new_bytes: Some(hex::encode(&n.bytes)),
                    old_mnemonic: None,
                    new_mnemonic: Some(n.mnemonic.clone()),
                    change_type: ChangeType::Added,
                });
                new_idx += 1;
            }
            (None, None) => break,
        }
    }

    changes.into_iter().skip(offset).take(limit).collect()
}

/// Fonksiyon adını okunabilir biçimde döndürür.
fn display_name(func: &FunctionInfo) -> String {
    func.name
        .clone()
        .unwrap_or_else(|| format!("sub_{:X}", func.address))
}

/// C makro adı için sanitize eder.
fn sanitize_macro(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let cleaned = cleaned.trim_matches('_').to_uppercase();
    if cleaned.is_empty() {
        "FUNC_UNKNOWN".to_string()
    } else {
        cleaned
    }
}

/// İmza kontrol sonuçlarını özetler (CI için).
pub fn summarize_signature_checks(checks: &[SignatureCheckResult]) -> serde_json::Value {
    let broken = checks
        .iter()
        .filter(|c| c.status == SignatureStatus::Broken)
        .count();
    let ambiguous = checks
        .iter()
        .filter(|c| c.status == SignatureStatus::Ambiguous)
        .count();
    let moved = checks
        .iter()
        .filter(|c| c.status == SignatureStatus::Moved)
        .count();
    let ok = checks
        .iter()
        .filter(|c| c.status == SignatureStatus::Ok)
        .count();

    json!({
        "total": checks.len(),
        "ok": ok,
        "moved": moved,
        "broken": broken,
        "ambiguous": ambiguous,
    })
}

/// Diff özetini üretir (sayfalama öncesi toplamlar kullanılır).
pub fn summarize_diff(diff: &DiffResult) -> serde_json::Value {
    json!({
        "old_total": diff.old_total,
        "new_total": diff.new_total,
        "unchanged": diff.totals.unchanged,
        "modified": diff.totals.modified,
        "added": diff.totals.added,
        "removed": diff.totals.removed,
    })
}

/// Eşleşmeleri özet listeye çevirir.
pub fn summarize_matches(matches: &[FunctionMatch]) -> Vec<serde_json::Value> {
    matches
        .iter()
        .map(|m| {
            json!({
                "old_address": m.old.as_ref().map(|f| format!("0x{:X}", f.address)),
                "new_address": m.new.as_ref().map(|f| format!("0x{:X}", f.address)),
                "name": m.new.as_ref().or(m.old.as_ref()).and_then(|f| f.name.clone()),
                "kind": format!("{:?}", m.kind),
                "score": m.score,
                "changed_blocks": m.changed_blocks,
            })
        })
        .collect()
}
