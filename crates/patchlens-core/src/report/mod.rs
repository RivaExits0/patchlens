//! Rapor üretimi: SARIF, JSON, C header ve Cheat Engine `.CT`.

use std::collections::BTreeSet;

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
                        "artifactLocation": { "uri": artifact_uri(new_binary) },
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
                        "artifactLocation": { "uri": artifact_uri(old_binary) },
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
                        "artifactLocation": { "uri": artifact_uri(new_binary) },
                        "region": { "startColumn": 1, "startLine": 1 }
                    }
                }],
                "properties": { "new_address": format!("0x{:X}", new_f.address) }
            }));
        }

        if let Some(set) = signatures {
            let checks = SignatureEngine::new().check(new_binary, set);
            for check in &checks {
                let (rule_id, level) = match check.status {
                    SignatureStatus::Broken => ("signature-broken", "error"),
                    SignatureStatus::Ambiguous => ("signature-ambiguous", "error"),
                    SignatureStatus::Moved => ("signature-moved", "warning"),
                    // Sağlıklı imzalar SARIF sonucu üretmez; CI gürültüsü olmaz.
                    SignatureStatus::Ok => continue,
                };
                results.push(json!({
                        "ruleId": rule_id,
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
                                "artifactLocation": { "uri": artifact_uri(new_binary) },
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
                            { "id": "signature-moved", "shortDescription": { "text": "Yeni konumda bulunan imza" } },
                            { "id": "signature-ambiguous", "shortDescription": { "text": "Birden fazla eşleşen imza" } },
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
                xml_escape(&display_name(new_f)),
                new_f.address,
                m.old.as_ref().map(|o| o.address).unwrap_or(0),
                m.score * 100.0
            ));
        }

        for m in &diff.added {
            let Some(new_f) = &m.new else { continue };
            entries.push(format!(
                "<CheatEntry>\n  <Description>{}</Description>\n  <VariableType>8 Bytes</VariableType>\n  <Address>0x{:X}</Address>\n  <Comment>Yeni build'de eklendi</Comment>\n</CheatEntry>",
                xml_escape(&display_name(new_f)),
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
    // Raporlar tam listeyi içermeli; varsayılan sayfalama (100) veri kaybettirir.
    let diff = diff_binaries(old_binary, new_binary, DiffConfig::unpaginated());
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
    let (old_func, new_func) = resolve_function_pair(old_binary, new_binary, function_addr);

    if old_func.is_none() && new_func.is_none() {
        return Err(anyhow::anyhow!(
            crate::error::PatchlensError::FunctionNotFound(format!("0x{function_addr:X}"))
        ));
    }

    let mut explanation = ChangeExplanation {
        function_address: function_addr,
        old_function: old_func.clone(),
        new_function: new_func.clone(),
        disassembly_diff: Vec::new(),
        basic_block_changes: Vec::new(),
        instruction_changes: Vec::new(),
    };

    match (&old_func, &new_func) {
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

/// Verilen adresi her iki build'de de karşılık gelen fonksiyon çiftine çözer.
///
/// Adres eski build'de varsa yeni karşılığı, yoksa yeni build'deki karşılığı
/// üzerinden eşleştirme yapılır. Eşleştirme sayfalamasız çalışır; aksi halde
/// 100'den fazla fonksiyon içeren build'lerde yanlış sonuç döner.
fn resolve_function_pair(
    old_binary: &Binary,
    new_binary: &Binary,
    address: u64,
) -> (Option<FunctionInfo>, Option<FunctionInfo>) {
    let old_at_address = old_binary.function_by_va(address).cloned();
    let new_at_address = new_binary.function_by_va(address).cloned();

    if old_at_address.is_some() && new_at_address.is_some() {
        // Aynı VA iki build'de farklı fonksiyonlara denk gelebilir; byte'lar
        // eşleşmiyorsa gerçek eşleşmeyi diff üzerinden bul.
        let (Some(old_func), Some(new_func)) = (&old_at_address, &new_at_address) else {
            unreachable!("her iki değer de Some");
        };
        if old_func.opcode_hash == new_func.opcode_hash && old_func.size == new_func.size {
            return (old_at_address, new_at_address);
        }
    }

    let diff = diff_binaries(old_binary, new_binary, DiffConfig::unpaginated());
    let mut old_func = old_at_address.clone();
    let mut new_func = new_at_address.clone();

    if old_at_address.is_some() {
        // Eski adres sorgusu: yeni karşılığı diff'ten al.
        new_func = None;
        for matched in diff.unchanged.iter().chain(diff.modified.iter()) {
            if let (Some(old_f), Some(new_f)) = (&matched.old, &matched.new) {
                if old_f.address == address {
                    new_func = Some(new_f.clone());
                    break;
                }
            }
        }
    } else if new_at_address.is_some() {
        // Yeni adres sorgusu: eski karşılığı diff'ten al.
        old_func = None;
        for matched in diff.unchanged.iter().chain(diff.modified.iter()) {
            if let (Some(old_f), Some(new_f)) = (&matched.old, &matched.new) {
                if new_f.address == address {
                    old_func = Some(old_f.clone());
                    break;
                }
            }
        }
    }

    (old_func, new_func)
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
///
/// Talimatlar mutlak adresle değil, sıra (index) ile hizalanır. Fonksiyon
/// build'ler arasında taşındığında adresler farklı olacağı için adres
/// karşılaştırması yanlışlıkla tüm satırları "silindi/eklendi" gösterirdi.
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
    for index in 0..old_insns.len().max(new_insns.len()) {
        match (old_insns.get(index), new_insns.get(index)) {
            (Some(o), Some(n)) => {
                let change_type = if o.bytes == n.bytes {
                    ChangeType::Unchanged
                } else {
                    ChangeType::Modified
                };
                lines.push(DisassemblyLine {
                    address: o.address,
                    old_bytes: Some(hex::encode(&o.bytes)),
                    new_bytes: Some(hex::encode(&n.bytes)),
                    old_mnemonic: Some(o.mnemonic.clone()),
                    new_mnemonic: Some(n.mnemonic.clone()),
                    change_type,
                });
            }
            (Some(o), None) => lines.push(DisassemblyLine {
                address: o.address,
                old_bytes: Some(hex::encode(&o.bytes)),
                new_bytes: None,
                old_mnemonic: Some(o.mnemonic.clone()),
                new_mnemonic: None,
                change_type: ChangeType::Removed,
            }),
            (None, Some(n)) => lines.push(DisassemblyLine {
                address: n.address,
                old_bytes: None,
                new_bytes: Some(hex::encode(&n.bytes)),
                old_mnemonic: None,
                new_mnemonic: Some(n.mnemonic.clone()),
                change_type: ChangeType::Added,
            }),
            (None, None) => break,
        }
    }

    lines.into_iter().skip(offset).take(limit).collect()
}

/// Fonksiyonun gerçek basic block aralıklarını (başlangıç, bitiş) çıkarır.
fn basic_block_ranges(func: &FunctionInfo) -> Vec<(u64, u64)> {
    let end = func.address.saturating_add(func.size as u64);
    let mut starts = BTreeSet::new();
    starts.insert(func.address);

    if let Ok(instructions) = FunctionFingerprinter::new().disassemble(&func.bytes, func.address) {
        for insn in &instructions {
            let next = insn.end_address();
            let is_terminator = insn.mnemonic == "ret" || insn.mnemonic.starts_with('j');
            if is_terminator && next < end {
                starts.insert(next);
            }
            if insn.mnemonic.starts_with('j') {
                if let Some(target) = insn.target {
                    if target >= func.address && target < end {
                        starts.insert(target);
                    }
                }
            }
        }
    }

    let starts: Vec<u64> = starts.into_iter().filter(|&start| start < end).collect();
    if starts.is_empty() {
        return vec![(func.address, end)];
    }
    starts
        .iter()
        .enumerate()
        .map(|(index, &start)| (start, starts.get(index + 1).copied().unwrap_or(end)))
        .collect()
}

/// Fonksiyon byte'larından verilen aralığı dilimler.
fn block_bytes(func: &FunctionInfo, start: u64, end: u64) -> &[u8] {
    let from = start.saturating_sub(func.address) as usize;
    let to = end.saturating_sub(func.address) as usize;
    func.bytes.get(from..to).unwrap_or_default()
}

/// Basic block değişikliklerini üretir.
fn diff_basic_blocks(old: &FunctionInfo, new: &FunctionInfo) -> Vec<BasicBlockChange> {
    let old_blocks = basic_block_ranges(old);
    let new_blocks = basic_block_ranges(new);
    let mut changes = Vec::new();

    for index in 0..old_blocks.len().max(new_blocks.len()) {
        match (old_blocks.get(index), new_blocks.get(index)) {
            (Some(&(old_start, old_end)), Some(&(new_start, new_end))) => {
                let change_type = if block_bytes(old, old_start, old_end)
                    == block_bytes(new, new_start, new_end)
                {
                    ChangeType::Unchanged
                } else {
                    ChangeType::Modified
                };
                changes.push(BasicBlockChange {
                    old_start,
                    new_start,
                    change_type,
                    size_delta: (new_end - new_start) as isize - (old_end - old_start) as isize,
                });
            }
            (Some(&(old_start, old_end)), None) => changes.push(BasicBlockChange {
                old_start,
                new_start: 0,
                change_type: ChangeType::Removed,
                size_delta: -((old_end - old_start) as isize),
            }),
            (None, Some(&(new_start, new_end))) => changes.push(BasicBlockChange {
                old_start: 0,
                new_start,
                change_type: ChangeType::Added,
                size_delta: (new_end - new_start) as isize,
            }),
            (None, None) => break,
        }
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
    for index in 0..old_insns.len().max(new_insns.len()) {
        match (old_insns.get(index), new_insns.get(index)) {
            (Some(o), Some(n)) if o.bytes == n.bytes => continue,
            (Some(o), Some(n)) => changes.push(InstructionChange {
                address: o.address,
                old_bytes: Some(hex::encode(&o.bytes)),
                new_bytes: Some(hex::encode(&n.bytes)),
                old_mnemonic: Some(o.mnemonic.clone()),
                new_mnemonic: Some(n.mnemonic.clone()),
                change_type: ChangeType::Modified,
            }),
            (Some(o), None) => changes.push(InstructionChange {
                address: o.address,
                old_bytes: Some(hex::encode(&o.bytes)),
                new_bytes: None,
                old_mnemonic: Some(o.mnemonic.clone()),
                new_mnemonic: None,
                change_type: ChangeType::Removed,
            }),
            (None, Some(n)) => changes.push(InstructionChange {
                address: n.address,
                old_bytes: None,
                new_bytes: Some(hex::encode(&n.bytes)),
                old_mnemonic: None,
                new_mnemonic: Some(n.mnemonic.clone()),
                change_type: ChangeType::Added,
            }),
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

/// SARIF için platformdan bağımsız (ileri eğik çizgili) artifact URI'si üretir.
fn artifact_uri(binary: &Binary) -> String {
    binary.path().to_string_lossy().replace('\\', "/")
}

/// XML metin/attribute değerlerini kaçışlar.
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
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
    } else if cleaned
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
    {
        // C makro adı rakamla başlayamaz.
        format!("FUNC_{cleaned}")
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
