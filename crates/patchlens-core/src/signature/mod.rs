//! AOB (byte pattern) ve export ismi tabanlı imza motoru.

use std::collections::HashMap;

use memchr::memchr;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::binary::Binary;
use crate::common::FunctionInfo;
use crate::diff::{diff_binaries, DiffConfig};
use crate::function::FunctionFingerprinter;

/// İmza türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SignatureKind {
    /// Joker desteği olan byte pattern (AOB).
    #[default]
    Aob,
    /// Dışa aktarım tablosundaki isim.
    ExportName,
}

/// Aranacak imza.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// İmzanın benzersiz adı.
    pub name: String,
    /// İmza türü.
    pub kind: SignatureKind,
    /// AOB pattern (ör. `48 8B 05 ?? ?? ?? ?? 90`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Export ismi (`ExportName` türü için).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Eski binary'de beklenen RVA (opsiyonel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_offset: Option<u64>,
    /// Açıklama.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: SignatureKind::Aob,
            pattern: None,
            function_name: None,
            expected_offset: None,
            description: None,
        }
    }
}

/// İmza listesi.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureSet {
    /// İmzalar.
    pub signatures: Vec<Signature>,
}

/// İmza kontrol sonucu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCheckResult {
    /// Kontrol edilen imza.
    pub signature: Signature,
    /// Kontrol durumu.
    pub status: SignatureStatus,
    /// Bulunan eşleşmeler.
    pub matches: Vec<SignatureMatch>,
    /// Kırık imza için önerilen yeni imza.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_signature: Option<Signature>,
}

/// İmza kontrol durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureStatus {
    /// Beklenen konumda tam olarak bir eşleşme.
    Ok,
    /// Tek eşleşme var ama beklenen konumdan farklı.
    Moved,
    /// Hiç eşleşme bulunamadı.
    Broken,
    /// Birden fazla eşleşme bulundu.
    Ambiguous,
}

impl std::fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            SignatureStatus::Ok => "ok",
            SignatureStatus::Moved => "moved",
            SignatureStatus::Broken => "broken",
            SignatureStatus::Ambiguous => "ambiguous",
        };
        f.write_str(text)
    }
}

/// Binary içinde bulunan imza eşleşmesi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    /// Eşleşmenin RVA'sı.
    pub offset: u64,
    /// Eşleşmenin dosya offseti.
    pub file_offset: u64,
    /// Eşleşmeyi içeren fonksiyonun VA'sı.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_address: Option<u64>,
    /// Eşleşmeyi içeren fonksiyonun ismi.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// Çevreleyen byte'lar (hex).
    pub context: String,
}

/// İmza motoru.
pub struct SignatureEngine {
    fingerprinter: FunctionFingerprinter,
}

impl SignatureEngine {
    /// Yeni motor oluşturur.
    pub fn new() -> Self {
        Self {
            fingerprinter: FunctionFingerprinter::new(),
        }
    }

    /// Tüm imzaları binary'ye karşı kontrol eder.
    pub fn check(&self, binary: &Binary, signatures: &SignatureSet) -> Vec<SignatureCheckResult> {
        signatures
            .signatures
            .par_iter()
            .map(|sig| self.check_one(binary, sig))
            .collect()
    }

    /// İmzaları kontrol eder ve kırık olanlar için öneri üretir.
    pub fn check_with_suggestions(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        signatures: &SignatureSet,
    ) -> Vec<SignatureCheckResult> {
        let mut results = self.check(new_binary, signatures);

        let broken: Vec<Signature> = results
            .iter()
            .filter(|r| r.status == SignatureStatus::Broken)
            .map(|r| r.signature.clone())
            .collect();

        if broken.is_empty() {
            return results;
        }

        // Öneriler kırık imza listesiyle birebir hizalıdır; üretilemeyen
        // imzalar `None` olur. Böylece bir sonraki imzanın önerisi yanlış
        // sonuca atanmaz.
        let suggestions = self.suggest_aligned(old_binary, new_binary, &broken);
        let mut iter = suggestions.into_iter();
        for result in results.iter_mut() {
            if result.status == SignatureStatus::Broken {
                result.suggested_signature = iter.next().flatten();
            }
        }
        results
    }

    /// Tek bir imzayı kontrol eder.
    pub fn check_one(&self, binary: &Binary, sig: &Signature) -> SignatureCheckResult {
        let matches = match sig.kind {
            SignatureKind::Aob => self.find_aob_matches(binary, sig),
            SignatureKind::ExportName => self.find_export_matches(binary, sig),
        };

        let status = match matches.len() {
            0 => SignatureStatus::Broken,
            1 => {
                let m = &matches[0];
                match sig.expected_offset {
                    Some(expected) if m.offset != expected => SignatureStatus::Moved,
                    _ => SignatureStatus::Ok,
                }
            }
            _ => SignatureStatus::Ambiguous,
        };

        SignatureCheckResult {
            signature: sig.clone(),
            status,
            matches,
            suggested_signature: None,
        }
    }

    /// AOB pattern eşleşmelerini bulur.
    pub fn find_aob_matches(&self, binary: &Binary, sig: &Signature) -> Vec<SignatureMatch> {
        let pattern = sig.pattern.as_deref().unwrap_or("");
        let Some(needle) = AobPattern::parse(pattern) else {
            return Vec::new();
        };

        let data = binary.data();
        let mut matches = Vec::new();

        let Some(first) = needle.first_fixed_byte() else {
            return matches;
        };

        let mut search_start = 0usize;
        while search_start < data.len() {
            let Some(found) = memchr(first, &data[search_start..]) else {
                break;
            };
            let offset = search_start + found;
            if needle.matches_at(data, offset) {
                let va = binary.va_from_offset(offset);
                let function = va.and_then(|va| {
                    binary
                        .function_by_va(va)
                        .or_else(|| containing_function(binary, va))
                });
                let rva = va
                    .map(|va| va.saturating_sub(binary.info().image_base))
                    .unwrap_or(offset as u64);
                matches.push(SignatureMatch {
                    offset: rva,
                    file_offset: offset as u64,
                    function_address: function.map(|f| f.address),
                    function_name: function.and_then(|f| f.name.clone()),
                    context: context_bytes(data, offset),
                });
            }
            search_start = offset + 1;
        }
        matches
    }

    /// Export ismi eşleşmelerini bulur.
    fn find_export_matches(&self, binary: &Binary, sig: &Signature) -> Vec<SignatureMatch> {
        let Some(name) = sig.function_name.as_deref() else {
            return Vec::new();
        };
        let Some(va) = binary.export_by_name(name) else {
            return Vec::new();
        };

        let function = binary.function_by_va(va);
        vec![SignatureMatch {
            offset: va.saturating_sub(binary.info().image_base),
            file_offset: binary.va_to_file_offset(va).unwrap_or(0) as u64,
            function_address: function.map(|f| f.address),
            function_name: Some(name.to_string()),
            context: function
                .map(|f| hex::encode(&f.bytes[..f.bytes.len().min(32)]))
                .unwrap_or_default(),
        }]
    }

    /// Kırık imzalar için yeni, doğrulanmış imzalar önerir.
    pub fn suggest(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        broken_signatures: &[Signature],
    ) -> Vec<Signature> {
        self.suggest_aligned(old_binary, new_binary, broken_signatures)
            .into_iter()
            .flatten()
            .collect()
    }

    /// Kırık imza listesiyle birebir hizalı öneriler üretir.
    fn suggest_aligned(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        broken_signatures: &[Signature],
    ) -> Vec<Option<Signature>> {
        // Sayfalama, eşleştirme haritasını 100 fonksiyonda kesmemeli;
        // büyük binary'lerde kırık imza önerisi aksi halde kaybolur.
        let diff = diff_binaries(old_binary, new_binary, DiffConfig::unpaginated());

        let mut old_to_new: HashMap<u64, u64> = HashMap::new();
        for m in diff.unchanged.iter().chain(diff.modified.iter()) {
            if let (Some(old_f), Some(new_f)) = (&m.old, &m.new) {
                old_to_new.insert(old_f.address, new_f.address);
            }
        }

        broken_signatures
            .iter()
            .map(|sig| self.suggest_one(old_binary, new_binary, sig, &old_to_new))
            .collect()
    }

    /// Tek bir kırık imza için öneri üretir.
    fn suggest_one(
        &self,
        old_binary: &Binary,
        new_binary: &Binary,
        sig: &Signature,
        old_to_new: &HashMap<u64, u64>,
    ) -> Option<Signature> {
        let old_func = self.find_function_for_signature(old_binary, sig)?;
        let new_addr = old_to_new.get(&old_func.address).copied()?;
        let new_func = new_binary.function_by_va(new_addr)?;

        let candidates = self.candidate_patterns(old_func, new_func);
        for pattern in candidates {
            let probe = Signature {
                name: sig.name.clone(),
                kind: SignatureKind::Aob,
                pattern: Some(pattern.clone()),
                function_name: None,
                expected_offset: None,
                description: None,
            };
            let matches = self.find_aob_matches(new_binary, &probe);
            if matches.len() == 1 {
                return Some(Signature {
                    name: format!("{}_v2", sig.name),
                    kind: SignatureKind::Aob,
                    pattern: Some(pattern),
                    function_name: None,
                    expected_offset: Some(
                        new_func
                            .address
                            .saturating_sub(new_binary.info().image_base),
                    ),
                    description: Some(format!(
                        "Otomatik üretilen değişim: {} (eski adres 0x{:X})",
                        sig.name, old_func.address
                    )),
                });
            }
        }
        None
    }

    /// Yeni fonksiyon için aday AOB pattern'leri üretir.
    fn candidate_patterns(&self, old_func: &FunctionInfo, new_func: &FunctionInfo) -> Vec<String> {
        let mut candidates = Vec::new();

        // 1) Eski/yeni fonksiyon arasında değişen byte'ları jokerleştir.
        if let Some(pattern) = diff_based_pattern(old_func, new_func) {
            candidates.push(pattern);
        }

        // 2) Immediate ve displacement byte'larını jokerleştir.
        if let Some(pattern) = self.volatile_pattern(new_func) {
            if !candidates.contains(&pattern) {
                candidates.push(pattern);
            }
        }

        // 3) Fonksiyonun tamamını (daha uzun, daha ayırt edici) kullan.
        if let Some(pattern) = exact_pattern(&new_func.bytes) {
            if !candidates.contains(&pattern) {
                candidates.push(pattern);
            }
        }

        candidates
    }

    /// Immediate/displacement jokerleştirilmiş pattern üretir.
    fn volatile_pattern(&self, func: &FunctionInfo) -> Option<String> {
        let instructions = self
            .fingerprinter
            .disassemble(&func.bytes, func.address)
            .ok()?;
        if instructions.is_empty() {
            return None;
        }

        let mut wildcard = vec![false; func.bytes.len()];
        for insn in &instructions {
            let start = (insn.address - func.address) as usize;
            let end = start + insn.size;
            if end > func.bytes.len() {
                continue;
            }

            if insn.op_str.contains("rip") {
                let from = end.saturating_sub(4);
                for slot in wildcard.iter_mut().take(end).skip(from) {
                    *slot = true;
                }
            }

            if let Some(value) = immediate_value(&insn.op_str) {
                let encoded = value.to_le_bytes();
                let slice = &func.bytes[start..end];
                if let Some(pos) = find_subslice(slice, &encoded[..4.min(slice.len())]) {
                    let significant = significant_bytes(value);
                    for offset in 0..significant {
                        if pos + offset < wildcard.len() {
                            wildcard[pos + offset] = true;
                        }
                    }
                }
            }
        }

        let tokens: Vec<String> = func
            .bytes
            .iter()
            .enumerate()
            .map(|(idx, byte)| {
                if wildcard[idx] {
                    "??".to_string()
                } else {
                    format!("{:02X}", byte)
                }
            })
            .collect();
        Some(tokens.join(" "))
    }

    /// İmzanın işaret ettiği fonksiyonu bulur.
    fn find_function_for_signature<'a>(
        &self,
        binary: &'a Binary,
        sig: &Signature,
    ) -> Option<&'a FunctionInfo> {
        match sig.kind {
            SignatureKind::Aob => {
                let matches = self.find_aob_matches(binary, sig);
                let m = matches.first()?;
                let va = binary
                    .va_from_offset(m.file_offset as usize)
                    .unwrap_or(binary.info().image_base + m.offset);
                binary
                    .function_by_va(va)
                    .or_else(|| containing_function(binary, va))
            }
            SignatureKind::ExportName => {
                let name = sig.function_name.as_deref()?;
                let va = binary.export_by_name(name)?;
                binary.function_by_va(va)
            }
        }
    }
}

impl Default for SignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// VA'yı içeren fonksiyonu bulur.
fn containing_function(binary: &Binary, va: u64) -> Option<&FunctionInfo> {
    binary
        .functions()
        .iter()
        .find(|f| va >= f.address && va < f.address + f.size as u64)
}

/// Parse edilmiş AOB pattern.
#[derive(Debug, Clone)]
pub struct AobPattern {
    /// Pattern byte'ları (jokerler 0).
    pub bytes: Vec<u8>,
    /// Her byte için joker maskesi (true = joker).
    pub mask: Vec<bool>,
}

impl AobPattern {
    /// Pattern metnini parse eder; geçersizse `None` döner.
    pub fn parse(pattern: &str) -> Option<Self> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for token in pattern.split_whitespace() {
            if token == "?" || token == "??" || token == "**" || token == "*" {
                bytes.push(0);
                mask.push(false);
                continue;
            }
            let hex = token.strip_prefix("0x").unwrap_or(token);
            if hex.len() != 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            let value = u8::from_str_radix(hex, 16).ok()?;
            bytes.push(value);
            mask.push(true);
        }

        if bytes.is_empty() {
            return None;
        }
        Some(Self { bytes, mask })
    }

    /// İlk sabit byte'ı döner (arama hızlandırma için).
    pub fn first_fixed_byte(&self) -> Option<u8> {
        self.bytes
            .iter()
            .zip(self.mask.iter())
            .find(|(_, &is_fixed)| is_fixed)
            .map(|(&byte, _)| byte)
    }

    /// Verilen offset'te pattern eşleşiyor mu?
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        let end = offset.saturating_add(self.bytes.len());
        if end > data.len() {
            return false;
        }
        let window = &data[offset..end];
        self.bytes
            .iter()
            .zip(self.mask.iter())
            .zip(window.iter())
            .all(|((&byte, &is_fixed), &actual)| !is_fixed || byte == actual)
    }
}

/// Eşleşmenin çevresindeki byte'ları hex olarak döndürür.
fn context_bytes(data: &[u8], offset: usize) -> String {
    let start = offset.saturating_sub(8);
    let end = offset.saturating_add(16).min(data.len());
    match data.get(start..end) {
        Some(slice) => hex::encode(slice),
        None => String::new(),
    }
}

/// Eski/yeni fonksiyon farklarından pattern üretir.
fn diff_based_pattern(old_func: &FunctionInfo, new_func: &FunctionInfo) -> Option<String> {
    let len = old_func.bytes.len().min(new_func.bytes.len());
    if len < 6 {
        return None;
    }
    let tokens: Vec<String> = (0..len)
        .map(|i| {
            if old_func.bytes[i] == new_func.bytes[i] {
                format!("{:02X}", new_func.bytes[i])
            } else {
                "??".to_string()
            }
        })
        .collect();
    Some(tokens.join(" "))
}

/// Fonksiyonun ham byte'larından tam pattern üretir.
fn exact_pattern(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 6 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Operand metnindeki ilk hexadecimal immediate değerini döndürür.
fn immediate_value(op_str: &str) -> Option<u64> {
    let idx = op_str.find("0x")?;
    let digits: String = op_str[idx + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(&digits, 16).ok()
}

/// Immediate değerini kodlayan anlamlı byte sayısı.
fn significant_bytes(value: u64) -> usize {
    match value {
        0 => 1,
        v if v <= 0xFF => 1,
        v if v <= 0xFFFF => 2,
        v if v <= 0xFF_FFFF => 3,
        _ => 4,
    }
}

/// Alt dizi arar.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
