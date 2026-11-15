//! Disassembly ve fonksiyon çıkarımı.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use capstone::arch::x86::ArchMode;
use capstone::prelude::*;
use xxhash_rust::xxh3::xxh3_64;

use crate::binary::SectionInfo;
use crate::common::{FunctionInfo, InstructionInfo};

/// Tek bir fonksiyonun başlangıç bilgisi.
#[derive(Debug, Clone)]
struct FunctionStart {
    /// Başlangıç RVA'sı.
    rva: u32,
    /// Varsa bilinen bitiş RVA'sı (.pdata / export boyutundan).
    end_rva: Option<u32>,
    /// Tespit güvenilirliği (0.0 - 1.0).
    confidence: f32,
    /// Tespit kaynağı.
    source: StartSource,
}

/// Fonksiyon başlangıcının bulunduğu kaynak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartSource {
    /// Dışa aktarım tablosu.
    Export,
    /// x64 unwind bilgisi (.pdata).
    Pdata,
    /// Giriş noktası.
    EntryPoint,
    /// Prolog heuristiği.
    Prologue,
}

/// x86-64 disassembler ve fonksiyon çıkarıcı.
///
/// Capstone handle'ı thread-local olarak önbelleklenir; bu sayede her
/// fonksiyon için yeniden başlatma maliyeti ödenmez.
pub struct FunctionFingerprinter;

impl FunctionFingerprinter {
    /// Yeni bir fingerprinter oluşturur.
    pub fn new() -> Self {
        Self
    }

    /// Verilen kod parçasını çözümler.
    pub fn disassemble(&self, code: &[u8], address: u64) -> Result<Vec<InstructionInfo>> {
        with_capstone(|cs| {
            let instructions = cs
                .disasm_all(code, address)
                .map_err(|e| anyhow::anyhow!("Disassembly başarısız: {e}"))?;

            let mut out = Vec::with_capacity(instructions.len());
            for insn in instructions.iter() {
                let mnemonic = insn.mnemonic().unwrap_or("").to_string();
                let op_str = insn.op_str().unwrap_or("").to_string();
                let bytes = insn.bytes().to_vec();
                let size = bytes.len();
                let end_address = insn.address().saturating_add(size as u64);

                out.push(InstructionInfo {
                    address: insn.address(),
                    size,
                    bytes,
                    target: direct_target(&op_str),
                    rip_target: rip_relative_target(&op_str, end_address),
                    mnemonic,
                    op_str,
                });
            }
            Ok(out)
        })
    }
}

impl Default for FunctionFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    static CAPSTONE: RefCell<Option<Capstone>> = const { RefCell::new(None) };
}

/// Thread-local capstone handle'ı ile verilen işi çalıştırır.
fn with_capstone<T>(f: impl FnOnce(&Capstone) -> Result<T>) -> Result<T> {
    CAPSTONE.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let cs = Capstone::new()
                .x86()
                .mode(ArchMode::Mode64)
                .detail(true)
                .build()
                .context("Capstone başlatılamadı")?;
            *slot = Some(cs);
        }
        match slot.as_ref() {
            Some(cs) => f(cs),
            None => Err(anyhow::anyhow!("Capstone başlatılamadı")),
        }
    })
}

/// `call 0x140001000` biçimindeki doğrudan hedefi çözer.
fn direct_target(op_str: &str) -> Option<u64> {
    let trimmed = op_str.trim();
    let hex = trimmed.strip_prefix("0x")?;
    if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// `qword ptr [rip + 0x1234]` biçimindeki RIP-relative hedefi çözer.
fn rip_relative_target(op_str: &str, insn_end: u64) -> Option<u64> {
    let idx = op_str.find("rip")?;
    let after = &op_str[idx + 3..];
    let hex_pos = after.find("0x")?;
    let between = &after[..hex_pos];
    let sign: i64 = if between.contains('-') { -1 } else { 1 };

    let digits: String = after[hex_pos + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    let displacement = i64::from_str_radix(&digits, 16).ok()?;
    let target = insn_end as i64 + sign * displacement;
    if target < 0 {
        return None;
    }
    Some(target as u64)
}

/// Operand metnindeki sayıları maskeleyerek normalize edilmiş form üretir.
pub fn normalize_operands(op_str: &str) -> String {
    let mut result = String::with_capacity(op_str.len());
    let bytes: Vec<char> = op_str.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == '0' && i + 1 < bytes.len() && bytes[i + 1] == 'x' {
            result.push_str("IMM");
            i += 2;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            continue;
        }
        if c.is_ascii_digit() {
            // `r8`, `r9`, `xmm0` gibi register adlarının sonundaki rakamlar
            // kimliğin parçasıdır; immediate gibi maskelenmemelidir.
            let previous_is_identifier = i > 0 && {
                let previous = bytes[i - 1];
                previous.is_ascii_alphanumeric() || previous == '_'
            };
            if previous_is_identifier {
                result.push(c);
                i += 1;
                continue;
            }
            result.push_str("IMM");
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        result.push(c);
        i += 1;
    }
    result
}

/// Normalleştirilmiş opcode dizisinin hash'ini hesaplar.
pub fn normalized_opcode_hash(instructions: &[InstructionInfo]) -> u64 {
    let mut buffer = String::new();
    for insn in instructions {
        buffer.push_str(&insn.mnemonic);
        buffer.push(' ');
        buffer.push_str(&normalize_operands(&insn.op_str));
        buffer.push('\n');
    }
    xxh3_64(buffer.as_bytes())
}

/// PE içeriğinden fonksiyonları çıkarır.
///
/// `exports`: isim -> VA eşlemesi, `imports`: IAT VA -> import ismi eşlemesi.
#[allow(clippy::too_many_arguments)]
pub fn extract_functions(
    data: &[u8],
    image_base: u64,
    sections: &[SectionInfo],
    exports: &HashMap<String, u64>,
    imports: &HashMap<u64, String>,
    entry_point_va: u64,
) -> Vec<FunctionInfo> {
    let starts = collect_function_starts(data, image_base, sections, exports, entry_point_va);
    if starts.is_empty() {
        return Vec::new();
    }

    let known_addresses: HashSet<u64> = starts.iter().map(|s| image_base + s.rva as u64).collect();

    let mut functions = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().enumerate() {
        let va = image_base + start.rva as u64;
        let limit_rva = starts
            .get(index + 1)
            .map(|next| next.rva)
            .unwrap_or(start.rva.saturating_add(MAX_FUNCTION_BYTES as u32));

        if let Some(func) = extract_function_at(
            data,
            image_base,
            sections,
            exports,
            imports,
            &known_addresses,
            start,
            va,
            limit_rva,
        ) {
            functions.push(func);
        }
    }

    build_call_graph(&mut functions, &known_addresses);
    functions
}

/// Bir fonksiyonun maksimum kabul edilen boyutu.
const MAX_FUNCTION_BYTES: usize = 0x1_0000;

/// Fonksiyon başlangıç noktalarını toplar (export + .pdata + prolog + giriş noktası).
fn collect_function_starts(
    data: &[u8],
    image_base: u64,
    sections: &[SectionInfo],
    exports: &HashMap<String, u64>,
    entry_point_va: u64,
) -> Vec<FunctionStart> {
    let mut starts: Vec<FunctionStart> = Vec::new();

    for va in exports.values() {
        let rva = va.saturating_sub(image_base);
        if rva > 0 && rva <= u32::MAX as u64 {
            starts.push(FunctionStart {
                rva: rva as u32,
                end_rva: None,
                confidence: 1.0,
                source: StartSource::Export,
            });
        }
    }

    if entry_point_va >= image_base {
        let rva = entry_point_va - image_base;
        if rva <= u32::MAX as u64 {
            starts.push(FunctionStart {
                rva: rva as u32,
                end_rva: None,
                confidence: 0.8,
                source: StartSource::EntryPoint,
            });
        }
    }

    for (begin, end) in pdata_ranges(data, sections) {
        starts.push(FunctionStart {
            rva: begin,
            end_rva: Some(end),
            confidence: 0.9,
            source: StartSource::Pdata,
        });
    }

    for rva in scan_prologues(data, sections) {
        starts.push(FunctionStart {
            rva,
            end_rva: None,
            confidence: 0.6,
            source: StartSource::Prologue,
        });
    }

    // Aynı RVA'yı birden fazla kaynak bulduysa en güvenilirini seç.
    starts.sort_by(|a, b| {
        a.rva.cmp(&b.rva).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    starts.dedup_by_key(|s| s.rva);
    starts.sort_by_key(|s| s.rva);
    starts
}

/// `.pdata` bölümünden RUNTIME_FUNCTION aralıklarını okur.
fn pdata_ranges(data: &[u8], sections: &[SectionInfo]) -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    for section in sections {
        if !section.name.starts_with(".pdata") {
            continue;
        }
        let Some(start) = usize::try_from(section.raw_offset).ok() else {
            continue;
        };
        let Some(len) = usize::try_from(section.raw_size).ok() else {
            continue;
        };
        let Some(chunk) = data.get(start..start.saturating_add(len)) else {
            continue;
        };
        for entry in chunk.as_chunks::<12>().0 {
            let begin = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let end = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            if begin != 0 && end > begin {
                ranges.push((begin, end));
            }
        }
        break;
    }
    ranges
}

/// Çalıştırılabilir bölümlerde yaygın x64 prologlarını tarar.
fn scan_prologues(data: &[u8], sections: &[SectionInfo]) -> Vec<u32> {
    let mut starts = Vec::new();
    for section in sections {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let Some(start) = usize::try_from(section.raw_offset).ok() else {
            continue;
        };
        let Some(len) = usize::try_from(section.raw_size).ok() else {
            continue;
        };
        let Some(chunk) = data.get(start..start.saturating_add(len)) else {
            continue;
        };
        if chunk.len() < 4 {
            continue;
        }
        for offset in 0..=chunk.len() - 4 {
            let bytes = &chunk[offset..offset + 4];
            let is_prologue =
                (bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xE5)
                    || (bytes[0] == 0x55 && bytes[1] == 0x8B && bytes[2] == 0xEC)
                    || (bytes[0] == 0x40 && bytes[1] == 0x55);
            if is_prologue {
                let rva = (section.virtual_address as usize).saturating_add(offset);
                starts.push(u32::try_from(rva).unwrap_or(u32::MAX));
            }
        }
    }
    starts
}

/// IMAGE_SCN_MEM_EXECUTE bayrağı.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Tek bir fonksiyonu çıkarır.
#[allow(clippy::too_many_arguments)]
fn extract_function_at(
    data: &[u8],
    image_base: u64,
    sections: &[SectionInfo],
    exports: &HashMap<String, u64>,
    imports: &HashMap<u64, String>,
    known_addresses: &HashSet<u64>,
    start: &FunctionStart,
    va: u64,
    limit_rva: u32,
) -> Option<FunctionInfo> {
    let section = sections.iter().find(|s| {
        let sec_start = s.virtual_address as u32;
        let sec_end = sec_start.saturating_add(s.virtual_size.max(s.raw_size) as u32);
        start.rva >= sec_start && start.rva < sec_end
    })?;

    let offset_in_section = start.rva.checked_sub(section.virtual_address as u32)? as usize;
    // Yalnızca dosyada gerçekten bulunan (ham) bölüm verisi okunabilir.
    // Sanal padding'in dosya offsetine eşlenmesi yanlış bölüm verisi okur.
    let raw_size = usize::try_from(section.raw_size).ok()?;
    if offset_in_section >= raw_size {
        return None;
    }
    let section_file_start = usize::try_from(section.raw_offset).ok()?;
    let file_start = section_file_start.checked_add(offset_in_section)?;

    let section_end_rva = u32::try_from(
        section
            .virtual_address
            .saturating_add(section.virtual_size.max(section.raw_size)),
    )
    .unwrap_or(u32::MAX);
    let limit_rva = limit_rva.min(section_end_rva);
    let limit_offset = (limit_rva.saturating_sub(section.virtual_address as u32)) as usize;
    let max_len = limit_offset
        .min(MAX_FUNCTION_BYTES)
        .min(data.len().saturating_sub(file_start));
    let code = data.get(file_start..file_start.saturating_add(max_len))?;

    let fingerprinter = FunctionFingerprinter::new();
    let instructions = fingerprinter.disassemble(code, va).ok()?;
    if instructions.is_empty() {
        return None;
    }

    // Fonksiyonun gerçek sonu: bilinen bitiş (pdata/export), ya da ilk `ret`.
    let size = if let Some(end_rva) = start.end_rva {
        (end_rva.saturating_sub(start.rva)) as usize
    } else {
        instructions
            .iter()
            .find(|insn| insn.mnemonic == "ret")
            .map(|insn| (insn.end_address() - va) as usize)
            .unwrap_or_else(|| instructions.iter().map(|i| i.size).sum())
    };

    let size = size.clamp(1, code.len());
    let bytes = code.get(..size)?.to_vec();

    let opcode_hash = normalized_opcode_hash(&instructions);
    let string_refs = collect_string_refs(&instructions, image_base, sections, data);
    let import_calls = collect_import_calls(&instructions, imports);
    let callees = collect_callees(&instructions, known_addresses);
    let block_count = count_basic_blocks(&instructions);
    let confidence = calculate_confidence(start, &instructions, size);

    let name = exports
        .iter()
        .find(|(_, addr)| **addr == va)
        .map(|(name, _)| name.clone());

    Some(FunctionInfo {
        address: va,
        size,
        name,
        opcode_hash,
        string_refs,
        callees,
        callers: Vec::new(),
        import_calls,
        block_count,
        confidence,
        bytes,
    })
}

/// RIP-relative referans verilen string'lerin hash'lerini toplar.
fn collect_string_refs(
    instructions: &[InstructionInfo],
    image_base: u64,
    sections: &[SectionInfo],
    data: &[u8],
) -> Vec<u64> {
    let mut refs = Vec::new();
    for insn in instructions {
        let Some(target) = insn.rip_target else {
            continue;
        };
        if target < image_base {
            continue;
        }
        let Some(section) = sections.iter().find(|s| {
            let sec_start = s.virtual_address;
            let sec_end = sec_start.saturating_add(s.virtual_size.max(s.raw_size));
            let rva = target - image_base;
            rva >= sec_start && rva < sec_end
        }) else {
            continue;
        };
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            continue;
        }
        let Some(file_offset) = va_to_file_offset(target, image_base, sections) else {
            continue;
        };
        if let Some(text) = read_ascii_string(data, file_offset) {
            refs.push(xxh3_64(text.as_bytes()));
        }
    }
    refs.sort_unstable();
    refs.dedup();
    refs
}

/// VA'yı dosya offsetine çevirir.
pub fn va_to_file_offset(va: u64, image_base: u64, sections: &[SectionInfo]) -> Option<usize> {
    let rva = va.checked_sub(image_base)?;
    for section in sections {
        let Some(delta) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        // Yalnızca ham (dosyada mevcut) veri eşlenir; sanal padding atlanır.
        if delta >= section.raw_size {
            continue;
        }
        let offset = section.raw_offset.checked_add(delta)?;
        return usize::try_from(offset).ok();
    }
    None
}

/// Offsetteki null sonlu ASCII string'i okur.
fn read_ascii_string(data: &[u8], offset: usize) -> Option<String> {
    let rest = data.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    if !(4..=512).contains(&end) {
        return None;
    }
    let bytes = &rest[..end];
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\t')
    {
        return None;
    }
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

/// Import çağrılarını toplar (doğrudan ve IAT üzerinden).
fn collect_import_calls(
    instructions: &[InstructionInfo],
    imports: &HashMap<u64, String>,
) -> Vec<String> {
    let mut calls = Vec::new();
    for insn in instructions {
        if insn.mnemonic != "call" {
            continue;
        }
        if let Some(target) = insn.target {
            if let Some(name) = imports.get(&target) {
                calls.push(name.clone());
                continue;
            }
        }
        if let Some(target) = insn.rip_target {
            if let Some(name) = imports.get(&target) {
                calls.push(name.clone());
            }
        }
    }
    calls.sort();
    calls.dedup();
    calls
}

/// Bilinen fonksiyon başlangıçlarına yapılan doğrudan çağrıları toplar.
fn collect_callees(instructions: &[InstructionInfo], known_addresses: &HashSet<u64>) -> Vec<u64> {
    let mut callees = Vec::new();
    for insn in instructions {
        if insn.mnemonic != "call" {
            continue;
        }
        if let Some(target) = insn.target {
            if known_addresses.contains(&target) {
                callees.push(target);
            }
        }
    }
    callees.sort_unstable();
    callees.dedup();
    callees
}

/// Basic block sayısını tahmin eder.
fn count_basic_blocks(instructions: &[InstructionInfo]) -> usize {
    if instructions.is_empty() {
        return 0;
    }
    let branches = instructions
        .iter()
        .filter(|insn| {
            insn.mnemonic == "ret"
                || insn.mnemonic == "jmp"
                || insn.mnemonic.starts_with('j')
                || insn.mnemonic == "call"
        })
        .count();
    (branches + 1).min(instructions.len().max(1))
}

/// Fonksiyon sınırı güven skorunu hesaplar.
fn calculate_confidence(
    start: &FunctionStart,
    instructions: &[InstructionInfo],
    size: usize,
) -> f32 {
    let mut score = start.confidence;
    if start.source == StartSource::Prologue {
        if let Some(first) = instructions.first() {
            if first.mnemonic == "push" && first.op_str.contains("rbp") {
                score += 0.1;
            }
        }
        if instructions.iter().any(|i| i.mnemonic == "ret") {
            score += 0.1;
        }
    }
    if size >= 16 {
        score += 0.05;
    }
    score.clamp(0.0, 1.0)
}

/// Çağıran/çağrılan ilişkilerini kurar.
fn build_call_graph(functions: &mut [FunctionInfo], known_addresses: &HashSet<u64>) {
    let mut callers: HashMap<u64, Vec<u64>> = HashMap::new();
    for func in functions.iter() {
        for callee in &func.callees {
            if known_addresses.contains(callee) {
                callers.entry(*callee).or_default().push(func.address);
            }
        }
    }
    for func in functions.iter_mut() {
        if let Some(list) = callers.get(&func.address) {
            let mut list = list.clone();
            list.sort_unstable();
            list.dedup();
            func.callers = list;
        }
    }
}
