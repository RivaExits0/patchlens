//! Testler için sentetik PE64 fixture üretimi.
//!
//! Üretilen dosyalar `old.exe` / `new.exe` ve `signatures.toml`.
//! `new.exe`, `old.exe` içindeki `mov eax, 30` immediate'ını `mov eax, 42`
//! olarak değiştirilmiş halidir; böylece diff motorunun "değişen fonksiyon"
//! yolunu test etmek mümkün olur.

use std::fs;
use std::path::Path;

use anyhow::Result;

/// Fixture dosyalarının yazılacağı dizin.
pub const FIXTURE_DIR: &str = "tests/fixtures";

/// Tek bir `.text` bölümü içeren minimal PE64 dosyası üretir.
fn build_pe_with_code(code: &[u8]) -> Result<Vec<u8>> {
    let mut pe = Vec::new();

    // ---- DOS header ----
    let mut dos = vec![0u8; 0x40];
    dos[0..2].copy_from_slice(b"MZ");
    dos[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe.extend_from_slice(&dos);
    pe.resize(0x80, 0);

    // ---- PE imzası ----
    pe.extend_from_slice(b"PE\0\0");

    // ---- COFF header ----
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
    pe.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    pe.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    pe.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    pe.extend_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
    pe.extend_from_slice(&0x0022u16.to_le_bytes()); // EXECUTABLE_IMAGE

    // ---- Optional header (PE32+) ----
    let opt = pe.len();
    pe.resize(opt + 0xF0, 0);
    pe[opt] = 0x0B; // Magic: PE32+ (0x20b -> bytes 0x0B 0x02)
    pe[opt + 1] = 0x02;

    let virtual_size = u32::try_from(code.len().max(1))?;
    let raw_size = code.len().max(1).div_ceil(0x200) as u32 * 0x200;
    let size_of_image = (0x1000 + virtual_size).div_ceil(0x1000) * 0x1000;

    put_u32(&mut pe, opt + 4, raw_size); // SizeOfCode
    put_u32(&mut pe, opt + 16, 0x1000); // AddressOfEntryPoint
    put_u32(&mut pe, opt + 20, 0x1000); // BaseOfCode
    put_u64(&mut pe, opt + 24, 0x0000_0001_4000_0000); // ImageBase
    put_u32(&mut pe, opt + 32, 0x1000); // SectionAlignment
    put_u32(&mut pe, opt + 36, 0x200); // FileAlignment
    put_u16(&mut pe, opt + 40, 6); // MajorOperatingSystemVersion
    put_u16(&mut pe, opt + 48, 6); // MajorSubsystemVersion
    put_u32(&mut pe, opt + 56, size_of_image); // SizeOfImage
    put_u32(&mut pe, opt + 60, 0x200); // SizeOfHeaders
    put_u16(&mut pe, opt + 68, 3); // Subsystem: CONSOLE
    put_u64(&mut pe, opt + 72, 0x100000); // SizeOfStackReserve
    put_u64(&mut pe, opt + 80, 0x1000); // SizeOfStackCommit
    put_u64(&mut pe, opt + 88, 0x100000); // SizeOfHeapReserve
    put_u64(&mut pe, opt + 96, 0x1000); // SizeOfHeapCommit
    put_u32(&mut pe, opt + 108, 16); // NumberOfRvaAndSizes

    // ---- Section header (.text) ----
    let sec = pe.len();
    pe.resize(sec + 40, 0);
    pe[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    put_u32(&mut pe, sec + 8, virtual_size); // VirtualSize
    put_u32(&mut pe, sec + 12, 0x1000); // VirtualAddress
    put_u32(&mut pe, sec + 16, raw_size); // SizeOfRawData
    put_u32(&mut pe, sec + 20, 0x200); // PointerToRawData
    put_u32(&mut pe, sec + 36, 0x6000_0020); // CODE | EXECUTE | READ

    // ---- Section içeriği ----
    pe.resize(0x200, 0);
    pe.extend_from_slice(code);
    pe.resize(0x200 + raw_size as usize, 0);

    Ok(pe)
}

/// `old.exe` içeriğini üretir.
pub fn build_old_pe() -> Result<Vec<u8>> {
    let mut code = Vec::new();
    // func_add @ 0x1000: push rbp; mov rbp,rsp; mov eax,30; add eax,esi; pop rbp; ret
    code.extend_from_slice(&[
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x1E, 0x00, 0x00, 0x00, 0x01, 0xF0, 0x5D, 0xC3,
    ]);
    while code.len() < 0x10 {
        code.push(0x90);
    }
    // func_sub @ 0x1010: push rbp; mov rbp,rsp; sub eax,edx; pop rbp; ret
    code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x2B, 0xC2, 0x5D, 0xC3]);
    while code.len() < 0x30 {
        code.push(0x90);
    }

    build_pe_with_code(&code)
}

/// `new.exe` içeriğini üretir (`old.exe` + immediate değişikliği).
pub fn build_new_pe() -> Result<Vec<u8>> {
    let mut pe = build_old_pe()?;
    // RVA 0x1005 -> dosya offseti 0x205: `mov eax, 30` -> `mov eax, 42`
    const PATCH_OFFSET: usize = 0x205;
    if let Some(byte) = pe.get_mut(PATCH_OFFSET) {
        *byte = 0x2A;
    }
    Ok(pe)
}

/// `count` adet 16 byte'lık, birbirinden farklı fonksiyon içeren PE üretir.
///
/// `patched = true` olduğunda her fonksiyonun immediate'ı bir artırılır; böylece
/// tüm fonksiyonlar "modified" olur ve sayfalama sınırı (100) test edilebilir.
/// Her fonksiyon: `push rbp; mov rbp,rsp; mov eax,<imm32>; pop rbp; ret`.
pub fn build_many_functions_pe(count: usize, patched: bool) -> Result<Vec<u8>> {
    let mut code = Vec::with_capacity(count * 16);
    for index in 0..count {
        // Patched sürümde immediate'lar 1000 offsetiyle kaydırılır; böylece
        // eski pattern'ler yeni build'de başka bir fonksiyona denk gelmez.
        let immediate = u32::try_from(index)? + 1 + if patched { 1000 } else { 0 };
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0xB8]);
        code.extend_from_slice(&immediate.to_le_bytes());
        code.extend_from_slice(&[0x5D, 0xC3]);
        while code.len() % 16 != 0 {
            code.push(0x90);
        }
    }
    build_pe_with_code(&code)
}

/// Fixture imza dosyasının içeriği.
pub fn signatures_toml() -> String {
    r#"
[[signatures]]
name = "func_add"
kind = "Aob"
pattern = "55 48 89 E5 B8 1E 00 00 00"
expected_offset = 0x1000
description = "Özgün add fonksiyonu (mov eax, 30)"

[[signatures]]
name = "func_sub"
kind = "Aob"
pattern = "55 48 89 E5 2B C2"
expected_offset = 0x1010
description = "Çıkarma fonksiyonu"

[[signatures]]
name = "func_add_wildcard"
kind = "Aob"
pattern = "55 48 89 E5 B8 ?? ?? ?? ??"
expected_offset = 0x1000
description = "func_add jokerli sürümü"
"#
    .to_string()
}

/// Tüm fixture dosyalarını verilen dizine yazar.
pub fn write_fixtures(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("old.exe"), build_old_pe()?)?;
    fs::write(dir.join("new.exe"), build_new_pe()?)?;
    fs::write(dir.join("signatures.toml"), signatures_toml())?;
    Ok(())
}

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
