//! Binary yükleme ve PE ayrıştırma.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use goblin::pe::PE;
use memmap2::Mmap;
use serde::{Deserialize, Serialize};

use crate::common::FunctionInfo;
use crate::function::extract_functions;

/// Desteklenen binary formatları.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    /// Windows PE (PE32+ / x64).
    Pe64,
    /// PE32 (x86) - desteklenmiyor.
    Pe32,
    /// Bilinmeyen format.
    Unsupported,
}

/// Bölüm (section) bilgisi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    /// Bölüm adı (ör. `.text`).
    pub name: String,
    /// Sanal adres (RVA).
    pub virtual_address: u64,
    /// Sanal boyut.
    pub virtual_size: u64,
    /// Dosya içindeki ham offset.
    pub raw_offset: u64,
    /// Ham boyut.
    pub raw_size: u64,
    /// PE bölüm bayrakları.
    pub characteristics: u32,
    /// Shannon entropisi.
    pub entropy: f64,
}

/// Import bilgisi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    /// Kaynak DLL adı.
    pub dll: String,
    /// Import edilen fonksiyon adı.
    pub name: String,
    /// PE hint değeri (goblin tarafından dışa aktarılmaz; bilinmiyorsa 0).
    pub hint: u16,
    /// IAT girdisinin sanal adresi.
    pub address: u64,
}

/// Export bilgisi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    /// Export edilen isim.
    pub name: String,
    /// Fonksiyonun sanal adresi.
    pub address: u64,
    /// Export ordinal'ı.
    pub ordinal: u16,
}

/// Binary hakkında üst seviye bilgi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// Dosya formatı.
    pub format: BinaryFormat,
    /// Mimari (ör. `x64`).
    pub architecture: String,
    /// Giriş noktasının sanal adresi.
    pub entry_point: u64,
    /// Image base (VA tabanı).
    pub image_base: u64,
    /// Bölümler.
    pub sections: Vec<SectionInfo>,
    /// Import'lar.
    pub imports: Vec<ImportInfo>,
    /// Export'lar.
    pub exports: Vec<ExportInfo>,
    /// Tespit edilen fonksiyon sayısı.
    pub function_count: usize,
}

/// PE'den çıkarılan, sahiplenilmiş metadata.
#[derive(Debug, Clone)]
pub struct PeImage {
    /// Image base.
    pub image_base: u64,
    /// Giriş noktasının VA'sı.
    pub entry_point: u64,
    /// Bölümler.
    pub sections: Vec<SectionInfo>,
    /// Import'lar.
    pub imports: Vec<ImportInfo>,
    /// Export'lar.
    pub exports: Vec<ExportInfo>,
}

/// Binary verisinin saklanma biçimi.
#[derive(Debug)]
enum Storage {
    /// Dosyadan bellek eşlemesi.
    Mapped(Arc<Mmap>),
    /// Bellekte tutulan kopya (test/fuzz için).
    Owned(Arc<Vec<u8>>),
}

impl Storage {
    /// Ham byte'ları döndürür.
    fn as_slice(&self) -> &[u8] {
        match self {
            Storage::Mapped(mmap) => mmap.as_ref(),
            Storage::Owned(bytes) => bytes.as_ref(),
        }
    }
}

/// Yüklenmiş ve analiz edilmiş binary.
#[derive(Debug)]
pub struct Binary {
    path: PathBuf,
    storage: Storage,
    info: BinaryInfo,
    functions: Vec<FunctionInfo>,
    function_map: HashMap<u64, usize>,
    exports_by_name: HashMap<String, u64>,
    exports_by_va: HashMap<u64, String>,
    imports_by_va: HashMap<u64, String>,
}

impl Binary {
    /// Dosyayı oku, PE olarak doğrula ve fonksiyonları çıkarır.
    pub fn load(path: &Path) -> Result<Arc<Self>> {
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let file = std::fs::File::open(path)
            .with_context(|| format!("Dosya açılamadı: {}", path.display()))?;
        let mmap = mmap::map_readonly(&file)
            .with_context(|| format!("Dosya eşlenemedi (mmap): {}", path.display()))?;

        Self::from_mmap(canonical, Arc::new(mmap))
    }

    /// Bellek eşlemesinden binary oluşturur.
    pub fn from_mmap(path: PathBuf, data: Arc<Mmap>) -> Result<Arc<Self>> {
        let image = parse_pe(&data)?;
        Self::from_image(path, Storage::Mapped(data), image)
    }

    /// Ham byte'lardan binary oluşturur (test/fuzz için).
    pub fn from_bytes(path: PathBuf, bytes: Vec<u8>) -> Result<Arc<Self>> {
        let storage = Storage::Owned(Arc::new(bytes));
        let image = parse_pe(storage.as_slice())?;
        Self::from_image(path, storage, image)
    }

    /// Çıkarılmış metadata ile binary oluşturur.
    fn from_image(path: PathBuf, storage: Storage, image: PeImage) -> Result<Arc<Self>> {
        let exports_by_name: HashMap<String, u64> = image
            .exports
            .iter()
            .map(|e| (e.name.clone(), e.address))
            .collect();
        let exports_by_va: HashMap<u64, String> = image
            .exports
            .iter()
            .map(|e| (e.address, e.name.clone()))
            .collect();
        let imports_by_va: HashMap<u64, String> = image
            .imports
            .iter()
            .map(|i| (i.address, i.name.clone()))
            .collect();

        let functions = extract_functions(
            storage.as_slice(),
            image.image_base,
            &image.sections,
            &exports_by_name,
            &imports_by_va,
            image.entry_point,
        );

        let function_count = functions.len();
        let mut function_map = HashMap::with_capacity(function_count);
        for (idx, func) in functions.iter().enumerate() {
            function_map.insert(func.address, idx);
        }

        let info = BinaryInfo {
            format: BinaryFormat::Pe64,
            architecture: "x64".to_string(),
            entry_point: image.entry_point,
            image_base: image.image_base,
            sections: image.sections,
            imports: image.imports,
            exports: image.exports,
            function_count,
        };

        Ok(Arc::new(Self {
            path,
            storage,
            info,
            functions,
            function_map,
            exports_by_name,
            exports_by_va,
            imports_by_va,
        }))
    }

    /// Binary'nin dosya yolu.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Binary'nin ham byte'ları.
    pub fn data(&self) -> &[u8] {
        self.storage.as_slice()
    }

    /// Üst seviye binary bilgisi.
    pub fn info(&self) -> &BinaryInfo {
        &self.info
    }

    /// Çıkarılan fonksiyonlar.
    pub fn functions(&self) -> &[FunctionInfo] {
        &self.functions
    }

    /// VA ile fonksiyon bulur.
    pub fn function_by_va(&self, va: u64) -> Option<&FunctionInfo> {
        self.function_map.get(&va).map(|&idx| &self.functions[idx])
    }

    /// VA ile fonksiyon bulur (yoksa `None`).
    pub fn function_at_va(&self, va: u64) -> Option<&FunctionInfo> {
        self.function_by_va(va)
    }

    /// İsme göre export bulur.
    pub fn export_by_name(&self, name: &str) -> Option<u64> {
        self.exports_by_name.get(name).copied()
    }

    /// VA'ya göre export ismi bulur.
    pub fn export_name_at(&self, va: u64) -> Option<&str> {
        self.exports_by_va.get(&va).map(|s| s.as_str())
    }

    /// IAT VA'sına göre import ismi bulur.
    pub fn import_name_at(&self, va: u64) -> Option<&str> {
        self.imports_by_va.get(&va).map(|s| s.as_str())
    }

    /// VA'dan byte okur.
    pub fn read_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        let offset = self.va_to_file_offset(va)?;
        let end = offset.checked_add(len)?;
        self.storage.as_slice().get(offset..end)
    }

    /// VA'yı dosya offsetine çevirir.
    pub fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.info.image_base)?;
        rva_to_file_offset(&self.info.sections, rva)
    }

    /// Dosya offsetini VA'ya çevirir.
    pub fn va_from_offset(&self, offset: usize) -> Option<u64> {
        for section in &self.info.sections {
            let raw_start = usize::try_from(section.raw_offset).ok()?;
            let raw_end = raw_start.checked_add(usize::try_from(section.raw_size).ok()?)?;
            if offset >= raw_start && offset < raw_end {
                let rva = section
                    .virtual_address
                    .checked_add((offset - raw_start) as u64)?;
                return self.info.image_base.checked_add(rva);
            }
        }
        None
    }

    /// RVA'yı dosya offsetine çevirir.
    pub fn file_offset_from_rva(&self, rva: u64) -> Option<usize> {
        rva_to_file_offset(&self.info.sections, rva)
    }
}

/// RVA'yı, yalnızca bölümün ham (dosyada bulunan) verisi içinde arar.
///
/// Sanal padding (virtual_size > raw_size) dosyada yer kaplamadığı için
/// dosya offsetine eşlenmez; aksi halde başka bir bölümün verisi okunur.
fn rva_to_file_offset(sections: &[SectionInfo], rva: u64) -> Option<usize> {
    for section in sections {
        let Some(delta) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        if delta >= section.raw_size {
            continue;
        }
        let offset = section.raw_offset.checked_add(delta)?;
        return usize::try_from(offset).ok();
    }
    None
}

/// PE header'ını ayrıştırıp sahiplenilmiş metadata üretir.
pub fn parse_pe(data: &[u8]) -> Result<PeImage> {
    let pe = PE::parse(data)
        .map_err(|e| anyhow::anyhow!("{} (goblin: {e})", crate::error::PatchlensError::NotPe64))?;

    if !pe.is_64 {
        bail!(
            "{} (bulunan: PE32/x86)",
            crate::error::PatchlensError::NotPe64
        );
    }

    let image_base = pe.image_base as u64;
    let entry_point = image_base.saturating_add(pe.entry as u64);

    let mut sections = Vec::with_capacity(pe.sections.len());
    for section in &pe.sections {
        let name = section.name().unwrap_or("<invalid>").to_string();
        let raw_offset = section.pointer_to_raw_data as u64;
        let raw_size = section.size_of_raw_data as u64;
        let entropy = section_data(data, raw_offset, raw_size)
            .map(calculate_entropy)
            .unwrap_or(0.0);

        sections.push(SectionInfo {
            name,
            virtual_address: section.virtual_address as u64,
            virtual_size: section.virtual_size as u64,
            raw_offset,
            raw_size,
            characteristics: section.characteristics,
            entropy,
        });
    }

    let mut imports = Vec::new();
    for import in &pe.imports {
        let dll = import.dll.to_string();
        let address = image_base.saturating_add(import.rva as u64);
        imports.push(ImportInfo {
            dll: dll.clone(),
            name: import.name.to_string(),
            hint: 0,
            address,
        });
    }

    let mut exports = Vec::new();
    let ordinals = export_ordinals(data, &pe, &sections);
    for export in &pe.exports {
        let Some(name) = export.name else {
            continue;
        };
        exports.push(ExportInfo {
            name: name.to_string(),
            address: image_base.saturating_add(export.rva as u64),
            ordinal: ordinals.get(name).copied().unwrap_or(0),
        });
    }

    Ok(PeImage {
        image_base,
        entry_point,
        sections,
        imports,
        exports,
    })
}

/// Export isimlerini gerçek ordinal numaralarına eşler.
///
/// `goblin`'in `Export` yapısı ordinal taşımadığı için ordinal tablosu
/// doğrudan export dizininden okunur; `enumerate()` indeksi ordinal değildir.
fn export_ordinals(data: &[u8], pe: &PE, sections: &[SectionInfo]) -> HashMap<String, u16> {
    let Some(export_data) = &pe.export_data else {
        return HashMap::new();
    };
    let ordinal_base = export_data.export_directory_table.ordinal_base;
    let mut ordinals = HashMap::new();

    for (&name_rva, &ordinal_index) in export_data
        .export_name_pointer_table
        .iter()
        .zip(export_data.export_ordinal_table.iter())
    {
        let Some(offset) = rva_to_file_offset(sections, u64::from(name_rva)) else {
            continue;
        };
        let Some(rest) = data.get(offset..) else {
            continue;
        };
        let Some(end) = rest.iter().position(|&byte| byte == 0) else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(&rest[..end]) else {
            continue;
        };
        let ordinal = ordinal_base.saturating_add(u32::from(ordinal_index));
        ordinals.insert(name.to_string(), u16::try_from(ordinal).unwrap_or(u16::MAX));
    }

    ordinals
}

/// Bölümün ham verisini dilimler (taşma olursa `None`).
fn section_data(data: &[u8], raw_offset: u64, raw_size: u64) -> Option<&[u8]> {
    let start = usize::try_from(raw_offset).ok()?;
    let len = usize::try_from(raw_size).ok()?;
    data.get(start..start.saturating_add(len))
}

/// Shannon entropisi hesaplar.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts.iter().fold(0.0, |acc, &count| {
        if count > 0 {
            let p = count as f64 / len;
            acc - p * p.log2()
        } else {
            acc
        }
    })
}

/// Yalnızca bu modül içinde kullanılan, `unsafe` izole edilmiş mmap yardımcıları.
mod mmap {
    use std::fs::File;
    use std::io;

    use memmap2::Mmap;

    /// Dosyayı salt-okunur olarak eşler.
    #[allow(unsafe_code)]
    pub fn map_readonly(file: &File) -> io::Result<Mmap> {
        // SAFETY: `Mmap::map` yalnızca geçerli bir dosya tanıtıcısı ister ve
        // sonuç salt-okunur bir eşlemedir; dosya değiştirilse bile bellek
        // her zaman geçerli bir eşlemeye karşılık gelir.
        unsafe { Mmap::map(file) }
    }
}
