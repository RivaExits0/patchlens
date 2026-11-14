//! Ortak veri tipleri: fonksiyon bilgisi, parmak izi ve talimat modelleri.

use serde::{Deserialize, Serialize};

/// Binary içinden çıkarılan tek bir fonksiyonun özeti.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Fonksiyon girişinin sanal adresi (VA).
    pub address: u64,
    /// Fonksiyonun byte cinsinden uzunluğu.
    pub size: usize,
    /// Dışa aktarım tablosundan gelen isim (varsa).
    pub name: Option<String>,
    /// Normalleştirilmiş opcode dizisi hash'i (adresler/immediat'ler maskelenir).
    pub opcode_hash: u64,
    /// Fonksiyonun referans verdiği string hash'leri.
    pub string_refs: Vec<u64>,
    /// Fonksiyonun çağırdığı fonksiyonların VA adresleri.
    pub callees: Vec<u64>,
    /// Fonksiyonu çağıran fonksiyonların VA adresleri.
    pub callers: Vec<u64>,
    /// Fonksiyon içindeki import çağrılarının isimleri.
    pub import_calls: Vec<String>,
    /// Tahmini basic block sayısı.
    pub block_count: usize,
    /// Fonksiyon sınırı tespit güven skoru (0.0 - 1.0).
    pub confidence: f32,
    /// Fonksiyonun ham byte'ları.
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

impl Default for FunctionInfo {
    fn default() -> Self {
        Self {
            address: 0,
            size: 0,
            name: None,
            opcode_hash: 0,
            string_refs: Vec::new(),
            callees: Vec::new(),
            callers: Vec::new(),
            import_calls: Vec::new(),
            block_count: 0,
            confidence: 0.0,
            bytes: Vec::new(),
        }
    }
}

/// İki build arasında karşılaştırma için normalleştirilmiş parmak izi.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    /// Normalleştirilmiş opcode hash'i.
    pub opcode_hash: u64,
    /// String referans hash'leri (sıralı).
    pub string_hashes: Vec<u64>,
    /// Import çağrı isimleri (sıralı).
    pub imports: Vec<String>,
    /// Fonksiyon boyutu.
    pub size: usize,
    /// Basic block sayısı.
    pub block_count: usize,
}

/// Bir fonksiyon için normalize parmak izi üretir.
pub fn generate_fingerprint(func: &FunctionInfo) -> Fingerprint {
    let mut string_hashes = func.string_refs.clone();
    string_hashes.sort_unstable();
    string_hashes.dedup();

    let mut imports = func.import_calls.clone();
    imports.sort();
    imports.dedup();

    Fingerprint {
        opcode_hash: func.opcode_hash,
        string_hashes,
        imports,
        size: func.size,
        block_count: func.block_count,
    }
}

/// Çözümlenmiş tek bir makine talimatı (sahibi olunan veri).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    /// Talimatın sanal adresi.
    pub address: u64,
    /// Talimatın byte uzunluğu.
    pub size: usize,
    /// Talimatın byte'ları.
    pub bytes: Vec<u8>,
    /// Mnemonik (ör. `mov`).
    pub mnemonic: String,
    /// Operand metni (ör. `eax, 0x1e`).
    pub op_str: String,
    /// Doğrudan çağrı/atlama hedefi (varsa).
    pub target: Option<u64>,
    /// RIP-relative adreslemeden hesaplanan hedef (varsa).
    pub rip_target: Option<u64>,
}

impl InstructionInfo {
    /// Talimatın bir sonraki adresi.
    pub fn end_address(&self) -> u64 {
        self.address + self.size as u64
    }
}
