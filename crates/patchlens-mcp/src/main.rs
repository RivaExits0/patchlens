//! Patchlens MCP Server: binary diff and signature analysis (rmcp 0.2.1, stdio).
//!
//! Tam olarak 5 araç sunar:
//!   - diff_builds
//!   - check_signatures
//!   - explain_change
//!   - ci_report
//!   - export_offsets
//!
//! Sayfalama: varsayılan 50, maksimum 500. Önbellek `Patchlens`/`AnalysisCache`
//! üzerinden yol+boyut+mtime ile anahtarlanır. Hata mesajları Türkçe ve
//! eyleme dönüştürülür (ör. "Not a PE file. Supported: PE x64").

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, tool::Parameters},
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    service::serve_server,
    tool, tool_handler, tool_router, Error, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io;
use tracing::info;
use tracing_subscriber::FmtSubscriber;

use patchlens_core::report::summarize_signature_checks;
use patchlens_core::report::{explain_change, export_offsets};
use patchlens_core::{Binary, DiffConfig, ExportFormat, Patchlens, SignatureSet};

/// Varsayılan sayfa boyutu.
const DEFAULT_PAGE_SIZE: usize = 50;
/// Maksimum sayfa boyutu (MCP sınırı).
const MAX_PAGE_SIZE: usize = 500;

/// Sunucu durumu. `Patchlens` zaten `AnalysisCache` ile path+size+mtime
/// anahtarlı önbelleğe sahiptir; burada tekrar önbelleğe alınmaz.
struct ServerState {
    patchlens: Patchlens,
    tool_router: ToolRouter<Self>,
}

impl ServerState {
    /// Binary'yi yükler (Patchlens önbelleği üzerinden).
    async fn load_binary(&self, path: &Path) -> Result<Arc<Binary>, Error> {
        self.patchlens
            .analyze_binary(path)
            .await
            .map_err(|e| Error::invalid_params(format!("Binary yüklenemedi: {e}"), None))
    }

    /// İmza kümesini TOML içeriğinden veya dosya yolundan yükler.
    fn load_signatures(inline: Option<&str>, path: Option<&str>) -> Result<SignatureSet, Error> {
        let content = match (inline, path) {
            (Some(toml_str), _) => toml_str.to_string(),
            (None, Some(path_str)) => std::fs::read_to_string(path_str)
                .map_err(|e| Error::invalid_params(format!("İmza dosyası okunamadı: {e}"), None))?,
            (None, None) => String::new(),
        };
        toml::from_str::<SignatureSet>(&content)
            .map_err(|e| Error::invalid_params(format!("İmza dosyası çözümlenemedi: {e}"), None))
    }

    /// Fonksiyon sorgu dizgisini VA'ya çözer (hex adres veya isim).
    fn resolve_address(binary: &Binary, query: &str) -> Result<u64, Error> {
        let trimmed = query.trim();
        if let Some(hex) = trimmed.strip_prefix("0x") {
            if let Ok(addr) = u64::from_str_radix(hex, 16) {
                return Ok(addr);
            }
        }
        for func in binary.functions() {
            if func.name.as_deref() == Some(trimmed) {
                return Ok(func.address);
            }
        }
        if let Some(va) = binary.export_by_name(trimmed) {
            return Ok(va);
        }
        if let Ok(addr) = trimmed.parse::<u64>() {
            return Ok(addr);
        }
        Err(Error::invalid_params(
            format!("Function not found: {query} (try a 0x address or export name)"),
            None,
        ))
    }

    /// Sayfa boyutunu sınırlar.
    fn clamp_limit(limit: usize) -> usize {
        limit.min(MAX_PAGE_SIZE)
    }
}

/// Çıkış kodu türü (MCP'de hata `Error` olarak iletilir).
type ToolResult = Result<String, Error>;

// --------------------------------------------------------------------------
/// ARAÇ PARAMETRELERİ
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DiffBuildsParams {
    /// Eski binary dosya yolu.
    pub old_path: String,
    /// Yeni binary dosya yolu.
    pub new_path: String,
    /// Bulanık eşleştirme için minimum benzerlik skoru (0.0 - 1.0).
    #[serde(default)]
    pub min_score: Option<f64>,
    /// Sayfa boyutu (varsayılan 50, maksimum 500).
    #[serde(default = "default_page_size")]
    pub limit: usize,
    /// Sayfa offseti (varsayılan 0).
    #[serde(default)]
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CheckSignaturesParams {
    /// Eski binary dosya yolu (öneri üretimi için).
    pub old_path: String,
    /// Yeni binary dosya yolu.
    pub new_path: String,
    /// İmza kümesi TOML içeriği.
    #[serde(default)]
    pub signatures: Option<String>,
    /// İmza dosyası yolu (TOML).
    #[serde(default)]
    pub signatures_path: Option<String>,
    /// Kırık imzalar için yeni imza öneri üret.
    #[serde(default)]
    pub suggest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExplainChangeParams {
    /// Eski binary dosya yolu.
    pub old_path: String,
    /// Yeni binary dosya yolu.
    pub new_path: String,
    /// Fonksiyon adresi (0x...) veya adı.
    pub function: String,
    /// Maksimum satır sayısı.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Başlangıç offseti.
    #[serde(default)]
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CiReportParams {
    /// Eski binary dosya yolu.
    pub old_path: String,
    /// Yeni binary dosya yolu.
    pub new_path: String,
    /// İmza kümesi TOML içeriği.
    #[serde(default)]
    pub signatures: Option<String>,
    /// İmza dosyası yolu (TOML).
    #[serde(default)]
    pub signatures_path: Option<String>,
    /// Çıktı formatı: "sarif" veya "json".
    #[serde(default = "default_sarif")]
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExportOffsetsParams {
    /// Eski binary dosya yolu.
    pub old_path: String,
    /// Yeni binary dosya yolu.
    pub new_path: String,
    /// İmza kümesi TOML içeriği.
    #[serde(default)]
    pub signatures: Option<String>,
    /// İmza dosyası yolu (TOML).
    #[serde(default)]
    pub signatures_path: Option<String>,
    /// Çıktı formatı: "header", "ct", "json", "sarif".
    #[serde(default = "default_header")]
    pub format: String,
}

// --------------------------------------------------------------------------
// YARDIMCI FONKSİYONLAR
// --------------------------------------------------------------------------

fn default_page_size() -> usize {
    DEFAULT_PAGE_SIZE
}

fn default_limit() -> usize {
    200
}

fn default_sarif() -> String {
    "sarif".to_string()
}

fn default_header() -> String {
    "header".to_string()
}

fn parse_export_format(value: &str) -> Result<ExportFormat, Error> {
    match value.to_lowercase().as_str() {
        "sarif" => Ok(ExportFormat::Sarif),
        "json" => Ok(ExportFormat::Json),
        "header" | "c_header" | "h" => Ok(ExportFormat::CHeader),
        "ct" | "cheat_engine" | "cheatengine" => Ok(ExportFormat::CheatEngineCt),
        other => Err(Error::invalid_params(
            format!("Bilinmeyen format: {other}. Desteklenen: sarif, json, header, ct"),
            None,
        )),
    }
}

fn parse_ci_format(value: &str) -> Result<ExportFormat, Error> {
    match value.to_lowercase().as_str() {
        "sarif" => Ok(ExportFormat::Sarif),
        "json" => Ok(ExportFormat::Json),
        other => Err(Error::invalid_params(
            format!("Bilinmeyen format: {other}. Desteklenen: sarif, json"),
            None,
        )),
    }
}

/// `SignatureSet` sonuçlarını özetlemek için sarmalayıcı JSON.
fn wrap_results<T: Serialize>(results: &[T], summary: serde_json::Value) -> Result<String, Error> {
    let value = json!({
        "results": results,
        "summary": summary,
    });
    serde_json::to_string_pretty(&value)
        .map_err(|e| Error::internal_error(format!("Serileştirme hatası: {e}"), None))
}

// --------------------------------------------------------------------------
// ARAÇLAR
// --------------------------------------------------------------------------

#[tool_router(router = tool_router)]
impl ServerState {
    pub fn new() -> Self {
        Self {
            patchlens: Patchlens::new(),
            tool_router: Self::tool_router(),
        }
    }

    /// İki PE64 binary build'ini karşılaştırır.
    #[tool(
        name = "diff_builds",
        description = "İki PE64 binary build'ini karşılaştırır ve değişen/eklenen/kaldırılan fonksiyonları raporlar. Sayfalama varsayılan 50, maksimum 500."
    )]
    async fn diff_builds(&self, Parameters(params): Parameters<DiffBuildsParams>) -> ToolResult {
        let old = self.load_binary(Path::new(&params.old_path)).await?;
        let new = self.load_binary(Path::new(&params.new_path)).await?;

        let limit = if params.limit == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            ServerState::clamp_limit(params.limit)
        };
        let config = DiffConfig::default()
            .with_min_score(params.min_score.unwrap_or(0.75))
            .with_pagination(params.offset, limit);

        let diff = self.patchlens.diff(&old, &new, config);

        let value = serde_json::to_value(&diff)
            .map_err(|e| Error::internal_error(format!("Serileştirme hatası: {e}"), None))?;
        serde_json::to_string_pretty(&value)
            .map_err(|e| Error::internal_error(format!("Serileştirme hatası: {e}"), None))
    }

    /// İmzaları yeni binary'ye karşı kontrol eder; kırık imzalar için yeni imza önerir.
    #[tool(
        name = "check_signatures",
        description = "İmzaları yeni binary'ye karşı kontrol eder; kırık imzalar için yeni imza öneri üretir."
    )]
    async fn check_signatures(
        &self,
        Parameters(params): Parameters<CheckSignaturesParams>,
    ) -> ToolResult {
        let old = self.load_binary(Path::new(&params.old_path)).await?;
        let new = self.load_binary(Path::new(&params.new_path)).await?;
        let set = ServerState::load_signatures(
            params.signatures.as_deref(),
            params.signatures_path.as_deref(),
        )?;

        let results = if params.suggest {
            self.patchlens
                .check_signatures_with_suggestions(&old, &new, &set)
        } else {
            self.patchlens.check_signatures(&new, &set)
        };

        let summary = summarize_signature_checks(&results);
        wrap_results(&results, summary)
    }

    /// Belirli bir fonksiyonun disassembly değişimini açıklar.
    #[tool(
        name = "explain_change",
        description = "Belirli bir fonksiyonun iki build arasındaki disassembly değişimini açıklar."
    )]
    async fn explain_change(
        &self,
        Parameters(params): Parameters<ExplainChangeParams>,
    ) -> ToolResult {
        let old = self.load_binary(Path::new(&params.old_path)).await?;
        let new = self.load_binary(Path::new(&params.new_path)).await?;

        let addr = ServerState::resolve_address(&old, &params.function)?;
        let explanation = explain_change(
            &old,
            &new,
            addr,
            params.limit.min(MAX_PAGE_SIZE),
            params.offset,
        )
        .map_err(|e| Error::invalid_params(format!("Değişim açıklanamadı: {e}"), None))?;

        serde_json::to_string_pretty(&explanation)
            .map_err(|e| Error::internal_error(format!("Serileştirme hatası: {e}"), None))
    }

    /// CI raporu (SARIF / JSON) üretir.
    #[tool(
        name = "ci_report",
        description = "CI raporu (SARIF 2.1.0 veya JSON) üretir."
    )]
    async fn ci_report(&self, Parameters(params): Parameters<CiReportParams>) -> ToolResult {
        let old = self.load_binary(Path::new(&params.old_path)).await?;
        let new = self.load_binary(Path::new(&params.new_path)).await?;
        let set = ServerState::load_signatures(
            params.signatures.as_deref(),
            params.signatures_path.as_deref(),
        )?;

        let format = parse_ci_format(&params.format)?;

        let report = self
            .patchlens
            .generate_report(&old, &new, Some(&set), format)
            .map_err(|e| Error::internal_error(format!("Rapor üretilemedi: {e}"), None))?;

        Ok(report)
    }

    /// Offset'leri çeşitli formatlarda dışa aktarır.
    #[tool(
        name = "export_offsets",
        description = "Değişen/eklenen fonksiyon offset'lerini C header, Cheat Engine .CT, JSON veya SARIF olarak dışa aktarır."
    )]
    async fn export_offsets(
        &self,
        Parameters(params): Parameters<ExportOffsetsParams>,
    ) -> ToolResult {
        let old = self.load_binary(Path::new(&params.old_path)).await?;
        let new = self.load_binary(Path::new(&params.new_path)).await?;
        let set = ServerState::load_signatures(
            params.signatures.as_deref(),
            params.signatures_path.as_deref(),
        )?;

        let format = parse_export_format(&params.format)?;
        let exported = export_offsets(&old, &new, &set, format)
            .map_err(|e| Error::internal_error(format!("Dışa aktarım başarısız: {e}"), None))?;

        Ok(exported)
    }
}

#[tool_handler]
impl ServerHandler for ServerState {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            // `#[tool_handler]` yalnızca `call_tool`/`list_tools` üretir;
            // yetenekleri burada açıkça ilan etmek gerekir. Aksi halde
            // istemciler araçları keşfetmek için izin alamaz.
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "patchlens".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "Patchlens: PE64 binary diff ve AOB imza analizi. \
                 Araçlar: diff_builds (fonksiyon eşleştirme), check_signatures \
                 (imza doğrulama + öneri), explain_change (tek fonksiyon diff'i), \
                 ci_report (SARIF/JSON), export_offsets (C header/CT/JSON/SARIF). \
                 Analiz tamamen statiktir; binary çalıştırılmaz."
                    .to_string(),
            ),
        }
    }
}

// --------------------------------------------------------------------------
// GİRİŞ NOKTASI
// --------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .with_writer(io::stderr)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let server = ServerState::new();
    info!("Patchlens MCP sunucusu başlatılıyor (stdio)...");

    let transport = rmcp::transport::stdio();
    let service = serve_server(server, transport).await.map_err(|e| {
        Box::<dyn std::error::Error + Send + Sync + 'static>::from(e)
            as Box<dyn std::error::Error + Send + Sync>
    })?;

    service.waiting().await?;
    Ok(())
}
