//! Patchlens CLI: binary diff ve imza analizi.
//!
//! Çıkış kodları:
//! - `0`: başarılı
//! - `1`: kırık imza bulundu
//! - `2`: kullanım veya G/Ç hatası

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use patchlens_core::report::{explain_change, export_offsets, CiReport, ExportFormat};
use patchlens_core::{Binary, DiffConfig, Patchlens, Signature, SignatureSet, SignatureStatus};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Kırık imza bulunduğunda dönülen çıkış kodu.
const EXIT_BROKEN_SIGNATURE: u8 = 1;
/// Kullanım/G/Ç hatasında dönülen çıkış kodu.
const EXIT_USAGE: u8 = 2;

#[derive(Parser)]
#[command(
    name = "patchlens",
    version,
    about = "Binary diff ve imza analizi (statik analiz)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Ayrıntılı loglama
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// İki binary build'ini karşılaştır
    Diff {
        /// Eski binary yolu
        #[arg(value_name = "OLD")]
        old: PathBuf,
        /// Yeni binary yolu
        #[arg(value_name = "NEW")]
        new: PathBuf,
        /// Çıktı formatı
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
        /// Bulanık eşleştirme için minimum benzerlik skoru
        #[arg(long, default_value = "0.75")]
        min_score: f64,
        /// Sayfalama: maksimum sonuç sayısı
        #[arg(long, default_value = "100")]
        limit: usize,
        /// Sayfalama: başlangıç offseti
        #[arg(long, default_value = "0")]
        offset: usize,
    },

    /// İmzaları binary'ye karşı kontrol et
    Sigs {
        /// Eski binary yolu (öneri üretimi için)
        #[arg(value_name = "OLD")]
        old: PathBuf,
        /// Yeni binary yolu
        #[arg(value_name = "NEW")]
        new: PathBuf,
        /// İmza dosyası (TOML)
        #[arg(short, long, value_name = "FILE")]
        signatures: PathBuf,
        /// Kırık imzalar için yeni imza öner
        #[arg(long)]
        suggest: bool,
        /// SARIF raporu yaz
        #[arg(long, value_name = "FILE")]
        sarif: Option<PathBuf>,
        /// Çıktı formatı
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },

    /// Bir fonksiyondaki değişimi açıkla
    Explain {
        /// Eski binary yolu
        #[arg(value_name = "OLD")]
        old: PathBuf,
        /// Yeni binary yolu
        #[arg(value_name = "NEW")]
        new: PathBuf,
        /// Fonksiyon adresi (hex) veya adı
        #[arg(short, long, value_name = "ADDR|NAME")]
        function: String,
        /// Maksimum satır sayısı
        #[arg(long, default_value = "200")]
        limit: usize,
        /// Başlangıç offseti
        #[arg(long, default_value = "0")]
        offset: usize,
    },

    /// Offset'leri çeşitli formatlarda dışa aktar
    Export {
        /// Eski binary yolu
        #[arg(value_name = "OLD")]
        old: PathBuf,
        /// Yeni binary yolu
        #[arg(value_name = "NEW")]
        new: PathBuf,
        /// İmza dosyası (TOML)
        #[arg(short, long, value_name = "FILE")]
        signatures: PathBuf,
        /// Çıktı formatı
        #[arg(short, long, value_enum, default_value = "header")]
        format: ExportFormatArg,
        /// Çıktı dosyası (yoksa stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

/// CLI çıktı formatı.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// JSON
    Json,
    /// Okunabilir metin
    Text,
    /// SARIF 2.1.0
    Sarif,
}

/// Dışa aktarma formatı.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ExportFormatArg {
    /// C header (`#define`)
    Header,
    /// Cheat Engine tablosu
    Ct,
    /// JSON
    Json,
    /// SARIF
    Sarif,
}

impl From<ExportFormatArg> for ExportFormat {
    fn from(value: ExportFormatArg) -> Self {
        match value {
            ExportFormatArg::Header => ExportFormat::CHeader,
            ExportFormatArg::Ct => ExportFormat::CheatEngineCt,
            ExportFormatArg::Json => ExportFormat::Json,
            ExportFormatArg::Sarif => ExportFormat::Sarif,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let level = if std::env::args().any(|arg| arg == "-v" || arg == "--verbose") {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("hata: {error:#}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

/// CLI mantığı; çıkış kodunu döndürür.
async fn run() -> Result<u8> {
    let cli = Cli::parse();
    let patchlens = Patchlens::new();

    match cli.command {
        Commands::Diff {
            old,
            new,
            format,
            min_score,
            limit,
            offset,
        } => {
            info!("Eski binary yükleniyor: {}", old.display());
            let old_bin = patchlens.analyze_binary(&old).await?;
            info!("Yeni binary yükleniyor: {}", new.display());
            let new_bin = patchlens.analyze_binary(&new).await?;

            let config = DiffConfig::default()
                .with_min_score(min_score)
                .with_pagination(offset, limit);
            let diff = patchlens.diff(&old_bin, &new_bin, config);

            let output = match format {
                OutputFormat::Json => {
                    CiReport::generate(&diff, &old_bin, &new_bin, None, ExportFormat::Json)?
                }
                OutputFormat::Sarif => {
                    CiReport::generate(&diff, &old_bin, &new_bin, None, ExportFormat::Sarif)?
                }
                OutputFormat::Text => format_text_diff(&diff),
            };
            println!("{output}");
            Ok(0)
        }

        Commands::Sigs {
            old,
            new,
            signatures,
            suggest,
            sarif,
            format,
        } => {
            let sig_set = load_signatures(&signatures)?;

            info!("Eski binary yükleniyor: {}", old.display());
            let old_bin = patchlens.analyze_binary(&old).await?;
            info!("Yeni binary yükleniyor: {}", new.display());
            let new_bin = patchlens.analyze_binary(&new).await?;

            let results = if suggest {
                patchlens.check_signatures_with_suggestions(&old_bin, &new_bin, &sig_set)
            } else {
                patchlens.check_signatures(&new_bin, &sig_set)
            };

            if suggest {
                let suggestions: Vec<Signature> = results
                    .iter()
                    .filter_map(|result| result.suggested_signature.clone())
                    .collect();
                if !suggestions.is_empty() {
                    println!("{}", serde_json::to_string_pretty(&suggestions)?);
                }
            }

            // SARIF hem `--format sarif` hem `--sarif FILE` için bir kez üretilir.
            let sarif_output = if format == OutputFormat::Sarif || sarif.is_some() {
                Some(CiReport::generate(
                    &patchlens.diff(&old_bin, &new_bin, DiffConfig::unpaginated()),
                    &old_bin,
                    &new_bin,
                    Some(&sig_set),
                    ExportFormat::Sarif,
                )?)
            } else {
                None
            };

            let output = match format {
                OutputFormat::Json => serde_json::to_string_pretty(&results)?,
                OutputFormat::Sarif => sarif_output.clone().unwrap_or_default(),
                OutputFormat::Text => format_text_sig_results(&results),
            };
            println!("{output}");

            if let (Some(sarif_path), Some(sarif_report)) = (sarif, sarif_output) {
                std::fs::write(&sarif_path, sarif_report)
                    .with_context(|| format!("SARIF yazılamadı: {}", sarif_path.display()))?;
                info!("SARIF raporu yazıldı: {}", sarif_path.display());
            }

            let has_broken = results
                .iter()
                .any(|result| result.status == SignatureStatus::Broken);
            Ok(if has_broken { EXIT_BROKEN_SIGNATURE } else { 0 })
        }

        Commands::Explain {
            old,
            new,
            function,
            limit,
            offset,
        } => {
            info!("Eski binary yükleniyor: {}", old.display());
            let old_bin = patchlens.analyze_binary(&old).await?;
            info!("Yeni binary yükleniyor: {}", new.display());
            let new_bin = patchlens.analyze_binary(&new).await?;

            let func_addr = resolve_function(&old_bin, &new_bin, &function)?;
            let explanation = explain_change(&old_bin, &new_bin, func_addr, limit, offset)?;
            println!("{}", serde_json::to_string_pretty(&explanation)?);
            Ok(0)
        }

        Commands::Export {
            old,
            new,
            signatures,
            format,
            output,
        } => {
            let sig_set = load_signatures(&signatures)?;

            info!("Eski binary yükleniyor: {}", old.display());
            let old_bin = patchlens.analyze_binary(&old).await?;
            info!("Yeni binary yükleniyor: {}", new.display());
            let new_bin = patchlens.analyze_binary(&new).await?;

            let exported = export_offsets(&old_bin, &new_bin, &sig_set, format.into())?;

            if let Some(output_path) = output {
                std::fs::write(&output_path, &exported)
                    .with_context(|| format!("Çıktı yazılamadı: {}", output_path.display()))?;
                info!("Dışa aktarıldı: {}", output_path.display());
            } else {
                println!("{exported}");
            }
            Ok(0)
        }
    }
}

/// TOML imza dosyasını okur.
fn load_signatures(path: &PathBuf) -> Result<SignatureSet> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("İmza dosyası okunamadı: {}", path.display()))?;
    let set: SignatureSet = toml::from_str(&content)
        .with_context(|| format!("İmza dosyası çözümlenemedi: {}", path.display()))?;
    Ok(set)
}

/// Fonksiyonu adres veya isim ile çözer.
fn resolve_function(old_binary: &Binary, new_binary: &Binary, query: &str) -> Result<u64> {
    let trimmed = query.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        if let Ok(addr) = u64::from_str_radix(hex, 16) {
            return Ok(addr);
        }
    }

    for binary in [old_binary, new_binary] {
        for func in binary.functions() {
            if func.name.as_deref() == Some(trimmed) {
                return Ok(func.address);
            }
        }
    }

    if let Ok(addr) = trimmed.parse::<u64>() {
        return Ok(addr);
    }

    anyhow::bail!("Function not found: {query} (try a 0x address or export name)")
}

/// Diff çıktısını metin olarak biçimlendirir.
fn format_text_diff(diff: &patchlens_core::DiffResult) -> String {
    let mut out = String::new();
    out.push_str("=== Patchlens Diff ===\n");
    out.push_str(&format!("Eski toplam: {} fonksiyon\n", diff.old_total));
    out.push_str(&format!("Yeni toplam: {} fonksiyon\n", diff.new_total));
    // Sayfalama kullanılsa bile gerçek toplamlar gösterilir.
    out.push_str(&format!("Değişmeyen: {}\n", diff.totals.unchanged));
    out.push_str(&format!("Değişen: {}\n", diff.totals.modified));
    out.push_str(&format!("Eklenen: {}\n", diff.totals.added));
    out.push_str(&format!("Kaldırılan: {}\n", diff.totals.removed));
    out.push('\n');

    for m in &diff.modified {
        if let (Some(old), Some(new)) = (&m.old, &m.new) {
            out.push_str(&format!(
                "DEĞİŞTİ: 0x{:x} -> 0x{:x} (skor: {:.1}%, blok: {}, eşleşme: {:?})\n",
                old.address,
                new.address,
                m.score * 100.0,
                m.changed_blocks,
                m.kind
            ));
        }
    }

    for m in &diff.added {
        if let Some(new) = &m.new {
            out.push_str(&format!(
                "EKLENDİ:  0x{:x} ({})\n",
                new.address,
                new.name.as_deref().unwrap_or("?")
            ));
        }
    }

    for m in &diff.removed {
        if let Some(old) = &m.old {
            out.push_str(&format!(
                "KALDIRILDI: 0x{:x} ({})\n",
                old.address,
                old.name.as_deref().unwrap_or("?")
            ));
        }
    }

    out
}

/// İmza sonuçlarını metin olarak biçimlendirir.
fn format_text_sig_results(results: &[patchlens_core::SignatureCheckResult]) -> String {
    let mut out = String::new();
    for result in results {
        let expected = match result.signature.expected_offset {
            Some(offset) => format!("beklenen 0x{:x}", offset),
            None => "beklenen offset yok".to_string(),
        };
        out.push_str(&format!(
            "{}: {} ({}) - {} eşleşme\n",
            result.signature.name,
            result.status,
            expected,
            result.matches.len()
        ));
        for m in &result.matches {
            out.push_str(&format!("  0x{:x} {}\n", m.offset, m.context));
        }
        if let Some(suggestion) = &result.suggested_signature {
            out.push_str(&format!(
                "  öneri: {} (pattern: {})\n",
                suggestion.name,
                suggestion.pattern.as_deref().unwrap_or("-")
            ));
        }
    }
    out
}
