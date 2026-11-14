//! Rapor üretimi: SARIF, JSON, C header ve Cheat Engine `.CT`.
//!
//! Bu crate core'daki rapor motorunun ince bir sarmalayıcısıdır; tüm
//! mantık `patchlens-core` içinde yaşar.

pub mod ci_report;
pub mod export;

pub use ci_report::{CiReport, ExportFormat};
pub use export::{
    explain_change, export_offsets, BasicBlockChange, ChangeExplanation, ChangeType,
    DisassemblyLine, InstructionChange,
};
