//! Offset dışa aktarma ve değişim açıklama API'si.

pub use patchlens_core::report::{
    explain_change, export_offsets, summarize_diff, summarize_matches, summarize_signature_checks,
    BasicBlockChange, ChangeExplanation, ChangeType, DisassemblyLine, InstructionChange,
};
