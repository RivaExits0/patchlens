//! Patchlens uçtan uca entegrasyon testleri.

use std::path::{Path, PathBuf};

use patchlens_core::{
    DiffConfig, Patchlens, Signature, SignatureKind, SignatureSet, SignatureStatus,
};

/// Fixture dosyalarını geçici dizine yazar.
fn fixtures() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("geçici dizin oluşturulamadı");
    make_fixtures::write_fixtures(dir.path()).expect("fixture üretilemedi");
    dir
}

fn fixture_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("old.exe"), dir.join("new.exe"))
}

#[tokio::test]
async fn diff_basic() {
    let dir = fixtures();
    let (old_path, new_path) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let old_bin = patchlens.analyze_binary(&old_path).await.unwrap();
    let new_bin = patchlens.analyze_binary(&new_path).await.unwrap();

    let diff = patchlens.diff(&old_bin, &new_bin, DiffConfig::default());

    assert!(!diff.modified.is_empty(), "değişen fonksiyon bulunamadı");
    assert_eq!(diff.old_total, new_bin.functions().len());
    assert_eq!(diff.unchanged.len() + diff.modified.len(), diff.old_total);
}

#[tokio::test]
async fn signature_check() {
    let dir = fixtures();
    let (old_path, new_path) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let old_bin = patchlens.analyze_binary(&old_path).await.unwrap();
    let new_bin = patchlens.analyze_binary(&new_path).await.unwrap();

    let sig_set = SignatureSet {
        signatures: vec![
            Signature {
                name: "func_add_original".to_string(),
                kind: SignatureKind::Aob,
                pattern: Some("55 48 89 E5 B8 1E 00 00 00".to_string()),
                expected_offset: Some(0x1000),
                ..Default::default()
            },
            Signature {
                name: "func_add_wildcard".to_string(),
                kind: SignatureKind::Aob,
                pattern: Some("55 48 89 E5 B8 ?? ?? ?? ??".to_string()),
                expected_offset: Some(0x1000),
                ..Default::default()
            },
        ],
    };

    let old_results = patchlens.check_signatures(&old_bin, &sig_set);
    assert_eq!(old_results[0].status, SignatureStatus::Ok);
    assert_eq!(old_results[1].status, SignatureStatus::Ok);

    let new_results = patchlens.check_signatures(&new_bin, &sig_set);
    assert_eq!(new_results[0].status, SignatureStatus::Broken);
    assert_eq!(new_results[1].status, SignatureStatus::Ok);
}

#[tokio::test]
async fn suggest_signatures() {
    let dir = fixtures();
    let (old_path, new_path) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let old_bin = patchlens.analyze_binary(&old_path).await.unwrap();
    let new_bin = patchlens.analyze_binary(&new_path).await.unwrap();

    let sig_set = SignatureSet {
        signatures: vec![Signature {
            name: "func_add_original".to_string(),
            kind: SignatureKind::Aob,
            pattern: Some("55 48 89 E5 B8 1E 00 00 00".to_string()),
            expected_offset: Some(0x1000),
            ..Default::default()
        }],
    };

    let results = patchlens.check_signatures(&new_bin, &sig_set);
    let broken: Vec<Signature> = results
        .iter()
        .filter(|r| r.status == SignatureStatus::Broken)
        .map(|r| r.signature.clone())
        .collect();

    let suggestions = patchlens.suggest_signatures(&old_bin, &new_bin, &broken);
    assert_eq!(suggestions.len(), 1);
    assert_eq!(suggestions[0].name, "func_add_original_v2");

    // Önerilen imza yeni binary'de tam olarak bir yerde eşleşmeli.
    let check = patchlens.check_signatures(
        &new_bin,
        &SignatureSet {
            signatures: suggestions.clone(),
        },
    );
    assert_eq!(check[0].status, SignatureStatus::Ok);
}

#[tokio::test]
async fn same_binary_diff_is_unchanged() {
    let dir = fixtures();
    let (old_path, _) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let bin = patchlens.analyze_binary(&old_path).await.unwrap();

    let diff = patchlens.diff(&bin, &bin, DiffConfig::default());

    assert_eq!(diff.unchanged.len(), bin.functions().len());
    assert_eq!(diff.modified.len(), 0);
    assert_eq!(diff.added.len(), 0);
    assert_eq!(diff.removed.len(), 0);
}

#[tokio::test]
async fn explain_change_reports_instruction_diff() {
    let dir = fixtures();
    let (old_path, new_path) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let old_bin = patchlens.analyze_binary(&old_path).await.unwrap();
    let new_bin = patchlens.analyze_binary(&new_path).await.unwrap();

    let target = old_bin
        .functions()
        .iter()
        .find(|f| f.address == old_bin.info().image_base + 0x1000)
        .expect("func_add bulunamadı");

    let explanation = patchlens
        .explain_change(&old_bin, &new_bin, target.address, 100, 0)
        .unwrap();

    assert!(explanation.old_function.is_some());
    assert!(explanation.new_function.is_some());
    assert!(!explanation.instruction_changes.is_empty());
}

#[tokio::test]
async fn reports_are_generated() {
    let dir = fixtures();
    let (old_path, new_path) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let old_bin = patchlens.analyze_binary(&old_path).await.unwrap();
    let new_bin = patchlens.analyze_binary(&new_path).await.unwrap();

    let sig_set = SignatureSet {
        signatures: vec![Signature {
            name: "func_add_original".to_string(),
            kind: SignatureKind::Aob,
            pattern: Some("55 48 89 E5 B8 1E 00 00 00".to_string()),
            expected_offset: Some(0x1000),
            ..Default::default()
        }],
    };

    let sarif = patchlens
        .generate_report(
            &old_bin,
            &new_bin,
            Some(&sig_set),
            patchlens_core::ExportFormat::Sarif,
        )
        .unwrap();
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(sarif.contains("signature-broken"));

    let json = patchlens
        .generate_report(
            &old_bin,
            &new_bin,
            Some(&sig_set),
            patchlens_core::ExportFormat::Json,
        )
        .unwrap();
    assert!(json.contains("\"summary\""));

    let header = patchlens
        .export_offsets(
            &old_bin,
            &new_bin,
            &sig_set,
            patchlens_core::ExportFormat::CHeader,
        )
        .unwrap();
    assert!(header.contains("PATCHLENS_OFFSETS_H"));

    let ct = patchlens
        .export_offsets(
            &old_bin,
            &new_bin,
            &sig_set,
            patchlens_core::ExportFormat::CheatEngineCt,
        )
        .unwrap();
    assert!(ct.contains("<CheatTable>"));
}

#[tokio::test]
async fn cache_reuses_analysis() {
    let dir = fixtures();
    let (old_path, _) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let first = patchlens.analyze_binary(&old_path).await.unwrap();
    let second = patchlens.analyze_binary(&old_path).await.unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(patchlens.cache_stats().entries, 1);
}

use std::sync::Arc;

#[tokio::test]
async fn non_pe_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-pe.bin");
    std::fs::write(&path, b"hello world").unwrap();

    let patchlens = Patchlens::new();
    let error = patchlens.analyze_binary(&path).await.unwrap_err();
    let message = format!("{error:#}");

    assert!(
        message.contains("PE x64"),
        "beklenen hata mesajı yok: {message}"
    );
}

#[tokio::test]
async fn binary_info_is_populated() {
    let dir = fixtures();
    let (old_path, _) = fixture_paths(dir.path());

    let patchlens = Patchlens::new();
    let binary = patchlens.analyze_binary(&old_path).await.unwrap();

    assert_eq!(binary.info().function_count, binary.functions().len());
    assert!(binary.info().function_count >= 2);
    assert_eq!(binary.info().architecture, "x64");
    assert!(!binary.info().sections.is_empty());
    assert!(!binary.data().is_empty());
}

#[tokio::test]
async fn diff_summary_insta_snapshot() {
    let dir = fixtures();
    let (old_path, new_path) = fixture_paths(dir.path());
    let patchlens = Patchlens::new();
    let old_bin = patchlens.analyze_binary(&old_path).await.unwrap();
    let new_bin = patchlens.analyze_binary(&new_path).await.unwrap();
    let diff = patchlens.diff(&old_bin, &new_bin, DiffConfig::default());
    insta::assert_snapshot!(
        serde_json::to_string(&patchlens_core::report::summarize_diff(&diff)).unwrap()
    );
}

#[tokio::test]
async fn random_bytes_do_not_panic() {
    let mut data = vec![0u8; 4096];
    let mut state: u64 = 0xdead_beef_cafe_babe;
    for b in &mut data {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = state as u8;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("random.bin");
    std::fs::write(&path, &data).unwrap();
    let patchlens = Patchlens::new();
    // Must not panic: either a valid PE or a NotPe64 error.
    let _ = patchlens.analyze_binary(&path).await;
}

#[tokio::test]
async fn tiny_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.bin");
    std::fs::write(&path, b"MZ").unwrap(); // çok küçük: PE imzası yok
    let patchlens = Patchlens::new();
    let error = patchlens.analyze_binary(&path).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("PE x64"),
        "beklenen hata: {error:#}"
    );
}

#[tokio::test]
async fn corrupt_header_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.bin");
    // MZ + PE imzası var ancak COFF/optional header bozuk: SizeOfOptionalHeader = 0
    let mut data = vec![0u8; 0x80];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data.extend_from_slice(b"PE\0\0");
    data.resize(0x80, 0);
    data[0x44] = 0; // SizeOfOptionalHeader low byte
    data[0x45] = 0; // high byte
    std::fs::write(&path, &data).unwrap();
    let patchlens = Patchlens::new();
    let error = patchlens.analyze_binary(&path).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("PE x64"),
        "beklenen hata: {error:#}"
    );
}

#[tokio::test]
async fn empty_section_binary_is_handled() {
    let dir = fixtures();
    let (old_path, _) = fixture_paths(dir.path());
    let patchlens = Patchlens::new();
    let bin = patchlens.analyze_binary(&old_path).await.unwrap();
    // Boş bölüm içeren dosyanın da panic yapmadan analizi bitmeli.
    assert!(!bin.functions().is_empty());
    assert!(bin.info().function_count == bin.functions().len());
    // Aynı dosya iki kez karşılaştırılırsa hepsi değişmez.
    let diff = patchlens.diff(&bin, &bin, DiffConfig::default());
    assert_eq!(diff.unchanged.len(), bin.functions().len());
    assert_eq!(diff.modified.len(), 0);
    assert_eq!(diff.added.len(), 0);
    assert_eq!(diff.removed.len(), 0);
    assert_eq!(diff.totals.unchanged, bin.functions().len());
}
