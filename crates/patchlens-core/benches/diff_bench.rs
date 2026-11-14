//! Patchlens performans ölçümleri (criterion).

use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use patchlens_core::{DiffConfig, Patchlens, Signature, SignatureKind, SignatureSet};

fn fixture_binaries() -> (PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("geçici dizin oluşturulamadı");
    make_fixtures::write_fixtures(dir.path()).expect("fixture üretilemedi");
    let old = dir.path().join("old.exe");
    let new = dir.path().join("new.exe");
    // Dizin test süresince yaşamalı; path'i saklayıp belleği leak ediyoruz.
    std::mem::forget(dir);
    (old, new)
}

fn bench_diff(c: &mut Criterion) {
    let (old_path, new_path) = fixture_binaries();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let patchlens = Patchlens::new();

    let old_bin = runtime
        .block_on(patchlens.analyze_binary(&old_path))
        .unwrap();
    let new_bin = runtime
        .block_on(patchlens.analyze_binary(&new_path))
        .unwrap();

    c.bench_function("diff_binaries", |b| {
        b.iter(|| {
            let diff = patchlens.diff(
                black_box(&old_bin),
                black_box(&new_bin),
                DiffConfig::default(),
            );
            black_box(diff);
        });
    });
}

fn bench_signature_check(c: &mut Criterion) {
    let (_, new_path) = fixture_binaries();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let patchlens = Patchlens::new();
    let new_bin = runtime
        .block_on(patchlens.analyze_binary(&new_path))
        .unwrap();

    let sig_set = SignatureSet {
        signatures: vec![Signature {
            name: "test".to_string(),
            kind: SignatureKind::Aob,
            pattern: Some("55 48 89 E5 B8 ?? ?? ?? ??".to_string()),
            ..Default::default()
        }],
    };

    c.bench_function("check_signatures", |b| {
        b.iter(|| {
            let results = patchlens.check_signatures(black_box(&new_bin), black_box(&sig_set));
            black_box(results);
        });
    });
}

fn bench_fingerprint(c: &mut Criterion) {
    let (old_path, _) = fixture_binaries();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let patchlens = Patchlens::new();
    let old_bin = runtime
        .block_on(patchlens.analyze_binary(&old_path))
        .unwrap();

    c.bench_function("generate_fingerprints", |b| {
        b.iter(|| {
            for func in black_box(old_bin.functions()) {
                black_box(patchlens_core::generate_fingerprint(func));
            }
        });
    });
}

fn bench_analysis(c: &mut Criterion) {
    let (old_path, _) = fixture_binaries();
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("analyze_binary", |b| {
        b.iter(|| {
            let patchlens = Patchlens::new();
            let binary = runtime
                .block_on(patchlens.analyze_binary(black_box(&old_path)))
                .unwrap();
            black_box(binary.functions().len());
        });
    });
}

criterion_group!(
    benches,
    bench_diff,
    bench_signature_check,
    bench_fingerprint,
    bench_analysis
);
criterion_main!(benches);
