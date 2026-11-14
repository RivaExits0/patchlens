//! Fixture üreticisinin CLI karşılığı.

use std::path::PathBuf;

use anyhow::Result;
use make_fixtures::{build_new_pe, build_old_pe, signatures_toml, FIXTURE_DIR};

fn main() -> Result<()> {
    let out_dir = PathBuf::from(FIXTURE_DIR);
    std::fs::create_dir_all(&out_dir)?;

    let old = build_old_pe()?;
    std::fs::write(out_dir.join("old.exe"), &old)?;
    println!("old.exe üretildi ({} byte)", old.len());

    let new = build_new_pe()?;
    std::fs::write(out_dir.join("new.exe"), &new)?;
    println!("new.exe üretildi ({} byte)", new.len());

    std::fs::write(out_dir.join("signatures.toml"), signatures_toml())?;
    println!("signatures.toml üretildi");

    Ok(())
}
