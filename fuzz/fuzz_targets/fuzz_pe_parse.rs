#![no_main]

use libfuzzer_sys::fuzz_target;
use patchlens_core::Binary;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes to the PE parser; it must never panic.
    let _ = Binary::from_bytes(PathBuf::from("fuzz.exe"), data.to_vec());
});
