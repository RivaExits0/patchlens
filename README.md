# Patchlens

[![CI](https://github.com/RivaExits0/patchlens/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/patchlens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-blue.svg)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-orange)](https://modelcontextprotocol.io/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

**Patchlens** is a static binary diff and signature analysis tool for reverse engineering. It compares two PE64 (x64) builds and tells you exactly what changed at the function level — with confidence scores, signature verification (`ok` / `moved` / `broken` / `ambiguous`), and automated signature migration. It ships both a **CLI** and an **MCP server** (5 tools over stdio) for use from Claude Desktop or any MCP client.

> **Turkish / Türkçe:** Patchlens, iki PE64 (x64) binary build'ini statik olarak karşılaştırıp fonksiyon düzeyinde neyin değiştiğini söyler. Güven skorları, imza doğrulaması (`ok` / `moved` / `broken` / `ambiguous`) ve otomatik imza göçü (migration) sunar. CLI ve MCP sunucusu (5 stdio aracı) içerir; Claude Desktop veya herhangi bir MCP istemcisiyle kullanılabilir.

---

## 🎯 What can it do?

| Domain | Key Operations |
|--------|----------------|
| **Binary Diffing** | Function-level staged matching: exact hash → string/import similarity → call graph propagation → fuzzy opcode similarity |
| **Signature Engine** | AOB (wildcard) and export-name signatures; status: `ok` / `moved` / `broken` / `ambiguous` |
| **Auto Migration** | For broken signatures, finds the matching function in the new build and generates a resilient wildcard signature that survives recompilation |
| **Change Explanation** | Line-by-line disassembly diff with pagination; structured JSON output for MCP/LLM consumption |
| **CI Reports** | SARIF 2.1.0 (GitHub Actions), JSON, C header (`#define`), Cheat Engine `.CT` |
| **MCP Server** | 5 tools via stdio: `diff_builds`, `check_signatures`, `explain_change`, `export_offsets`, `ci_report` |
| **Safety** | Static analysis only — binaries are never executed; read-only file access via `mmap` |

---

## 🚀 Quick Start

### 1. Install

#### From crates.io (when published)
```bash
cargo install patchlens
cargo install patchlens-mcp   # MCP server for Claude Desktop
```

#### From GitHub
```bash
git clone https://github.com/RivaExits0/patchlens.git
cd patchlens

# CLI
cargo install --path crates/patchlens-cli

# MCP server (stdio)
cargo install --path crates/patchlens-mcp
```

#### From source (development)
```bash
cargo build --workspace
cargo test --workspace
cargo run --bin make_fixtures   # generate synthetic PE64 test fixtures
```

### 2. External Dependencies (Optional)
| Tool | Purpose |
|------|---------|
| `clang`/`MSVC` | Only for building test fixtures |

---

## 🔧 CLI Usage

```bash
# Diff two builds (text output)
patchlens diff old.exe new.exe --format text

# Diff as JSON with pagination
patchlens diff old.exe new.exe --format json --min-score 0.8 --limit 50 --offset 0

# Check signatures against new build; auto-suggest replacements for broken ones
patchlens sigs old.exe new.exe --signatures sigs.toml --suggest --sarif broken.sarif

# Explain a specific function change (hex address or name)
patchlens explain old.exe new.exe --function 0x140001000 --limit 200

# Export offsets for modders (C header, Cheat Engine .CT, JSON, SARIF)
patchlens export old.exe new.exe --signatures sigs.toml --format header --out offsets.h
```

### Exit Codes
| Code | Meaning |
|------|---------|
| `0` | Success, no broken signatures |
| `1` | Broken signatures found (CI-friendly) |
| `2` | Usage / I/O error |

---

## 📝 Signature Format (TOML)

```toml
[[signatures]]
name = "player_health_get"
kind = "Aob"
pattern = "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 40 10"
expected_offset = 0x3A20
description = "Player health getter"

[[signatures]]
name = "player_health_get_v2"
kind = "Aob"
pattern = "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 40 10"
expected_offset = 0x3A20
description = "Wildcard version for migration"
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | ✅ | Unique identifier |
| `kind` | ✅ | `Aob` or `ExportName` |
| `pattern` | For `Aob` | Wildcard pattern (`??` for wildcards) |
| `function_name` | For `ExportName` | Exact export name |
| `expected_offset` | Optional | Expected RVA in old build |
| `description` | Optional | Human-readable description |

---

## 🔌 MCP Integration (Claude Desktop)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "patchlens": {
      "command": "patchlens-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

> **Windows:** If installed via cargo, `patchlens-mcp` should be on PATH. Otherwise use full path: `C:\\path\\to\\patchlens-mcp.exe`.

### OpenCode Integration

Add to `opencode.json`:

```json
{
  "mcp": {
    "patchlens": {
      "type": "local",
      "command": ["patchlens-mcp"],
      "enabled": true
    }
  }
}
```

---

## 🛠 Available MCP Tools

| Tool | Description | Example |
|------|-------------|---------|
| `diff_builds` | Diff two PE64 builds; pagination default 50 / max 500 | `{"old_path": "old.exe", "new_path": "new.exe", "min_score": 0.8}` |
| `check_signatures` | Verify signatures; `suggest: true` auto-migrates broken ones | `{"old_path": "old.exe", "new_path": "new.exe", "signatures": [...], "suggest": true}` |
| `explain_change` | Explain a function's disassembly diff | `{"old_path": "old.exe", "new_path": "new.exe", "function": "0x140001000"}` |
| `export_offsets` | Export offsets as header / .CT / JSON / SARIF | `{"old_path": "old.exe", "new_path": "new.exe", "format": "header"}` |
| `ci_report` | Generate CI report (SARIF 2.1.0 or JSON) | `{"old_path": "old.exe", "new_path": "new.exe", "format": "sarif"}` |

---

## 📖 Example Workflow

> **Goal:** "My AOB signature broke after the game updated. Find the new function address and generate a replacement signature."

```bash
# 1. Diff the two builds
patchlens diff game_v1.exe game_v2.exe --format json --out diff.json

# 2. Check which signatures broke
patchlens sigs game_v1.exe game_v2.exe --signatures sigs.toml --suggest --sarif report.sarif

# 3. Inspect the changed function in detail
patchlens explain game_v1.exe game_v2.exe --function sub_140003A20 --limit 200

# 4. Export the new offset for your mod
patchlens export game_v1.exe game_v2.exe --signatures sigs.toml --format header --out offsets.h
```

---

## 🔄 CI Integration (GitHub Actions)

```yaml
- name: Check signatures
  run: |
    patchlens sigs old.exe new.exe --signatures sigs.toml --sarif report.sarif
    exit_code=$?
    if [ $exit_code -eq 1 ]; then
      echo "::warning::Broken signatures detected"
    fi

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

The SARIF report includes:
- `function-modified` (warning)
- `function-removed` (error)
- `function-added` (note)
- `signature-broken` (error)

---

## 📊 Output Formats

| Format | Use Case |
|--------|----------|
| **SARIF 2.1.0** | GitHub Actions, VS Code, static analysis tools |
| **JSON** | Programmatic consumption, custom tooling |
| **C Header** | Mod SDKs, `#define FUNC_HEALTH_GET 0x140003A20` |
| **Cheat Engine .CT** | Modders, trainer authors |

---

## 🖥 Platform Support

| Platform | PE64 (x64) | CLI | MCP | Notes |
|----------|------------|-----|-----|-------|
| Linux    | ✅ Full    | ✅  | ✅  | Tested in CI |
| Windows  | ✅ Full    | ✅  | ✅  | Tested in CI (windows-latest) |
| macOS    | ✅ Full    | ✅  | ✅  | Rust toolchain required |

Patchlens analyzes **PE32+ (x64)** files on any platform. PE32 (x86) is intentionally rejected with an actionable error: `"Dosya PE değil. Desteklenen: PE x64"`.

---

## 📈 Benchmarks

Measured with `cargo bench -p patchlens-core` on the synthetic fixture (~1 KB, 2 functions):

| Operation | Time |
|-----------|------|
| Analyze (load + PE parse + extract) | ~457 µs per file |
| Diff (staged, 2 functions) | ~2.05 µs |
| Signature check (default set) | ~767 ns |
| Suggestion generation (1 broken sig) | see `cargo bench` output |

*Measured on fixtures only; real-world numbers coming.*

### Real-world measurement (jq, Windows x64)

Compared `jq 1.6` (`jq-win64.exe`, 3.4 MB) against `jq 1.7.1`
(`jq-windows-amd64.exe`, 0.94 MB) with `patchlens diff ... --format json`:

| Metric | Value |
|--------|-------|
| Old functions | 1023 |
| New functions | 1327 |
| Unchanged | 0 |
| Modified | 1 |
| Removed | 1022 |
| Added | 1326 |
| Wall-clock time (debug build) | 5 min 21 s |

The two releases share almost no matching functions, which is expected for
a major version jump (different compiler/optimisation settings). This is a
stress test of the parser and differ, not a like-for-like rebuild.

---

## 🎬 Demo

<!-- GIF goes here -->

See `docs/demo-script.md` for a step-by-step walkthrough: a signature breaks, `--suggest` finds the new one, and verification passes.

---

## 🛡 Safety & Ethics

This tool is designed for **single-player modding, security research, and owned binaries only**. The following principles are enforced by design:

- **Static analysis only** — Binaries are **never executed**.
- **Read-only access** — Files are opened read-only via `mmap`; originals are never modified.
- **No network access** — The CLI and MCP server only read the paths you pass; nothing is uploaded.
- **Memory-safe parsing** — Bounds-checked PE parsing, no `unwrap()` in library code paths; fuzz-style random-byte tests run in normal `cargo test`.
- **No anti-cheat/DRM bypass** — Designed for single-player modding, security research, and owned binaries only.

> **Legal:** Only use on binaries you own or have explicit permission to analyze. Check your local laws and the software's EULA.

---

## 🔍 Fuzzing

Fuzz the PE parser with cargo-fuzz (nightly toolchain):

```sh
cargo +nightly fuzz run fuzz_pe_parse
```

The fuzz target lives in `fuzz/fuzz_targets/fuzz_pe_parse.rs` and feeds arbitrary bytes to `Binary::from_bytes`. CI does not run it; run it locally.

## 🧪 Testing

Run the full suite:

```sh
cargo test --workspace --all-targets
```

Real-binary smoke test (ignored by default). Set `PATCHLENS_OLD` and `PATCHLENS_NEW` to two real PE64 executables:

```sh
PATCHLENS_OLD=/path/to/old.exe PATCHLENS_NEW=/path/to/new.exe \
  cargo test --package patchlens-core --test integration_test real_pe_diff -- --ignored
```

---

## 🏗 Architecture

```
patchlens/
├── crates/
│   ├── patchlens-core/     # Binary loading, function extraction, diffing, signatures, reports, cache
│   ├── patchlens-cli/      # CLI entry point (clap): diff / sigs / explain / export
│   ├── patchlens-mcp/      # MCP server (rmcp, stdio): 5 tools
├── tools/make_fixtures/    # Synthetic PE64 fixture generator (lib + bin)
├── .github/workflows/ci.yml # CI: fmt --check, clippy -D warnings, build, test (ubuntu + windows + macos)
└── README.md
```

---

## 📚 Related Projects

| Project | Description |
|---------|-------------|
| **forge-mcp** | Game modding toolkit (hex, PE, APK, Unity, Unreal, tables) |
| **emu-mcp** | Isolated function emulation with Unicorn |
| **crash-mcp** | Crash dump analysis (ELF core + Windows minidump) |
| **henry-mcp** | Static compatibility analysis (EXE/DLL/APK/Kotlin) |

---

## 📄 License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo test`, `cargo fmt --check`, `cargo clippy -- -D warnings` pass
5. Open a PR

---

## 🔗 Links

- **Repository**: https://github.com/RivaExits0/patchlens
- **Issues**: https://github.com/RivaExits0/patchlens/issues
- **MCP Spec**: https://modelcontextprotocol.io/
- **SARIF Spec**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
