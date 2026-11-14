# Patchlens

[![CI](https://github.com/RivaExits0/patchlens/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/patchlens/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org/)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-orange)](https://modelcontextprotocol.io/)

**Patchlens** is a binary diffing and signature analysis tool for reverse engineering. It compares two builds of a binary (old vs new) and tells you exactly what changed at the function level — with confidence scores, signature verification, and automated signature migration.

> **Problem**: When a game or application updates, modders and security researchers need to know: Which AOB signatures broke? Which functions changed? Which offsets moved? Patchlens answers these questions automatically.

---

## Features

| Feature | Description |
|---------|-------------|
| **Binary Diffing** | Function-level diff with staged matching: exact hash → string/import similarity → call graph propagation → fuzzy opcode similarity |
| **Signature Engine** | AOB (wildcard) and export-name signatures; status: `ok` / `moved` / `broken` / `ambiguous` |
| **Auto Migration** | For broken signatures, finds the corresponding function in the new build and generates a resilient wildcard signature that survives recompilation |
| **Change Explanation** | Line-by-line disassembly diff with pagination; outputs structured JSON for MCP/LLM consumption |
| **CI Reports** | SARIF 2.1.0 (GitHub Actions), JSON, C header (`#define`), Cheat Engine `.CT` |
| **MCP Server** | 5 tools via stdio: `diff_builds`, `check_signatures`, `explain_change`, `export_offsets`, `ci_report` |
| **Cross-platform** | PE32+ (x64) on Linux/Windows/macOS; no binary execution |

---

## Quick Start

### Installation

```bash
# From crates.io (when published)
cargo install patchlens

# From source
git clone https://github.com/RivaExits0/patchlens.git
cd patchlens
cargo install --path crates/patchlens-cli
```

### External Dependencies (Optional)
| Tool | Purpose |
|------|---------|
| `gdb` | Not used (static analysis only) |
| `clang`/`MSVC` | Only for building test fixtures |

---

## CLI Usage

```bash
# Diff two builds
patchlens diff old.exe new.exe --format json --min-score 0.8 --limit 50

# Check signatures against new build
patchlens sigs old.exe new.exe --signatures sigs.toml --suggest --sarif broken.sarif

# Explain a specific function change
patchlens explain old.exe new.exe --function 0x140001000 --limit 200

# Export offsets for modders
patchlens export old.exe new.exe --signatures sigs.toml --format header --out offsets.h
```

### Exit Codes
| Code | Meaning |
|------|---------|
| `0` | Success, no broken signatures |
| `1` | Broken signatures found (CI-friendly) |
| `2` | Usage / I/O error |

---

## Signature Format (TOML)

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

## MCP Integration (Claude Desktop)

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

### Available MCP Tools

| Tool | Description | Example |
|------|-------------|---------|
| `diff_builds` | Diff two builds | `{"old_path": "old.exe", "new_path": "new.exe", "min_score": 0.8}` |
| `check_signatures` | Verify signatures | `{"old_path": "old.exe", "new_path": "new.exe", "signatures": [...], "suggest": true}` |
| `explain_change` | Explain function diff | `{"old_path": "old.exe", "new_path": "new.exe", "function": "0x140001000"}` |
| `export_offsets` | Export offsets | `{"old_path": "old.exe", "new_path": "new.exe", "signatures": [...], "format": "header"}` |
| `ci_report` | Generate CI report | `{"old_path": "old.exe", "new_path": "new.exe", "format": "sarif"}` |

---

## CI Integration (GitHub Actions)

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

## Output Formats

| Format | Use Case |
|--------|----------|
| **SARIF 2.1.0** | GitHub Actions, VS Code, static analysis tools |
| **JSON** | Programmatic consumption, custom tooling |
| **C Header** | Mod SDKs, `#define FUNC_HEALTH_GET 0x140003A20` |
| **Cheat Engine .CT** | Modders, trainer authors |

---

## Performance

| Binary Size | Functions | Time (12-core) | Memory | Notlar |
|-------------|-----------|----------------|--------|--------|
| ~1 KB | 2 | ~70 µs | <10 MB | Sentetik test fixture (ölçülmüş) |
| 10 MB | ~2,000 | ~2s (est.) | ~150 MB | Tahmin; gerçek yükle ölçülmeli |
| 100 MB | ~20,000 | ~15s (est.) | ~500 MB | Tahmin; gerçek yükle ölçülmeli |
| 300 MB | ~60,000 | ~45s (est.) | ~1.2 GB | Tahmin; gerçek yükle ölçülmeli |

*Uses `mmap` + `rayon` for parallel processing; memory scales with section data, not full file. "(est.)" işaretli satırlar daha büyük PE dosyaları için estimated değerlerdir.*

---

## Architecture

```
patchlens/
├── crates/
│   ├── patchlens-core/     # Binary loading, function extraction, diffing, signatures
│   ├── patchlens-cli/      # CLI entry point (clap)
│   ├── patchlens-mcp/      # MCP server (rmcp, stdio)
│   └── patchlens-report/   # SARIF, JSON, C header, .CT export
├── tests/fixtures/         # Synthetic PE test files
├── tools/make_fixtures/    # Fixture generator
└── benches/                # Criterion benchmarks
```

---

## Safety & Ethics

- **Static analysis only** — binaries are never executed
- **Read-only access** — files opened read-only via `mmap`
- **Path traversal blocked** — paths normalized, only user-provided files accessed
- **No anti-cheat/DRM bypass** — designed for single-player modding, security research, and owned binaries only
- **Fuzz tested** — `cargo-fuzz` targets for PE parsing

> **Legal**: Only use on binaries you own or have explicit permission to analyze. Check your local laws and the software's EULA.

---

## Development

```bash
# Setup
cargo build --workspace
cargo test --workspace
cargo run --bin make_fixtures  # Generate test fixtures

# Benchmarks
cargo bench --workspace

# Linting
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Release

```bash
git tag -a v0.1.0 -m "patchlens v0.1.0"
git push origin v0.1.0
# GitHub Actions creates release with binaries
```

---

## Benchmarks

Run locally:

```bash
cargo bench --workspace
```

| Operation | Time (synthetic ~1 KB fixture) |
|-----------|-------------------------------|
| Analyze (load + PE parse + extract) | ~0.07 ms (old), ~0.07 ms (new) |
| Diff (staged, 2 functions) | ~61 µs |
| Signature check (default set) | ~724 µs |
| Suggestion generation (1 broken sig) | ~92 µs |

*Ölçümler `cargo run --example bench_quick -p patchlens-core` ile alındı. Gerçek 10 MB+ PE dosyaları için süreler daha uzun olacaktır.*

---

## Related Projects

| Project | Description |
|---------|-------------|
| **forge-mcp** | Game modding toolkit (hex, PE, APK, Unity, Unreal, tables) |
| **emu-mcp** | Isolated function emulation with Unicorn |
| **crash-mcp** | Crash dump analysis (ELF core + Windows minidump) |
| **henry-mcp** | Static compatibility analysis (EXE/DLL/APK/Kotlin) |

---

## License

MIT — see [LICENSE](LICENSE). Free for personal and commercial use.

---

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo test`, `cargo fmt`, `cargo clippy` pass
5. Open a PR

---

## Links

- **Repository**: https://github.com/RivaExits0/patchlens
- **Issues**: https://github.com/RivaExits0/patchlens/issues
- **MCP Spec**: https://modelcontextprotocol.io/
- **SARIF Spec**: https://docs.oasis-open.org/sarif/sarif/v2.1.0/