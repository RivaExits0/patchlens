# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-14

### Added
- Initial release of Patchlens
- Binary diffing with staged matching (exact → string/import → call graph → fuzzy)
- AOB and export-name signature engine with status reporting
- Automatic signature migration for broken signatures
- Line-by-line disassembly diff with pagination
- CI reports: SARIF 2.1.0, JSON, C header, Cheat Engine .CT
- MCP server with 5 tools via stdio transport
- PE32+ (x64) support with mmap-based loading
- Cross-platform: Linux, Windows, macOS
- Comprehensive test suite with synthetic PE fixtures
- Benchmark suite with Criterion

### Security
- Static analysis only (no binary execution)
- Read-only mmap access
- Path traversal protection
- No anti-cheat/DRM bypass features

[0.1.0]: https://github.com/RivaExits0/patchlens/releases/tag/v0.1.0