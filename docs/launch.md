# Launch drafts

## (a) awesome-mcp-servers list entry

- **Patchlens** — Static PE64 binary diff and AOB signature analysis MCP server (Rust). Tools: `diff_builds`, `check_signatures`, `explain_change`, `ci_report`, `export_offsets`. https://github.com/RivaExits0/patchlens

PR description: Adds Patchlens, a read-only static analysis MCP server for
comparing two PE64 builds at the function level, verifying/migrating AOB
signatures, and emitting SARIF/JSON/C-header/Cheat Engine reports.

## (b) r/ReverseEngineering post

Title: Patchlens — static diff of two PE64 builds (function-level) + AOB signature migration

Body: I built a small Rust CLI/MCP server that statically compares two PE64
builds and reports changed/added/removed functions with confidence scores,
verifies AOB signatures (ok/moved/broken/ambiguous), and can suggest a
replacement signature for broken ones. It also emits SARIF/JSON/C header/CT
reports and runs entirely read-only (no execution of the target).

Measured on a real pair (jq 1.6 vs 1.7.1, Windows x64): 1023 vs 1327
functions, 0 unchanged / 1 modified / 1022 removed / 1326 added; wall-clock
5 min 21 s (debug build) on the differ. The low match rate is expected for
a major version jump.

Repo: https://github.com/RivaExits0/patchlens

## (c) X/Twitter

Patchlens: static diff of two PE64 builds at function level + AOB signature
migration (ok/moved/broken/ambiguous). CLI + MCP server (5 tools), SARIF/JSON/
C header/CT output, read-only. Measured on jq 1.6→1.7.1 (1023 vs 1327 funcs,
5m21s debug). https://github.com/RivaExits0/patchlens
