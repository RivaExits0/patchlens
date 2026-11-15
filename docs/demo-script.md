# Patchlens Demo Script

Step-by-step flow for the demo GIF. Run from the repository root after
building the fixtures.

## Setup

```sh
cargo run --bin make_fixtures
```

This writes `tests/fixtures/old.exe`, `tests/fixtures/new.exe`, and
`tests/fixtures/signatures.toml`.

## 1. Diff the two builds

```sh
patchlens diff tests/fixtures/old.exe tests/fixtures/new.exe --format text
```

Expected: one modified function (`func_add`), one unchanged (`func_sub`).

## 2. Check signatures (one breaks)

```sh
patchlens sigs tests/fixtures/old.exe tests/fixtures/new.exe \
  --signatures tests/fixtures/signatures.toml
```

Expected: `func_add` is reported as `broken` because its immediate changed
from `0x1E` to `0x2A`.

## 3. Suggest a replacement signature

```sh
patchlens sigs tests/fixtures/old.exe tests/fixtures/new.exe \
  --signatures tests/fixtures/signatures.toml --suggest
```

Expected: a new AOB pattern for `func_add` with the updated immediate.

## 4. Verify the suggested signature

```sh
patchlens sigs tests/fixtures/old.exe tests/fixtures/new.exe \
  --signatures tests/fixtures/signatures.toml --suggest --format sarif
```

The suggested signature resolves to `ok` on the new build.

## 5. Explain the change

```sh
patchlens explain tests/fixtures/old.exe tests/fixtures/new.exe \
  --function 0x140001000
```

Shows the instruction-level diff (`mov eax, 30` -> `mov eax, 42`).
