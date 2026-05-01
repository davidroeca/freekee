# AGENTS.md

Instructions for coding agents. Consult `docs/design.md` before making architectural decisions or adding audit rules.

## Non-negotiable rules

**TDD is mandatory.** No production code without a failing test first:

1. Write a failing test. Commit (`test: ...`).
2. Implement the minimum code to pass. Commit (`feat: ...` or `fix: ...`).
3. Refactor if needed, tests still green. Commit (`refactor: ...`).

Crypto-adjacent code (KDF parameter changes, cipher selection, audit checks) especially.

**Never write or modify cryptographic primitives.** Use audited crates only, primarily whatever `keepass-rs` already pulls in (AES, ChaCha20, Argon2, HMAC). If a task seems to require touching primitive crypto directly, stop and ask the human.

**Never log, print, or include in error messages:** plaintext passwords, master passphrases, derived keys, keyfile contents, or decrypted entry values. Error types must not embed secret material. Use `zeroize` for in-memory secrets where the underlying types support it. A meta-test runs the CLI with a known plaintext and greps stdout/stderr for it; keep it green.

**KDBX round-trip must be lossless.** Any database written by KeePassXC 2.7+ must round-trip through our code such that re-opening it in KeePassXC shows no data loss. The fixture suite in `tests/roundtrip/` is the source of truth. Breaking a fixture is a regression.

**Audit recommendations stay conservative.** When the audit feature flags something as "weak" or "post-quantum-risky," it must cite a specific source (NIST publication, KeePass docs, OWASP guidance). Don't editorialize.

## Architecture

Monorepo Cargo workspace. See `docs/design.md` for full crate responsibilities.

- `crates/kdbx/` - wraps `keepass-rs` behind a stable trait
- `crates/audit/` - pure analysis: takes a parsed database, returns findings
- `crates/core/` - orchestrator: `Vault::open`, `vault.save`, rotation, audit invocation
- `crates/cli/` - `freekee` binary, clap-based, no business logic
- `crates/tauri-bridge/` - `#[tauri::command]` handlers returning DTOs
- `app/src-tauri/` - single Tauri 2 project, emits desktop + mobile
- `plugins/tauri-plugin-keychain/` - iOS Keychain / Android Keystore

Crate boundaries are enforced: the frontend never sees `core` types directly (only DTOs from `tauri-bridge`); the CLI never imports `keepass-rs` directly (only `core`). Bypassing a boundary is a design discussion, not a code change.

## JS/TS toolchain

Use **Bun**, not npm/pnpm/yarn. Lockfile is `bun.lock`; commit it. CI uses `bun install --frozen-lockfile`. Do not introduce a `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`.

## Commands

```bash
# Test
cargo test --workspace
cargo test -p kdbx --test roundtrip     # KeePassXC compatibility fixtures
cargo test -p audit                      # audit findings logic

# Lint
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

# Security
cargo audit
cargo deny check

# CLI dev
cargo run -p cli -- --help
cargo run -p cli -- audit path/to/db.kdbx

# Tauri (desktop)
cd app && bun run tauri dev

# Tauri (iOS - requires macOS + Xcode)
cd app && bun run tauri ios dev
```

## Workflow conventions

- Branch per feature. Conventional Commits. Squash-merge with a meaningful summary.
- **Before every commit**: run `cargo fmt`, then `cargo fmt --check`. CI gates on `--check`.
- Every PR: tests added/updated, `docs/` updated if behavior changed, audit checks updated if a new weak configuration is identified upstream.
- Crypto-touching or audit-rule PRs are flagged `security-review` and require explicit human sign-off.
- Crypto-related crates pin exact versions (`=0.x.y`). Other deps may use caret. New deps need justification in the PR description.
- `unsafe` is forbidden in `crates/audit/` and `crates/core/`. Allowed elsewhere only with a `// SAFETY:` comment.
- Order by cost: when a function tries multiple strategies, put the cheapest first (e.g., check a known path before scanning a directory).
- Avoid needless allocations: prefer borrowing (`&str`, `&Value`) over `.to_string()` / `.cloned()` when the owned value isn't needed.
- Avoid `.unwrap()` in production code: use `?`, `.expect("reason")`, or combinators. `.unwrap()` is acceptable in `#[test]` and `#[cfg(test)]`. Enforced via `clippy.toml` `disallowed-methods`.

## Ask the human before

- Adding a new audit rule (especially anything claiming "post-quantum risk")
- Bumping `keepass-rs` or any pinned crypto crate to a new minor/major
- Modifying anything that changes how a file is _written_ (vs. read)
- Adding a new platform target
- Anything that touches sync semantics (file locking, conflict detection, merge logic)

When in doubt: write the test, ask the human, prefer compatibility over cleverness.
