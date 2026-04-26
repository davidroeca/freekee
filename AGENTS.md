# CLAUDE.md

Instructions for Claude Code when working in this repository. Read this file first, then `docs/design.md`, before doing anything.

## Project: freekee

A cross-platform password manager that speaks **standard KDBX4** — full read/write compatibility with KeePassXC, Strongbox, KeePassDX, and every other KeePass client. The added value is in tooling, not file format: ergonomic CLI, first-class key/credential rotation, and a post-quantum-aware audit feature that helps users stay on safe symmetric configurations.

The primary author syncs a `.kdbx` between Linux (KeePassXC) and iOS (Strongbox) via Dropbox. Every design decision must preserve that workflow. **A file written by freekee must open cleanly in KeePassXC 2.7+.** No exceptions.

## Why no custom envelope format

Quantum computers threaten asymmetric crypto (Shor's algorithm) far more than symmetric crypto (Grover gives only a quadratic speedup). KDBX4 with AES-256 or ChaCha20 + Argon2id is already considered post-quantum-secure at rest. Wrapping the file in a custom PQ envelope would solve a problem that doesn't really exist while breaking compatibility with every other KeePass client. The valuable PQ-related work is *audit*: making sure users are actually on the safe configurations.

## Non-negotiable rules

**TDD is mandatory.** No production code is written without a failing test first. The loop is:

1. Write a failing test that captures the next behavior. Commit (`test: ...`).
2. Implement the minimum code to pass. Commit (`feat: ...` or `fix: ...`).
3. Refactor if needed, tests still green. Commit (`refactor: ...`).

If you find yourself writing implementation code without a failing test on disk, stop and write the test first. Crypto-adjacent code (KDF parameter changes, cipher selection logic, audit checks) especially.

**Never write or modify cryptographic primitives.** We use audited crates only — primarily whatever `keepass-rs` already pulls in (AES, ChaCha20, Argon2, HMAC). If a task seems to require touching primitive crypto directly, stop and ask the human.

**Never log, print, or include in error messages:** plaintext passwords, master passphrases, derived keys, keyfile contents, or decrypted entry values. Error types must not embed secret material. Use `zeroize` for in-memory secrets where the underlying types support it. There is a meta-test that runs the CLI with a known plaintext, captures all stdout/stderr, and grep's for the plaintext — keep it green.

**KDBX round-trip must be lossless.** Any database written by KeePassXC 2.7+ must round-trip through our code such that re-opening it in KeePassXC shows no data loss. The fixture suite in `tests/roundtrip/` is the source of truth. Adding a feature that breaks a fixture is a regression.

**Keep the audit recommendations conservative.** When the audit feature flags something as "weak" or "post-quantum-risky," it must cite a specific source (NIST publication, KeePass docs, OWASP guidance). Don't editorialize.

## Architecture

Monorepo Cargo workspace. See `docs/design.md` for full crate responsibilities. Quick map:

- `crates/kdbx/` — wraps `keepass-rs` behind a stable trait; isolates upstream churn
- `crates/audit/` — pure analysis: takes a parsed database, returns findings
- `crates/core/` — orchestrator: `Vault::open`, `vault.save`, rotation operations, audit invocation
- `crates/cli/` — `freekee` binary, clap-based, no business logic
- `crates/tauri-bridge/` — `#[tauri::command]` handlers returning DTOs
- `app/src-tauri/` — single Tauri 2 project, emits desktop + mobile
- `plugins/tauri-plugin-keychain/` — iOS Keychain / Android Keystore

Crate boundaries are enforced. The frontend never sees `core` types directly — only DTOs from `tauri-bridge`. The CLI never imports `keepass-rs` directly — only `core`. If you need to bypass a boundary, that's a design discussion, not a code change.

## JS/TS toolchain: Bun

We use **Bun** as the package manager and runtime, not npm/pnpm/yarn. Tauri 2 supports any JS package manager that produces a working `node_modules`.

```bash
bun install              # not npm install
bun run dev
bun add <pkg>
bun add -d <pkg>
bun pm ls
```

The lockfile is `bun.lock`. Commit it. CI uses `bun install --frozen-lockfile`. Do not introduce a `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` — pick one tool, stay on it.

If a Tauri plugin's docs assume npm, the equivalent Bun invocation is almost always a direct substitution; only flag a divergence if Bun actually fails.

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

# Tauri (iOS — requires macOS + Xcode)
cd app && bun run tauri ios dev
```

## Workflow conventions

- Branch per feature. Conventional Commits. Squash-merge with a meaningful summary.
- Every PR: tests added/updated, `docs/` updated if behavior changed, audit checks updated if a new weak configuration is identified upstream.
- Crypto-touching or audit-rule PRs are flagged `security-review` and require explicit human sign-off.
- Crypto-related crates pin exact versions (`=0.x.y`). Other deps may use caret. New deps need justification in the PR description.
- `unsafe` is forbidden in `crates/audit/` and `crates/core/`. Allowed elsewhere only with a `// SAFETY:` comment.
- Order by cost: when a function tries multiple strategies, put the cheapest one first (e.g., check a known path before scanning a directory).
- Avoid needless allocations: prefer borrowing (`&str`, `&Value`) over `.to_string()` / `.cloned()` when the owned value isn't needed.
- Avoid `.unwrap()` in production code: use `?`, `.expect("reason")`, or combinators (`.unwrap_or`, `.map`). `.unwrap()` is acceptable in `#[test]` functions and `#[cfg(test)]` modules. Also enforced as a `clippy.toml` `disallowed-methods` rule.

## Things to ask the human before doing

- Adding a new audit rule (especially anything claiming "post-quantum risk")
- Bumping `keepass-rs` or any pinned crypto crate to a new minor/major
- Modifying anything that changes how a file is *written* (vs. read)
- Adding a new platform target
- Anything that touches sync semantics (file locking, conflict detection, merge logic)

## What good looks like

- Unit tests run in under 30 seconds
- `tests/roundtrip/fixtures/` covers every KeePassXC 2.7+ feature: groups, entries, history, attachments, custom icons, custom data, auto-type, expiry, tags, deleted-objects
- A KDBX file written by `freekee` opens in KeePassXC with zero warnings and zero data loss
- `freekee audit` produces actionable output — every finding has a remediation command
- `cargo doc --workspace --no-deps` produces clean docs
- A new contributor can clone, `cargo test`, and have a green build in under five minutes

When in doubt: write the test, ask the human, prefer compatibility over cleverness.
