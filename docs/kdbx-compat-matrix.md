# KDBX Compatibility Matrix

What `freekee` does and does not preserve when round-tripping a KeePassXC-generated KDBX file. Updated per release.

The source of truth is `tests/roundtrip/fixtures/`. Every entry below maps to one fixture directory there.

Read = the fixture parses without error.
Round-trip = `read → write → read` is structurally equivalent (see `crates/kdbx/tests/common/mod.rs::assert_self_roundtrip`).
Verify = a file we wrote can be re-opened by `keepassxc-cli` (gated on the `keepassxc-verify` feature; lands with milestone-0 task #1).

| Fixture | KDBX | Cipher | KDF | Read | Round-trip | Verify | Notes |
|---|---|---|---|---|---|---|---|
| `empty` | 4.1 | ChaCha20 | Argon2id | ✓ | ✓ | TBD | |
| `single-entry` | 4.1 | ChaCha20 | Argon2id | ✓ | ✓ | TBD | |
| `groups-and-entries` | 4.1 | AES-256 | Argon2d | ✗ | ✗ | — | **Upstream bug**: `keepass-rs` 0.12.0 has no `PreviousParentGroup` field on `Group`/`Entry` in its XML schema. KDBX 4.1 records the previous-parent UUID whenever an entry or group is moved; this fixture's history triggers the field. Fails with `Format(Kdbx4(Xml(Custom("unknown variant `PreviousParentGroup`, expected `Group` or `Entry`"))))`. Tracked at `crates/kdbx/tests/roundtrip.rs::roundtrip_groups_and_entries_preserves_hierarchy` (`#[ignore]`). Resolution options: wait for upstream, submit upstream PR (small fix in `format/xml_db/group.rs` + `entry.rs`), or fork. |
| `with-history` | 4.1 | ChaCha20 | Argon2id | ✓ | ✓ | TBD | |
| `with-attachments` | 4.1 | ChaCha20 | Argon2id | ✓ | ✓ | TBD | Binary attachments preserved byte-for-byte. |
| `with-custom-icons` | 4.1 | — | — | TBD | TBD | TBD | Test scaffolded in milestone-0 task #11 follow-up. |
| `with-custom-data` | 4.1 | ChaCha20 | Argon2id | ✓ | ✓ | TBD | |
| `with-tags-and-expiry` | 4.1 | — | — | TBD | TBD | TBD | Test scaffolded in milestone-0 task #11 follow-up. |
| `with-autotype` | 4.1 | — | — | TBD | TBD | TBD | Test scaffolded in milestone-0 task #11 follow-up. |
| `with-keyfile` | 4.1 | — | — | TBD | TBD | TBD | Test scaffolded in milestone-0 task #11 follow-up. |
| `kdbx41-features` | 4.1 | ChaCha20 | Argon2id | ✓ | ✓ | TBD | |
| `kdbx40-legacy` | 4.0 | ChaCha20 | Argon2id | ✓ | — | — | Read-only fixture per `docs/design.md` §3 non-goal (we write only KDBX 4.x current). |
| `kdbx3-legacy` | 3.1 | — | — | ✓ | — | — | Read-only fixture; audit will flag for upgrade. We do not write KDBX 3.x. |

## Known upstream gaps in `keepass = 0.12.0`

1. **`PreviousParentGroup` (KDBX 4.1) — read failure.** See `groups-and-entries` row above. Affects any database where a group or entry has been moved.

3. **KDBX minor version normalized to 0 on parse.** `Database::config.version` always reports `KDB4(0)` after parsing, regardless of whether the file header says `KDB4(0)` or `KDB4(1)`. Visible via `cargo run --features dump-expected --bin dump-expected` against the `empty` fixture (which has header bytes for KDBX 4.1 but is reported as `kdb4.0`). Cosmetic for round-trip — both directions read consistently — but means our own writes are always emitted as KDBX 4.0. Should be filed alongside #2 if upstream PRs are pursued.

2. **Writer produces files KeePassXC rejects — M0 BLOCKER.** A file written by `keepass::Database::save` cannot be re-opened by `keepassxc-cli` 2.7.12. KeePassXC errors with `Invalid EnableSearching value`, after warnings about skipped `DefaultUsername`, `DefaultUsernameChanged`, `ProtectUsername` Meta elements. Reproduce with `cargo test -p kdbx --test roundtrip --features keepassxc-verify -- --ignored`. This contradicts the project goal "A file written by freekee must open cleanly in KeePassXC 2.7+" (`AGENTS.md`). Affected tests: `keepassxc_can_open_written_empty`, `keepassxc_can_open_written_single_entry` (both `#[ignore]`). Resolution requires either: (a) an upstream fix to `keepass`'s XML serializer (likely a small fix in `format/xml_db/group.rs` for the `EnableSearching` tri-state), (b) a fork, or (c) a different KDBX library. **Decision needed before further milestone work claims KDBX compatibility.**
