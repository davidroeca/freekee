//! Generative round-trip tests. Each test builds a random in-memory
//! `Database`, saves to a tempfile, reopens, and asserts structural
//! equality via the wrapper's `PartialEq + Eq` derive.
//!
//! Case count is intentionally low (32 per test) and Argon2 params are
//! the smallest the upstream validator accepts, so the suite stays
//! cheap on `cargo test --workspace --locked`. Use
//! `PROPTEST_CASES=512 cargo test -p kdbx --test proptest_roundtrip`
//! for local stress runs.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use chrono::{DateTime, NaiveDateTime, Utc};
use kdbx::{
    Argon2idParams, Database, EntryDraft, EntryField, EntryFieldValue, EntryPath, GroupPath,
    InnerCipher, NewDatabaseTemplate, OuterCipher,
};
use proptest::prelude::*;

fn tiny_kdf() -> Argon2idParams {
    Argon2idParams {
        memory: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    }
}

fn template(outer: OuterCipher, inner: InnerCipher) -> NewDatabaseTemplate {
    NewDatabaseTemplate {
        kdf: tiny_kdf(),
        outer_cipher: outer,
        inner_cipher: inner,
    }
}

fn arb_outer() -> impl Strategy<Value = OuterCipher> {
    prop_oneof![
        Just(OuterCipher::Aes256),
        Just(OuterCipher::Twofish),
        Just(OuterCipher::ChaCha20),
    ]
}

fn arb_inner() -> impl Strategy<Value = InnerCipher> {
    prop_oneof![
        Just(InnerCipher::Plain),
        Just(InnerCipher::Salsa20),
        Just(InnerCipher::ChaCha20),
    ]
}

// 1 to `max` non-control Unicode chars, with at least one non-whitespace
// char. Two narrowings vs. "any string":
//
//   - Control chars are excluded because XML 1.0 forbids them in element
//     content, so they aren't valid input to the format regardless of the
//     wrapper.
//   - Empty and whitespace-only strings are excluded because upstream
//     `keepass-rs` 0.12.1 drops `<Value></Value>` elements on save and
//     trims whitespace-only titles on parse, breaking round-trip. Tracked
//     in `docs/kdbx-compat-matrix.md` "Known upstream gaps" #4-adjacent
//     (empty-field drop). Re-widen this strategy once upstream preserves
//     them losslessly.
fn arb_text(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(
        any::<char>().prop_filter("non-control", |c| !c.is_control()),
        1..=max,
    )
    .prop_map(|v| v.into_iter().collect())
    .prop_filter("at least one non-whitespace char", |s: &String| {
        s.chars().any(|c| !c.is_whitespace())
    })
}

fn arb_ident() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,7}".prop_map(String::from)
}

fn arb_custom_key() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_-]{0,11}".prop_map(String::from)
}

// Argon2id parameters that always satisfy the upstream validator's floor
// (rust-argon2 requires `mem_cost >= 8 * lanes`, where `mem_cost` is
// `memory_bytes / 1024`). `memory` is carried in *bytes*, so we build it
// from `mem_kib * 1024` with `mem_kib >= 8 * parallelism`. Ranges are kept
// small on purpose: every case runs two real Argon2 derivations (save +
// verify-on-open), so this stays cheap at 32 cases.
fn arb_kdf_params() -> impl Strategy<Value = Argon2idParams> {
    (1u32..=2).prop_flat_map(|parallelism| {
        ((8 * parallelism)..=32u32, 1u64..=2).prop_map(move |(mem_kib, iterations)| {
            Argon2idParams {
                memory: u64::from(mem_kib) * 1024,
                iterations,
                parallelism,
            }
        })
    })
}

// `None`, or a whole-second timestamp in a modern range (~2001-2096).
// KDBX serializes times at second precision, so sub-second values would
// not round-trip; building from `from_timestamp(secs, 0)` guarantees no
// nanosecond component to lose.
fn arb_whole_second_expiry() -> impl Strategy<Value = Option<NaiveDateTime>> {
    prop_oneof![
        Just(None),
        (1_000_000_000i64..=4_000_000_000).prop_map(|secs| Some(
            DateTime::<Utc>::from_timestamp(secs, 0)
                .unwrap()
                .naive_utc()
        )),
    ]
}

fn save_open_roundtrip(db: &Database) -> Database {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("p.kdbx");
    db.save(&path, "pw", None).unwrap();
    Database::open(&path, "pw", None).unwrap()
}

#[derive(Debug, Clone)]
struct GenGroup {
    name: String,
    entries: Vec<String>,
    children: Vec<GenGroup>,
}

#[derive(Debug, Clone)]
struct GenTree {
    root_entries: Vec<String>,
    children: Vec<GenGroup>,
}

fn arb_group(depth_remaining: u32) -> BoxedStrategy<GenGroup> {
    if depth_remaining == 0 {
        return (arb_ident(), proptest::collection::vec(arb_ident(), 0..=2))
            .prop_map(|(name, entries)| GenGroup {
                name,
                entries,
                children: vec![],
            })
            .boxed();
    }
    (
        arb_ident(),
        proptest::collection::vec(arb_ident(), 0..=2),
        proptest::collection::vec(arb_group(depth_remaining - 1), 0..=3),
    )
        .prop_map(|(name, entries, children)| GenGroup {
            name,
            entries,
            children,
        })
        .boxed()
}

fn arb_shallow_tree() -> impl Strategy<Value = GenTree> {
    (
        proptest::collection::vec(arb_ident(), 0..=2),
        proptest::collection::vec(arb_group(2), 0..=3),
    )
        .prop_map(|(root_entries, children)| GenTree {
            root_entries,
            children,
        })
}

fn apply_group(db: &mut Database, parent: &[&str], g: &GenGroup) {
    let mut segments: Vec<&str> = parent.to_vec();
    segments.push(&g.name);
    db.ensure_group(GroupPath {
        segments: &segments,
    })
    .unwrap();
    for title in &g.entries {
        db.add_entry(
            EntryPath {
                groups: &segments,
                title,
            },
            EntryDraft::default(),
        )
        .unwrap();
    }
    for child in &g.children {
        apply_group(db, &segments, child);
    }
}

fn apply_tree(db: &mut Database, tree: &GenTree) {
    for title in &tree.root_entries {
        db.add_entry(EntryPath { groups: &[], title }, EntryDraft::default())
            .unwrap();
    }
    for child in &tree.children {
        apply_group(db, &[], child);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// 1. Empty database across the cipher × inner-cipher matrix.
    /// Catches header / cipher / KDF serialization drift on save.
    #[test]
    fn prop_empty_db_template_roundtrip(
        outer in arb_outer(),
        inner in arb_inner(),
    ) {
        let db = Database::new_empty(template(outer, inner));
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(db, reopened);
    }

    /// 2. Single entry under root with arbitrary string fields plus
    /// 0-3 custom fields. Catches XML escape / UTF-8 / protected-
    /// stream issues across all standard and custom field paths.
    #[test]
    fn prop_single_entry_string_fields_roundtrip(
        title in arb_text(32),
        username in arb_text(32),
        password in arb_text(32),
        url in arb_text(64),
        notes in arb_text(64),
        customs in proptest::collection::vec(
            (arb_custom_key(), arb_text(32), any::<bool>()),
            0..=3,
        ),
    ) {
        let mut db = Database::new_empty(template(
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
        ));
        let entry_path = EntryPath { groups: &[], title: &title };
        db.add_entry(
            entry_path,
            EntryDraft {
                username: Some(&username),
                password: Some(&password),
                url: Some(&url),
                notes: Some(&notes),
            },
        ).unwrap();
        for (k, v, protected) in &customs {
            db.set_entry_field(
                entry_path,
                EntryField::Custom(k),
                if *protected {
                    EntryFieldValue::Protected(v)
                } else {
                    EntryFieldValue::Plain(v)
                },
            ).unwrap();
        }
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(db, reopened);
    }

    /// 3. Random shallow tree of groups and entries (depth ≤ 2,
    /// ≤ 3 subgroups per level, ≤ 2 entries per group). Catches
    /// hierarchy and ordering invariants. Sibling-name collisions
    /// collapse via `ensure_group`'s idempotent lookup; the
    /// post-collapse tree is what gets round-tripped.
    #[test]
    fn prop_shallow_tree_roundtrip(tree in arb_shallow_tree()) {
        let mut db = Database::new_empty(template(
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
        ));
        apply_tree(&mut db, &tree);
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(db, reopened);
    }

    /// 4. `move_entry` round-trip. Ignored until upstream
    /// `keepass-rs` PR #308 (`<PreviousParentGroup>`) lands. The
    /// existing fixture test
    /// `roundtrip_groups_and_entries_preserves_hierarchy` tracks the
    /// same blocker.
    #[test]
    #[ignore = "blocked on upstream keepass-rs PR #308 (<PreviousParentGroup>)"]
    fn prop_move_entry_roundtrip(
        src_group in arb_ident(),
        dst_group in arb_ident(),
        title in arb_ident(),
    ) {
        prop_assume!(src_group != dst_group);
        let mut db = Database::new_empty(template(
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
        ));
        db.ensure_group(GroupPath { segments: &[&src_group] }).unwrap();
        db.ensure_group(GroupPath { segments: &[&dst_group] }).unwrap();
        db.add_entry(
            EntryPath { groups: &[&src_group], title: &title },
            EntryDraft::default(),
        ).unwrap();
        db.move_entry(
            EntryPath { groups: &[&src_group], title: &title },
            EntryPath { groups: &[&dst_group], title: &title },
        ).unwrap();
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(db, reopened);
    }

    /// 5. Argon2id parameter variation. Every other test fixes
    /// `tiny_kdf()`; this varies memory / iterations / parallelism within
    /// the validator's floor and asserts the params survive save → open.
    /// Generative sibling of the example-based `set_kdf_params` test in
    /// `mutate.rs`.
    #[test]
    fn prop_kdf_params_roundtrip(params in arb_kdf_params()) {
        let mut db = Database::new_empty(template(
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
        ));
        db.set_kdf_params(params).unwrap();
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(db, reopened);
    }

    /// 6. Entry expiry round-trip across the `Some(ts)` set path and the
    /// `None` clear path. Timestamps are whole seconds (see
    /// `arb_whole_second_expiry`). Generative sibling of the example-based
    /// expiry persist / clear tests in `mutate.rs`.
    #[test]
    fn prop_entry_expiry_roundtrip(
        title in arb_ident(),
        expiry in arb_whole_second_expiry(),
    ) {
        let mut db = Database::new_empty(template(
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
        ));
        let path = EntryPath { groups: &[], title: &title };
        db.add_entry(path, EntryDraft::default()).unwrap();
        db.set_entry_expiry(path, expiry).unwrap();
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(db, reopened);
    }

    /// 7. History accumulation. Each `set_entry_field` snapshots the prior
    /// version via `edit_tracking`, so N successive edits yield N history
    /// versions (a freshly-added entry starts at zero). Asserts both the
    /// full structural round-trip and the surviving `history_count`. N ≤ 5
    /// stays under the default `history_max_items = 10`, so no pruning.
    #[test]
    fn prop_entry_history_roundtrip(
        title in arb_ident(),
        values in proptest::collection::vec(arb_text(32), 1..=5),
    ) {
        let mut db = Database::new_empty(template(
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
        ));
        let path = EntryPath { groups: &[], title: &title };
        db.add_entry(path, EntryDraft::default()).unwrap();
        for v in &values {
            db.set_entry_field(path, EntryField::Password, EntryFieldValue::Protected(v))
                .unwrap();
        }
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(
            reopened.entry_by_path(path).unwrap().history_count(),
            values.len()
        );
        prop_assert_eq!(db, reopened);
    }

    /// 8. Delete registry. `remove_entry` registers each UUID in
    /// `deleted_objects` (KeePassXC sync correctness). Builds 1-3 entries,
    /// removes a generated subset, and asserts both the structural
    /// round-trip and the surviving `deleted_object_count`.
    #[test]
    fn prop_delete_registry_roundtrip(
        titles in proptest::collection::hash_set(arb_ident(), 1..=3),
        remove_mask in proptest::collection::vec(any::<bool>(), 1..=3),
    ) {
        let titles: Vec<String> = titles.into_iter().collect();
        let mut db = Database::new_empty(template(
            OuterCipher::ChaCha20,
            InnerCipher::ChaCha20,
        ));
        for title in &titles {
            db.add_entry(EntryPath { groups: &[], title }, EntryDraft::default())
                .unwrap();
        }
        let mut removed = 0usize;
        for (title, remove) in titles.iter().zip(remove_mask.iter().cycle()) {
            if *remove {
                db.remove_entry(EntryPath { groups: &[], title }).unwrap();
                removed += 1;
            }
        }
        let reopened = save_open_roundtrip(&db);
        prop_assert_eq!(reopened.deleted_object_count(), removed);
        prop_assert_eq!(db, reopened);
    }
}
