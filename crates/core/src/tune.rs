//! Per-platform Argon2id parameter tuning. Runs one baseline
//! Argon2id derivation against the host, then picks an iteration
//! count that should make a full derivation take approximately
//! `target_ms`. Memory and parallelism are held at sane defaults
//! (the search space is one-dimensional on purpose).
//!
//! Surfaced behind `freekee init --tune` and
//! `freekee rotate kdf-params --tune`. Not run implicitly.

use std::thread;
use std::time::Instant;

/// Lower bound on tuned iterations. Matches the audit rule's
/// `weak-argon2-params` safety floor so the tuner can never bake a
/// database that the audit feature would immediately flag.
const MIN_ITERS: u64 = 2;

/// Upper bound on tuned iterations. Caps the tuner on a host so slow
/// that the baseline measurement overshoots target — prefer a
/// reasonably-sized iter count over a runaway loop.
const MAX_ITERS: u64 = 200;

/// Memory the tuner picks, in bytes. Matches `DEFAULT_TEMPLATE.kdf.memory`.
const TUNE_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on parallelism the tuner will request, regardless of
/// host CPU count. Prevents a 32-core build host from baking a
/// database whose Argon2id parallelism the user's phone can't
/// saturate. The actual value is `min(available_parallelism, 4)`.
const MAX_TUNE_PARALLELISM: u32 = 4;

/// Iteration count the baseline run uses. Picking 4 (rather than 2)
/// gives the timer enough work to escape sub-millisecond noise on
/// fast hosts; the result is then linearly scaled to `target_ms`.
const BASELINE_ITERS: u64 = 4;

/// Pure algebra: given a baseline that ran `baseline_iters` Argon2id
/// passes in `baseline_ms` milliseconds, return the iteration count
/// that should take approximately `target_ms` (clamped to
/// `[MIN_ITERS, MAX_ITERS]`).
///
/// `baseline_ms == 0` falls back to `MAX_ITERS` — host was too fast
/// to measure, so prefer over-tuning to under-tuning.
pub fn iterations_for_target(baseline_iters: u64, baseline_ms: u128, target_ms: u32) -> u64 {
    if baseline_ms == 0 {
        return MAX_ITERS;
    }
    let numerator = baseline_iters as u128 * target_ms as u128;
    let raw = numerator.div_ceil(baseline_ms);
    raw.clamp(MIN_ITERS as u128, MAX_ITERS as u128) as u64
}

/// Benchmark the host with one Argon2id derivation at
/// `BASELINE_ITERS`, then scale linearly to `target_ms`. Memory is
/// held at 64 MiB and parallelism at `min(available_parallelism, 4)`.
pub fn tune_argon2id(target_ms: u32) -> kdbx::Argon2idParams {
    let parallelism = thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
        .clamp(1, MAX_TUNE_PARALLELISM);

    // rust-argon2 expects mem_cost in KiB; our public API stays in bytes.
    let mem_cost_kib = (TUNE_MEMORY_BYTES / 1024) as u32;
    let thread_mode = if parallelism > 1 {
        argon2::ThreadMode::Parallel
    } else {
        argon2::ThreadMode::Sequential
    };
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: mem_cost_kib,
        time_cost: BASELINE_ITERS as u32,
        lanes: parallelism,
        thread_mode,
        ..argon2::Config::default()
    };

    // Throwaway inputs. The derived key is discarded; we only care
    // about how long the call took on this host. The password and
    // salt are constants by design — they never touch user data and
    // never get stored.
    let password = b"freekee-tune-benchmark";
    let salt = b"freekee-tune-saltsaltsalt";

    let start = Instant::now();
    let _ = argon2::hash_raw(password, salt, &config).expect("argon2 baseline must succeed");
    let elapsed_ms = start.elapsed().as_millis();

    let iterations = iterations_for_target(BASELINE_ITERS, elapsed_ms, target_ms);
    kdbx::Argon2idParams {
        memory: TUNE_MEMORY_BYTES,
        iterations,
        parallelism,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn iterations_for_target_scales_linearly() {
        // 4 iters took 100ms; target 1000ms → 40 iters.
        assert_eq!(iterations_for_target(4, 100, 1000), 40);
    }

    #[test]
    fn iterations_for_target_rounds_up() {
        // 4 * 1000 / 300 = 13.33… → 14 (ceil, not truncate, so the
        // tuner never under-shoots target).
        assert_eq!(iterations_for_target(4, 300, 1000), 14);
    }

    #[test]
    fn iterations_for_target_clamps_low() {
        // Host so slow that even baseline took longer than target.
        // Raw result would be 1 (or less); clamped to MIN_ITERS.
        assert_eq!(iterations_for_target(4, 10_000, 1000), MIN_ITERS);
    }

    #[test]
    fn iterations_for_target_clamps_high() {
        // Host so fast that scaled result blows past 200. Clamp
        // protects against runaway iteration counts.
        assert_eq!(iterations_for_target(4, 1, 10_000), MAX_ITERS);
    }

    #[test]
    fn iterations_for_target_zero_baseline_returns_max() {
        assert_eq!(iterations_for_target(4, 0, 1000), MAX_ITERS);
    }

    #[test]
    fn tune_argon2id_returns_params_within_bounds() {
        let p = tune_argon2id(50);
        assert_eq!(
            p.memory, TUNE_MEMORY_BYTES,
            "memory should be fixed at 64 MiB"
        );
        assert!(
            (1..=MAX_TUNE_PARALLELISM).contains(&p.parallelism),
            "parallelism {} out of [1, {}]",
            p.parallelism,
            MAX_TUNE_PARALLELISM,
        );
        assert!(
            (MIN_ITERS..=MAX_ITERS).contains(&p.iterations),
            "iterations {} out of [{}, {}]",
            p.iterations,
            MIN_ITERS,
            MAX_ITERS,
        );
    }
}
