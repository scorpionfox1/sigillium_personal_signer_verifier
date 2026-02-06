// src/platform/debug_faults.rs

#[cfg(any(debug_assertions, test))]
use std::collections::HashMap;
#[cfg(any(debug_assertions, test))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(debug_assertions, test))]
use std::sync::{Mutex, OnceLock};

#[cfg(any(debug_assertions, test))]
use crate::platform::BestEffortFailure;

#[cfg(any(debug_assertions, test))]
static HARD_FAIL_COUNTDOWN: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(debug_assertions, test))]
static SOFT_FAIL_COUNTDOWN: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(debug_assertions, test))]
static SOFT_FAIL_VEC_COUNTDOWN: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(debug_assertions, test))]
static SOFT_FAIL_VEC_EMIT: AtomicUsize = AtomicUsize::new(1);

// Per-op countdowns (debug/test only).
#[cfg(any(debug_assertions, test))]
static PER_OP_HARD: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
#[cfg(any(debug_assertions, test))]
static PER_OP_SOFT: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
#[cfg(any(debug_assertions, test))]
static PER_OP_SOFT_VEC: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
#[cfg(any(debug_assertions, test))]
static PER_OP_SOFT_VEC_EMIT: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

#[cfg(any(debug_assertions, test))]
static ENV_INIT: OnceLock<()> = OnceLock::new();

#[cfg(any(debug_assertions, test))]
fn ensure_env_init() {
    ENV_INIT.get_or_init(init_from_env_inner);
}

#[cfg(any(debug_assertions, test))]
fn lock_unpoisoned<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(any(debug_assertions, test))]
fn hard_map() -> &'static Mutex<HashMap<String, usize>> {
    PER_OP_HARD.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(debug_assertions, test))]
fn soft_map() -> &'static Mutex<HashMap<String, usize>> {
    PER_OP_SOFT.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(debug_assertions, test))]
fn soft_vec_map() -> &'static Mutex<HashMap<String, usize>> {
    PER_OP_SOFT_VEC.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(debug_assertions, test))]
fn soft_vec_emit_map() -> &'static Mutex<HashMap<String, usize>> {
    PER_OP_SOFT_VEC_EMIT.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(debug_assertions, test))]
fn countdown_hit(counter: &AtomicUsize) -> bool {
    // Returns true exactly once, on the call that decrements from 1 -> 0.
    let prev = counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
            if x == 0 {
                None
            } else {
                Some(x - 1)
            }
        })
        .ok();

    matches!(prev, Some(1))
}

#[cfg(any(debug_assertions, test))]
fn per_op_countdown_hit(map: &'static Mutex<HashMap<String, usize>>, op: &'static str) -> bool {
    let mut guard = lock_unpoisoned(map);

    let Some(v) = guard.get_mut(op) else {
        return false;
    };

    if *v == 0 {
        guard.remove(op);
        return false;
    }

    *v -= 1;

    if *v == 0 {
        guard.remove(op);
        true
    } else {
        false
    }
}

#[cfg(any(debug_assertions, test))]
fn per_op_emit_for(op: &'static str) -> usize {
    let guard = lock_unpoisoned(soft_vec_emit_map());
    guard
        .get(op)
        .copied()
        .unwrap_or_else(|| SOFT_FAIL_VEC_EMIT.load(Ordering::SeqCst))
}

/// Force the next N calls to hard-fail (global).
#[cfg(any(debug_assertions, test))]
pub fn inject_hard_fail_after(n: usize) {
    HARD_FAIL_COUNTDOWN.store(n, Ordering::SeqCst);
}

/// Force the next N calls to emit a best-effort failure (single warning, global).
#[cfg(any(debug_assertions, test))]
pub fn inject_soft_fail_after(n: usize) {
    SOFT_FAIL_COUNTDOWN.store(n, Ordering::SeqCst);
}

/// Force the next N calls to emit a best-effort failure vector (multiple warnings, global).
/// When it triggers, it emits `emit` failures at once.
#[cfg(any(debug_assertions, test))]
pub fn inject_soft_fail_vec_after(n: usize, emit: usize) {
    SOFT_FAIL_VEC_EMIT.store(emit, Ordering::SeqCst);
    SOFT_FAIL_VEC_COUNTDOWN.store(n, Ordering::SeqCst);
}

/// Targeted: force the next N calls for a specific op to hard-fail.
#[cfg(any(debug_assertions, test))]
pub fn inject_hard_fail_for_op_after(op: &str, n: usize) {
    lock_unpoisoned(hard_map()).insert(op.to_string(), n);
}

/// Targeted: force the next N calls for a specific op to emit a single warning.
#[cfg(any(debug_assertions, test))]
pub fn inject_soft_fail_for_op_after(op: &str, n: usize) {
    lock_unpoisoned(soft_map()).insert(op.to_string(), n);
}

/// Targeted: force the next N calls for a specific op to emit a warning vector.
#[cfg(any(debug_assertions, test))]
pub fn inject_soft_fail_vec_for_op_after(op: &str, n: usize, emit: usize) {
    lock_unpoisoned(soft_vec_emit_map()).insert(op.to_string(), emit);
    lock_unpoisoned(soft_vec_map()).insert(op.to_string(), n);
}

/// Initialize fault injection from env var (debug/test only).
///
/// Global:
/// - `hard:N`
/// - `soft:N`
/// - `soft_vec:N[:EMIT]`
///
/// Targeted (disambiguated with '@'):
/// - `hard@OP:N`
/// - `soft@OP:N`
/// - `soft_vec@OP:N[:EMIT]`

#[cfg(any(debug_assertions, test))]
fn init_from_env_inner() {
    let spec = match std::env::var("SIGILLIUM_DEBUG_FAULTS") {
        Ok(v) => v,
        Err(_) => return,
    };

    for part in spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let (head, tail) = match part.split_once(':') {
            Some((h, t)) => (h.trim(), t.trim()),
            None => continue,
        };

        let (kind, op_opt) = match head.split_once('@') {
            Some((k, op)) => (k.trim().to_ascii_lowercase(), Some(op.trim())),
            None => (head.to_ascii_lowercase(), None),
        };

        let args: Vec<&str> = if tail.is_empty() {
            Vec::new()
        } else {
            tail.split(':')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect()
        };

        match (kind.as_str(), op_opt) {
            // ---------- targeted ----------
            ("hard", Some(op)) => {
                if let Some(n_str) = args.get(0) {
                    if let Ok(n) = n_str.parse::<usize>() {
                        if !op.is_empty() {
                            inject_hard_fail_for_op_after(op, n);
                        }
                    }
                }
            }
            ("soft", Some(op)) => {
                if let Some(n_str) = args.get(0) {
                    if let Ok(n) = n_str.parse::<usize>() {
                        if !op.is_empty() {
                            inject_soft_fail_for_op_after(op, n);
                        }
                    }
                }
            }
            ("soft_vec", Some(op)) => {
                if let Some(n_str) = args.get(0) {
                    if let Ok(n) = n_str.parse::<usize>() {
                        let emit = args
                            .get(1)
                            .and_then(|s| s.parse::<usize>().ok())
                            .unwrap_or(1);
                        if !op.is_empty() {
                            inject_soft_fail_vec_for_op_after(op, n, emit);
                        }
                    }
                }
            }

            // ---------- global ----------
            ("hard", None) => {
                if let Some(n_str) = args.get(0) {
                    if let Ok(n) = n_str.parse::<usize>() {
                        inject_hard_fail_after(n);
                    }
                }
            }
            ("soft", None) => {
                if let Some(n_str) = args.get(0) {
                    if let Ok(n) = n_str.parse::<usize>() {
                        inject_soft_fail_after(n);
                    }
                }
            }
            ("soft_vec", None) => {
                if let Some(n_str) = args.get(0) {
                    if let Ok(n) = n_str.parse::<usize>() {
                        let emit = args
                            .get(1)
                            .and_then(|s| s.parse::<usize>().ok())
                            .unwrap_or(1);
                        inject_soft_fail_vec_after(n, emit);
                    }
                }
            }

            _ => {}
        }
    }
}

/// Maybe inject a hard failure (early abort).
#[cfg(any(debug_assertions, test))]
pub fn maybe_inject_hard_fail(op: &'static str) -> Option<String> {
    ensure_env_init();

    if per_op_countdown_hit(hard_map(), op) || countdown_hit(&HARD_FAIL_COUNTDOWN) {
        Some(format!("debug fault: forced hard failure in {}", op))
    } else {
        None
    }
}

/// Maybe inject a best-effort failure (warning only, single).
#[cfg(any(debug_assertions, test))]
pub fn maybe_inject_soft_fail(op: &'static str) -> Option<BestEffortFailure> {
    ensure_env_init();

    if per_op_countdown_hit(soft_map(), op) || countdown_hit(&SOFT_FAIL_COUNTDOWN) {
        Some(BestEffortFailure {
            kind: "debug_fault",
            errno: None,
            msg: op,
        })
    } else {
        None
    }
}

/// Maybe inject best-effort failures (warning only, vector).
#[cfg(any(debug_assertions, test))]
pub fn maybe_inject_soft_fail_vec(op: &'static str) -> Vec<BestEffortFailure> {
    ensure_env_init();

    let triggered_targeted = per_op_countdown_hit(soft_vec_map(), op);
    let triggered_global = if triggered_targeted {
        false
    } else {
        countdown_hit(&SOFT_FAIL_VEC_COUNTDOWN)
    };

    if !triggered_targeted && !triggered_global {
        return Vec::new();
    }

    let emit = if triggered_targeted {
        per_op_emit_for(op)
    } else {
        SOFT_FAIL_VEC_EMIT.load(Ordering::SeqCst)
    };

    if emit == 0 {
        return Vec::new();
    }

    let mut v = Vec::with_capacity(emit);
    for _ in 0..emit {
        v.push(BestEffortFailure {
            kind: "debug_fault",
            errno: None,
            msg: op,
        });
    }
    v
}

#[cfg(not(any(debug_assertions, test)))]
pub fn maybe_inject_hard_fail(_: &'static str) -> Option<String> {
    None
}
#[cfg(not(any(debug_assertions, test)))]
pub fn maybe_inject_soft_fail(_: &'static str) -> Option<crate::platform::BestEffortFailure> {
    None
}
#[cfg(not(any(debug_assertions, test)))]
pub fn maybe_inject_soft_fail_vec(_: &'static str) -> Vec<crate::platform::BestEffortFailure> {
    Vec::new()
}
