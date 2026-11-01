//! PatchProof AI core library.
//!
//! Ports the Python backend: static scanner, triage/risk/validator agents,
//! sandboxed PoC reproduction, deterministic patch generation, verification,
//! and the pipeline orchestrator. Storage is SQLite via rusqlite.

pub mod agents;
pub mod config;
pub mod error;
pub mod model;
pub mod patcher;
pub mod pipeline;
pub mod sandbox;
pub mod scanner;
pub mod store;
pub mod verifier;

/// Truncate to at most `n` Unicode scalar values (mirrors Python `s[:n]`).
pub fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    s.chars().take(n).collect()
}
