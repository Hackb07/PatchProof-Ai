//! Patcher (ports `backend/app/patcher/`).

pub mod applier;
pub mod generator;

pub use applier::apply_diff;
pub use generator::{deterministic_fix, fix_hint, generate_patches};
