//! Static scanner (ports `backend/app/scanner/`).

pub mod rules;
pub mod scan;

pub use rules::{scan_source, RawFinding, RULE_META};
pub use scan::{scan_repo, SKIP_DIRS};
