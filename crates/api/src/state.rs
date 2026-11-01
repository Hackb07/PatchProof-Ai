//! Shared application state.

use patchproof_core::config::Settings;
use patchproof_core::store::Store;

#[derive(Debug, Clone)]
pub struct AppState {
    pub store: Store,
    pub settings: Settings,
}
