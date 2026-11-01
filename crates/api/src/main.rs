//! API entrypoint (ports `backend/app/main.py`).

use patchproof_api::{build_app, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let settings = patchproof_core::config::Settings::from_env();
    let store = patchproof_core::store::Store::from_settings(&settings);
    store.init_db()?;

    let state = AppState { store, settings };
    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
