//! RMA Daemon - Background server for IDE integration and API access

pub mod api;
pub mod state;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use rma_common::RmaConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use state::AppState;

/// Daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub host: String,
    pub port: u16,
    pub rma_config: RmaConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 9876,
            rma_config: RmaConfig::default(),
        }
    }
}

/// Start the daemon server
pub async fn start_server(config: DaemonConfig) -> Result<()> {
    let state = Arc::new(RwLock::new(AppState::new(config.rma_config)));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/scan", post(api::scan_endpoint))
        .route("/api/v1/analyze", post(api::analyze_file_endpoint))
        .route("/api/v1/search", get(api::search_endpoint))
        .route("/api/v1/stats", get(api::stats_endpoint))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("Starting RMA daemon on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let result = health_check().await;
        assert_eq!(result, "OK");
    }
}
