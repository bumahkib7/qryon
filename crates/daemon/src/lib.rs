//! Qryon Daemon - Background server for IDE integration and API access
//!
//! Features:
//! - REST API for scanning and analysis
//! - WebSocket for real-time file watching updates
//! - Designed for IDE integration

pub mod api;
pub mod state;
pub mod websocket;

use anyhow::Result;
use axum::{
    Router,
    routing::{get, post},
};
use rma_common::RmaConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use state::AppState;
use websocket::WsState;

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

/// Start the daemon server with just an address string
pub async fn start_server(addr: &str) -> Result<()> {
    let parts: Vec<&str> = addr.split(':').collect();
    let config = DaemonConfig {
        host: parts.first().unwrap_or(&"127.0.0.1").to_string(),
        port: parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(8080),
        ..Default::default()
    };
    start_server_with_config(config).await
}

/// Start the daemon server with full configuration
pub async fn start_server_with_config(config: DaemonConfig) -> Result<()> {
    let app_state = Arc::new(RwLock::new(AppState::new(config.rma_config)));
    let ws_state = Arc::new(WsState::new());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // REST API routes
    let api_routes = Router::new()
        .route("/scan", post(api::scan_endpoint))
        .route("/analyze", post(api::analyze_file_endpoint))
        .route("/search", get(api::search_endpoint))
        .route("/stats", get(api::stats_endpoint))
        .with_state(app_state);

    // WebSocket routes
    let ws_routes = Router::new()
        .route("/watch", get(websocket::ws_handler))
        .with_state(ws_state);

    let app = Router::new()
        .route("/health", get(health_check))
        .nest("/api/v1", api_routes)
        .nest("/ws", ws_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("Starting Qryon daemon on {}", addr);
    info!("  REST API: http://{}/api/v1/", addr);
    info!("  WebSocket: ws://{}/ws/watch", addr);

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
