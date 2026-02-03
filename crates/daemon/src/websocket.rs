//! WebSocket support for real-time file watching and analysis updates

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use rma_analyzer::AnalyzerEngine;
use rma_common::{Finding, RmaConfig, Severity};
use rma_indexer::watcher::{self, FileEventKind};
use rma_parser::ParserEngine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;
use tracing::info;

/// WebSocket message types sent to clients
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum WsMessage {
    Connected {
        client_id: String,
    },
    FileChanged {
        path: String,
        kind: String,
    },
    AnalysisComplete {
        path: String,
        findings: Vec<FindingDto>,
        duration_ms: u64,
    },
    Error {
        message: String,
    },
    WatchingStarted {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingDto {
    pub rule_id: String,
    pub message: String,
    pub severity: String,
    pub line: usize,
    pub column: usize,
}

impl From<&Finding> for FindingDto {
    fn from(f: &Finding) -> Self {
        Self {
            rule_id: f.rule_id.clone(),
            message: f.message.clone(),
            severity: match f.severity {
                Severity::Critical => "critical",
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "info",
            }
            .to_string(),
            line: f.location.start_line,
            column: f.location.start_column,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", content = "data")]
pub enum WsCommand {
    Watch { path: String },
    StopWatch,
    Analyze { path: String },
    Ping,
}

pub struct WsState {
    pub tx: broadcast::Sender<WsMessage>,
}

impl WsState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self { tx }
    }
}

impl Default for WsState {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<WsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<WsState>) {
    let client_id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    info!("WebSocket client connected: {}", client_id);

    let (mut sender, mut receiver) = socket.split();

    // Send connected message
    let msg = WsMessage::Connected {
        client_id: client_id.clone(),
    };
    let _ = sender
        .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
        .await;

    // Subscribe to broadcasts
    let mut broadcast_rx = state.tx.subscribe();

    // Task to forward broadcasts to this client
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = broadcast_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&msg)
                && sender.send(Message::Text(json.into())).await.is_err()
            {
                break;
            }
        }
    });

    // Handle incoming messages
    let tx = state.tx.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg
                && let Ok(cmd) = serde_json::from_str::<WsCommand>(&text)
            {
                handle_command(cmd, tx.clone()).await;
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }

    info!("WebSocket client disconnected: {}", client_id);
}

async fn handle_command(cmd: WsCommand, tx: broadcast::Sender<WsMessage>) {
    match cmd {
        WsCommand::Watch { path } => {
            start_watching(&path, tx).await;
        }
        WsCommand::StopWatch => {
            // Would need to track watcher handles per client
        }
        WsCommand::Analyze { path } => {
            analyze_file(&path, tx).await;
        }
        WsCommand::Ping => {}
    }
}

async fn start_watching(path: &str, tx: broadcast::Sender<WsMessage>) {
    let path = PathBuf::from(path);
    let tx_clone = tx.clone();

    // Notify watching started
    let _ = tx.send(WsMessage::WatchingStarted {
        path: path.display().to_string(),
    });

    // Run watcher in a blocking thread (not tokio task)
    let watch_path = path.clone();
    std::thread::spawn(move || {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config.clone());
        let analyzer = AnalyzerEngine::new(config);

        // Initial scan of existing files
        scan_directory(&watch_path, &parser, &analyzer, &tx_clone);

        // Start watching for changes
        let watcher_result = watcher::watch_directory(&watch_path);
        let (_watcher, file_rx) = match watcher_result {
            Ok(w) => w,
            Err(e) => {
                let _ = tx_clone.send(WsMessage::Error {
                    message: format!("Failed to start watcher: {}", e),
                });
                return;
            }
        };

        // Watch loop - runs forever until channel disconnects
        while let Ok(event) = file_rx.recv() {
            let events = watcher::filter_source_events(vec![event]);
            for ev in events {
                // Notify about file change immediately
                let _ = tx_clone.send(WsMessage::FileChanged {
                    path: ev.path.display().to_string(),
                    kind: format!("{:?}", ev.kind),
                });

                // Skip deleted files
                if matches!(ev.kind, FileEventKind::Deleted) {
                    continue;
                }

                // Analyze immediately
                let start = Instant::now();
                if let Ok(content) = std::fs::read_to_string(&ev.path)
                    && let Ok(parsed) = parser.parse_file(&ev.path, &content)
                    && let Ok(analysis) = analyzer.analyze_file(&parsed)
                {
                    let findings: Vec<FindingDto> =
                        analysis.findings.iter().map(FindingDto::from).collect();
                    let _ = tx_clone.send(WsMessage::AnalysisComplete {
                        path: ev.path.display().to_string(),
                        findings,
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
        }
    });
}

/// Scan directory for existing source files
fn scan_directory(
    path: &PathBuf,
    parser: &ParserEngine,
    analyzer: &AnalyzerEngine,
    tx: &broadcast::Sender<WsMessage>,
) {
    let extensions = ["rs", "js", "ts", "tsx", "jsx", "py", "go", "java"];

    let entries = walkdir::WalkDir::new(path)
        .max_depth(10)
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in entries {
        let file_path = entry.path();

        // Skip non-files and hidden/target directories
        if !file_path.is_file() {
            continue;
        }
        let path_str = file_path.to_string_lossy();
        if path_str.contains("/target/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/.")
        {
            continue;
        }

        // Check extension
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !extensions.contains(&ext) {
            continue;
        }

        // Analyze file
        let start = Instant::now();
        if let Ok(content) = std::fs::read_to_string(file_path)
            && let Ok(parsed) = parser.parse_file(file_path, &content)
            && let Ok(analysis) = analyzer.analyze_file(&parsed)
            && !analysis.findings.is_empty()
        {
            let findings: Vec<FindingDto> =
                analysis.findings.iter().map(FindingDto::from).collect();
            let _ = tx.send(WsMessage::AnalysisComplete {
                path: file_path.display().to_string(),
                findings,
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }
    }
}

async fn analyze_file(path: &str, tx: broadcast::Sender<WsMessage>) {
    let path = PathBuf::from(path);

    tokio::task::spawn_blocking(move || {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config.clone());
        let analyzer = AnalyzerEngine::new(config);

        let start = Instant::now();
        if let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(parsed) = parser.parse_file(&path, &content)
            && let Ok(analysis) = analyzer.analyze_file(&parsed)
        {
            let findings: Vec<FindingDto> =
                analysis.findings.iter().map(FindingDto::from).collect();
            let _ = tx.send(WsMessage::AnalysisComplete {
                path: path.display().to_string(),
                findings,
                duration_ms: start.elapsed().as_millis() as u64,
            });
        }
    })
    .await
    .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_dto_conversion() {
        let finding = Finding {
            id: "test".to_string(),
            rule_id: "rust/unsafe".to_string(),
            message: "Unsafe block".to_string(),
            severity: Severity::Warning,
            location: rma_common::SourceLocation::new(PathBuf::from("test.rs"), 10, 5, 10, 20),
            language: rma_common::Language::Rust,
            snippet: None,
            suggestion: None,
            fix: None,
            confidence: rma_common::Confidence::High,
            category: rma_common::FindingCategory::Security,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        };

        let dto = FindingDto::from(&finding);
        assert_eq!(dto.rule_id, "rust/unsafe");
        assert_eq!(dto.severity, "warning");
        assert_eq!(dto.line, 10);
    }
}
