//! API endpoints for the daemon

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use rma_analyzer::FileAnalysis;
use rma_common::Language;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use super::state::AppState;

/// Scan request
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub path: PathBuf,
    pub incremental: Option<bool>,
}

/// Scan response
#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub files_analyzed: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub duration_ms: u64,
}

/// Analyze file request
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    pub path: PathBuf,
    pub content: String,
}

/// Search query params
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    pub limit: Option<usize>,
}

/// Search response
#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub path: String,
    pub language: String,
    pub findings_count: usize,
}

/// Stats response
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub index_docs: usize,
    pub cache_entries: usize,
}

/// POST /api/v1/scan - Scan a directory
pub async fn scan_endpoint(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let start = std::time::Instant::now();

    info!("Scanning: {:?}", request.path);

    let state = state.read().await;

    let (parsed_files, _parse_stats) = state
        .parser
        .parse_directory(&request.path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (results, summary) = state
        .analyzer
        .analyze_files(&parsed_files)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let duration = start.elapsed();

    Ok(Json(ScanResponse {
        files_analyzed: summary.files_analyzed,
        total_findings: summary.total_findings,
        critical_count: summary.critical_count,
        error_count: summary.error_count,
        warning_count: summary.warning_count,
        duration_ms: duration.as_millis() as u64,
    }))
}

/// POST /api/v1/analyze - Analyze a single file
pub async fn analyze_file_endpoint(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<FileAnalysis>, (StatusCode, String)> {
    let state = state.read().await;

    let parsed = state
        .parser
        .parse_file(&request.path, &request.content)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let analysis = state
        .analyzer
        .analyze_file(&parsed)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(analysis))
}

/// GET /api/v1/search - Search indexed files
pub async fn search_endpoint(
    State(_state): State<Arc<RwLock<AppState>>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, (StatusCode, String)> {
    // For now, return empty results - full implementation would use the indexer
    info!("Search query: {}", query.q);

    Ok(Json(SearchResponse {
        results: vec![],
    }))
}

/// GET /api/v1/stats - Get daemon statistics
pub async fn stats_endpoint(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Result<Json<StatsResponse>, (StatusCode, String)> {
    let state = state.read().await;

    Ok(Json(StatsResponse {
        index_docs: 0, // Would query indexer
        cache_entries: state.scan_cache.len(),
    }))
}
