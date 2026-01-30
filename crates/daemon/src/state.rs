//! Application state for the daemon

use rma_analyzer::AnalyzerEngine;
use rma_common::RmaConfig;
use rma_parser::ParserEngine;
use std::collections::HashMap;
use std::path::PathBuf;

/// Shared application state
pub struct AppState {
    pub config: RmaConfig,
    pub parser: ParserEngine,
    pub analyzer: AnalyzerEngine,
    pub scan_cache: HashMap<PathBuf, CachedScan>,
}

impl AppState {
    pub fn new(config: RmaConfig) -> Self {
        Self {
            parser: ParserEngine::new(config.clone()),
            analyzer: AnalyzerEngine::new(config.clone()),
            config,
            scan_cache: HashMap::new(),
        }
    }
}

/// Cached scan result
pub struct CachedScan {
    pub timestamp: std::time::Instant,
    pub hash: String,
    pub findings_count: usize,
}
