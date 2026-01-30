//! Tantivy/Sled based indexing for Rust Monorepo Analyzer
//!
//! Provides fast full-text search and incremental updates.

pub mod search;
pub mod store;
pub mod watcher;

use anyhow::Result;
use rma_analyzer::FileAnalysis;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tantivy::schema::*;
use tantivy::{doc, Index, IndexWriter};
use tracing::{info, instrument};

/// Index configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    pub index_path: PathBuf,
    pub memory_budget: usize,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            index_path: PathBuf::from(".rma/index"),
            memory_budget: 50_000_000, // 50MB
        }
    }
}

/// The main indexer engine
pub struct IndexerEngine {
    index: Index,
    schema: Schema,
    config: Arc<IndexConfig>,
}

impl IndexerEngine {
    /// Create or open an index at the specified path
    #[instrument(skip_all)]
    pub fn new(config: IndexConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.index_path)?;

        let schema = build_schema();
        let index = Index::create_in_dir(&config.index_path, schema.clone())
            .or_else(|_| Index::open_in_dir(&config.index_path))?;

        info!("Index opened at {:?}", config.index_path);

        Ok(Self {
            index,
            schema,
            config: Arc::new(config),
        })
    }

    /// Index analysis results
    #[instrument(skip(self, results))]
    pub fn index_results(&self, results: &[FileAnalysis]) -> Result<usize> {
        let mut writer: IndexWriter = self.index.writer(self.config.memory_budget)?;

        let path_field = self.schema.get_field("path").unwrap();
        let language_field = self.schema.get_field("language").unwrap();
        let content_field = self.schema.get_field("content").unwrap();
        let findings_field = self.schema.get_field("findings").unwrap();
        let severity_field = self.schema.get_field("max_severity").unwrap();
        let complexity_field = self.schema.get_field("complexity").unwrap();
        let loc_field = self.schema.get_field("loc").unwrap();

        let mut indexed = 0;

        for result in results {
            let max_severity = result
                .findings
                .iter()
                .map(|f| severity_to_num(&f.severity))
                .max()
                .unwrap_or(0);

            let findings_json = serde_json::to_string(&result.findings)?;

            writer.add_document(doc!(
                path_field => result.path.clone(),
                language_field => result.language.to_string(),
                content_field => "", // Could store snippets here
                findings_field => findings_json,
                severity_field => max_severity as i64,
                complexity_field => result.metrics.cyclomatic_complexity as i64,
                loc_field => result.metrics.lines_of_code as i64,
            ))?;

            indexed += 1;
        }

        writer.commit()?;
        info!("Indexed {} files", indexed);

        Ok(indexed)
    }

    /// Search for files by query
    pub fn search(&self, query_str: &str, limit: usize) -> Result<Vec<SearchResult>> {
        search::execute_search(&self.index, &self.schema, query_str, limit)
    }

    /// Get statistics about the index
    pub fn stats(&self) -> Result<IndexStats> {
        let reader = self.index.reader()?;
        let searcher = reader.searcher();

        Ok(IndexStats {
            num_docs: searcher.num_docs() as usize,
            index_path: self.config.index_path.clone(),
        })
    }
}

/// Build the tantivy schema
fn build_schema() -> Schema {
    let mut builder = Schema::builder();

    builder.add_text_field("path", TEXT | STORED);
    builder.add_text_field("language", STRING | STORED);
    builder.add_text_field("content", TEXT);
    builder.add_text_field("findings", STORED);
    builder.add_i64_field("max_severity", INDEXED | STORED);
    builder.add_i64_field("complexity", INDEXED | STORED);
    builder.add_i64_field("loc", INDEXED | STORED);

    builder.build()
}

fn severity_to_num(severity: &rma_common::Severity) -> u8 {
    match severity {
        rma_common::Severity::Info => 0,
        rma_common::Severity::Warning => 1,
        rma_common::Severity::Error => 2,
        rma_common::Severity::Critical => 3,
    }
}

/// Search result from index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub path: String,
    pub language: String,
    pub score: f32,
    pub findings_count: usize,
}

/// Index statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub num_docs: usize,
    pub index_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_index() {
        let temp = TempDir::new().unwrap();
        let config = IndexConfig {
            index_path: temp.path().to_path_buf(),
            ..Default::default()
        };

        let indexer = IndexerEngine::new(config);
        assert!(indexer.is_ok());
    }
}
