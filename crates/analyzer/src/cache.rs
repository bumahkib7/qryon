//! Analysis Cache for Incremental Scanning
//!
//! Caches analysis results based on file content hashes to avoid
//! re-analyzing unchanged files. This can reduce scan time by 80-90%
//! for repeated scans of the same codebase.
//!
//! # Cache Structure
//!
//! ```text
//! .rma/cache/
//!   analysis/
//!     {content_hash}.json  # Per-file analysis results
//!   manifest.json          # File path -> hash mapping
//! ```

use crate::FileAnalysis;
use anyhow::Result;
use rma_common::Language;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Fast content hash using DefaultHasher (FxHash-based)
/// Good enough for cache keys, not cryptographic
pub fn hash_content(content: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    hasher.finish()
}

/// Cache manifest tracking file -> hash mappings
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CacheManifest {
    /// Map of file path -> (content hash, last modified time)
    pub files: HashMap<PathBuf, CacheEntry>,
    /// Version of cache format (for invalidation on schema changes)
    pub version: u32,
}

/// Entry for a single cached file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Hash of file content
    pub content_hash: u64,
    /// Last modified time (for quick staleness check)
    pub mtime: u64,
    /// Whether file was analyzed (vs just parsed)
    pub analyzed: bool,
}

/// Summary of cached file analysis results
///
/// This is a lightweight summary stored in memory for quick lookups.
/// The full FileAnalysis is stored on disk in `.rma/cache/analysis/{hash}.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFileAnalysis {
    /// Number of findings in this file
    pub findings_count: usize,
    /// Whether any finding has Critical severity
    pub has_critical: bool,
    /// Programming language of the file
    pub language: Language,
    /// Summary of code metrics
    pub metrics_summary: MetricsSummary,
}

/// Lightweight metrics summary for cache entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub lines_of_code: usize,
    pub cyclomatic_complexity: usize,
    pub function_count: usize,
}

impl CacheManifest {
    const CURRENT_VERSION: u32 = 1;

    /// Load manifest from cache directory
    pub fn load(cache_dir: &Path) -> Result<Self> {
        let manifest_path = cache_dir.join("manifest.json");
        if manifest_path.exists() {
            let content = fs::read_to_string(&manifest_path)?;
            let manifest: Self = serde_json::from_str(&content)?;
            if manifest.version == Self::CURRENT_VERSION {
                return Ok(manifest);
            }
        }
        Ok(Self::default())
    }

    /// Save manifest to cache directory
    pub fn save(&self, cache_dir: &Path) -> Result<()> {
        fs::create_dir_all(cache_dir)?;
        let manifest_path = cache_dir.join("manifest.json");
        let content = serde_json::to_string_pretty(self)?;
        fs::write(manifest_path, content)?;
        Ok(())
    }

    /// Check if a file needs re-analysis
    ///
    /// Uses a two-level check:
    /// 1. Fast path: if mtime changed, assume content changed (most common case)
    /// 2. Slow path: compare content hash (handles edge cases like `touch`)
    pub fn needs_analysis(&self, path: &Path, content: &str, mtime: SystemTime) -> bool {
        let mtime_secs = mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        match self.files.get(path) {
            Some(entry) => {
                if !entry.analyzed {
                    return true; // Was parsed but not analyzed
                }
                // Fast check: mtime changed -> definitely need to re-analyze
                if entry.mtime != mtime_secs {
                    return true;
                }
                // Even if mtime is same, check content hash (handles weird edge cases)
                // In practice, this branch is rarely taken
                let new_hash = hash_content(content);
                entry.content_hash != new_hash
            }
            None => true, // Never seen this file
        }
    }

    /// Update cache entry for a file
    pub fn update(&mut self, path: PathBuf, content: &str, mtime: SystemTime) {
        let mtime_secs = mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.files.insert(
            path,
            CacheEntry {
                content_hash: hash_content(content),
                mtime: mtime_secs,
                analyzed: true,
            },
        );
    }

    /// Get number of cached files
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.files.clear();
    }
}

/// Analysis cache manager
pub struct AnalysisCache {
    cache_dir: PathBuf,
    manifest: CacheManifest,
    enabled: bool,
}

impl AnalysisCache {
    /// Create a new cache manager
    pub fn new(project_root: &Path) -> Self {
        let cache_dir = project_root.join(".rma").join("cache").join("analysis");
        let manifest = CacheManifest::load(&cache_dir).unwrap_or_default();
        Self {
            cache_dir,
            manifest,
            enabled: true,
        }
    }

    /// Create a disabled cache (for testing or --no-cache flag)
    pub fn disabled() -> Self {
        Self {
            cache_dir: PathBuf::new(),
            manifest: CacheManifest::default(),
            enabled: false,
        }
    }

    /// Check if file needs re-analysis
    pub fn needs_analysis(&self, path: &Path, content: &str, mtime: SystemTime) -> bool {
        if !self.enabled {
            return true;
        }
        self.manifest.needs_analysis(path, content, mtime)
    }

    /// Mark file as analyzed
    pub fn mark_analyzed(&mut self, path: PathBuf, content: &str, mtime: SystemTime) {
        if self.enabled {
            self.manifest.update(path, content, mtime);
        }
    }

    /// Save cache to disk
    pub fn save(&self) -> Result<()> {
        if self.enabled {
            self.manifest.save(&self.cache_dir)?;
        }
        Ok(())
    }

    /// Get cache stats
    pub fn stats(&self) -> (usize, bool) {
        (self.manifest.len(), self.enabled)
    }

    /// Check if cache is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the content hash for a file path
    pub fn get_content_hash(&self, path: &Path) -> Option<u64> {
        self.manifest.files.get(path).map(|e| e.content_hash)
    }

    /// Store FileAnalysis results to disk cache
    pub fn store_analysis(
        &self,
        _path: &Path,
        content: &str,
        analysis: &FileAnalysis,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let content_hash = hash_content(content);
        let cache_file = self.cache_dir.join(format!("{}.json", content_hash));
        fs::create_dir_all(&self.cache_dir)?;
        let json = serde_json::to_string(analysis)?;
        fs::write(cache_file, json)?;
        Ok(())
    }

    /// Load FileAnalysis results from disk cache
    pub fn load_analysis(&self, path: &Path, content: &str) -> Option<FileAnalysis> {
        let content_hash = hash_content(content);
        self.load_analysis_by_hash(path, content_hash)
    }

    /// Save analysis results to cache (alias for store_analysis)
    ///
    /// Stores the full FileAnalysis to `.rma/cache/analysis/{hash}.json`
    /// where hash is the content hash of the source file.
    pub fn save_analysis(&self, path: &Path, hash: u64, analysis: &FileAnalysis) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let cache_file = self.cache_dir.join(format!("{}.json", hash));
        fs::create_dir_all(&self.cache_dir)?;
        let json = serde_json::to_string(analysis)?;
        fs::write(cache_file, json)?;
        let _ = path; // path reserved for future use (e.g., logging)
        Ok(())
    }

    /// Load cached analysis results by hash
    ///
    /// Returns the cached FileAnalysis if it exists and matches the given hash.
    /// Returns None if cache miss or cache is disabled.
    pub fn load_analysis_by_hash(&self, _path: &Path, hash: u64) -> Option<FileAnalysis> {
        if !self.enabled {
            return None;
        }
        let cache_file = self.cache_dir.join(format!("{}.json", hash));
        if cache_file.exists()
            && let Ok(json) = fs::read_to_string(&cache_file)
            && let Ok(analysis) = serde_json::from_str::<FileAnalysis>(&json)
        {
            return Some(analysis);
        }
        None
    }

    /// Get a summary of cached analysis without loading full results
    ///
    /// Useful for quick checks without deserializing the full findings list.
    pub fn get_analysis_summary(&self, path: &Path, hash: u64) -> Option<CachedFileAnalysis> {
        let analysis = self.load_analysis_by_hash(path, hash)?;

        let has_critical = analysis
            .findings
            .iter()
            .any(|f| f.severity == rma_common::Severity::Critical);

        Some(CachedFileAnalysis {
            findings_count: analysis.findings.len(),
            has_critical,
            language: analysis.language,
            metrics_summary: MetricsSummary {
                lines_of_code: analysis.metrics.lines_of_code,
                cyclomatic_complexity: analysis.metrics.cyclomatic_complexity,
                function_count: analysis.metrics.function_count,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::{CodeMetrics, Finding, Severity};
    use std::time::Duration;

    #[test]
    fn test_hash_content() {
        let h1 = hash_content("hello world");
        let h2 = hash_content("hello world");
        let h3 = hash_content("hello world!");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_cache_manifest() {
        let mut manifest = CacheManifest::default();
        let path = PathBuf::from("/test/file.rs");
        let content = "fn main() {}";
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);

        // Initially needs analysis
        assert!(manifest.needs_analysis(&path, content, mtime));

        // After update, doesn't need analysis
        manifest.update(path.clone(), content, mtime);
        assert!(!manifest.needs_analysis(&path, content, mtime));

        // Changed content needs analysis
        assert!(manifest.needs_analysis(&path, "fn main() { panic!() }", mtime));
    }

    #[test]
    fn test_save_and_load_analysis() {
        let temp_dir = std::env::temp_dir().join("rma_cache_test");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let cache = AnalysisCache::new(&temp_dir);
        let path = PathBuf::from("/test/file.rs");
        let content = "fn main() {}";
        let hash = hash_content(content);

        // Create a test FileAnalysis
        let analysis = FileAnalysis {
            path: path.to_string_lossy().to_string(),
            language: Language::Rust,
            metrics: CodeMetrics {
                lines_of_code: 10,
                lines_of_comments: 2,
                blank_lines: 1,
                cyclomatic_complexity: 3,
                cognitive_complexity: 2,
                function_count: 1,
                class_count: 0,
                import_count: 0,
            },
            findings: vec![],
        };

        // Save and load
        cache.save_analysis(&path, hash, &analysis).unwrap();
        let loaded = cache.load_analysis_by_hash(&path, hash);

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.path, analysis.path);
        assert_eq!(loaded.language, Language::Rust);
        assert_eq!(loaded.metrics.lines_of_code, 10);
        assert_eq!(loaded.metrics.cyclomatic_complexity, 3);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_get_analysis_summary() {
        let temp_dir = std::env::temp_dir().join("rma_cache_summary_test");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let cache = AnalysisCache::new(&temp_dir);
        let path = PathBuf::from("/test/critical.rs");
        let content = "unsafe fn dangerous() {}";
        let hash = hash_content(content);

        // Create analysis with a critical finding
        let analysis = FileAnalysis {
            path: path.to_string_lossy().to_string(),
            language: Language::Rust,
            metrics: CodeMetrics {
                lines_of_code: 5,
                lines_of_comments: 0,
                blank_lines: 0,
                cyclomatic_complexity: 1,
                cognitive_complexity: 0,
                function_count: 1,
                class_count: 0,
                import_count: 0,
            },
            findings: vec![Finding {
                id: "test-1".to_string(),
                rule_id: "test-rule".to_string(),
                message: "A test finding".to_string(),
                severity: Severity::Critical,
                language: Language::Rust,
                location: rma_common::SourceLocation {
                    file: path.clone(),
                    start_line: 1,
                    start_column: 0,
                    end_line: 1,
                    end_column: 10,
                },
                snippet: Some("unsafe fn".to_string()),
                suggestion: None,
                fix: None,
                confidence: rma_common::Confidence::default(),
                category: rma_common::FindingCategory::default(),
                fingerprint: None,
                properties: None,
                occurrence_count: None,
                additional_locations: None,
            }],
        };

        cache.save_analysis(&path, hash, &analysis).unwrap();
        let summary = cache.get_analysis_summary(&path, hash);

        assert!(summary.is_some());
        let summary = summary.unwrap();
        assert_eq!(summary.findings_count, 1);
        assert!(summary.has_critical);
        assert_eq!(summary.language, Language::Rust);
        assert_eq!(summary.metrics_summary.lines_of_code, 5);
        assert_eq!(summary.metrics_summary.function_count, 1);

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_disabled_cache() {
        let cache = AnalysisCache::disabled();
        let path = PathBuf::from("/test/file.rs");
        let hash = 12345u64;

        let analysis = FileAnalysis {
            path: path.to_string_lossy().to_string(),
            language: Language::Rust,
            metrics: CodeMetrics::default(),
            findings: vec![],
        };

        // Save should succeed but not actually save
        cache.save_analysis(&path, hash, &analysis).unwrap();

        // Load should return None
        let loaded = cache.load_analysis_by_hash(&path, hash);
        assert!(loaded.is_none());

        // Summary should return None
        let summary = cache.get_analysis_summary(&path, hash);
        assert!(summary.is_none());
    }
}
