//! File system walker for discovering source files

use anyhow::Result;
use ignore::WalkBuilder;
use rma_common::{Language, RmaConfig};
use std::path::{Path, PathBuf};
use tracing::{debug, trace};

/// Collect all source files from a directory tree
pub fn collect_files(root: &Path, config: &RmaConfig) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(true)  // Skip hidden files by default
        .git_ignore(true)  // Respect .gitignore
        .git_global(true)
        .git_exclude(true)
        .follow_links(false)
        .build();

    let supported_extensions: Vec<&str> = if config.languages.is_empty() {
        // All supported languages
        vec!["rs", "js", "mjs", "cjs", "ts", "tsx", "py", "pyi", "go", "java"]
    } else {
        config
            .languages
            .iter()
            .flat_map(|l| l.extensions().iter().copied())
            .collect()
    };

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();

        // Skip directories
        if path.is_dir() {
            continue;
        }

        // Check extension
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        if !supported_extensions.contains(&ext) {
            trace!("Skipping unsupported extension: {}", path.display());
            continue;
        }

        // Check exclude patterns
        let path_str = path.to_string_lossy();
        let excluded = config.exclude_patterns.iter().any(|pattern| {
            glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
        });

        if excluded {
            debug!("Excluded by pattern: {}", path.display());
            continue;
        }

        files.push(path.to_path_buf());
    }

    // Sort for deterministic ordering
    files.sort();

    Ok(files)
}

/// Check if a path should be excluded based on patterns
pub fn is_excluded(path: &Path, patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    patterns.iter().any(|pattern| {
        glob::Pattern::new(pattern)
            .map(|p| p.matches(&path_str))
            .unwrap_or(false)
    })
}

/// Get language stats from a list of files
pub fn language_stats(files: &[PathBuf]) -> std::collections::HashMap<Language, usize> {
    let mut stats = std::collections::HashMap::new();

    for file in files {
        let ext = file
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let lang = Language::from_extension(ext);
        *stats.entry(lang).or_insert(0) += 1;
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_collect_files() {
        let temp = TempDir::new().unwrap();

        // Create test files
        fs::write(temp.path().join("test.rs"), "fn main() {}").unwrap();
        fs::write(temp.path().join("test.py"), "def main(): pass").unwrap();
        fs::write(temp.path().join("test.txt"), "ignored").unwrap();

        let config = RmaConfig::default();
        let files = collect_files(temp.path(), &config).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|p| p.extension().unwrap() == "rs"));
        assert!(files.iter().any(|p| p.extension().unwrap() == "py"));
    }

    #[test]
    fn test_language_stats() {
        let files = vec![
            PathBuf::from("a.rs"),
            PathBuf::from("b.rs"),
            PathBuf::from("c.py"),
            PathBuf::from("d.js"),
        ];

        let stats = language_stats(&files);

        assert_eq!(stats.get(&Language::Rust), Some(&2));
        assert_eq!(stats.get(&Language::Python), Some(&1));
        assert_eq!(stats.get(&Language::JavaScript), Some(&1));
    }
}
