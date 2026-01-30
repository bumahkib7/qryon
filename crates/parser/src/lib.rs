//! Tree-sitter based polyglot parser for Rust Monorepo Analyzer
//!
//! This crate provides high-performance parallel parsing of source code
//! using tree-sitter grammars for multiple languages.

pub mod languages;
pub mod walker;

use anyhow::{Context, Result};
use rayon::prelude::*;
use rma_common::{Language, RmaConfig, RmaError, SourceLocation};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use tree_sitter::{Node, Parser, Tree};

/// A parsed source file with its AST
#[derive(Debug)]
pub struct ParsedFile {
    pub path: PathBuf,
    pub language: Language,
    pub content: String,
    pub tree: Tree,
    pub parse_errors: Vec<ParseError>,
}

/// A parsing error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseError {
    pub location: SourceLocation,
    pub message: String,
}

/// Statistics from a parsing operation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParseStats {
    pub files_parsed: usize,
    pub files_failed: usize,
    pub files_skipped: usize,
    pub total_bytes: usize,
    pub parse_errors: usize,
}

/// The main parser engine
pub struct ParserEngine {
    config: Arc<RmaConfig>,
}

impl ParserEngine {
    /// Create a new parser engine with the given configuration
    pub fn new(config: RmaConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Parse a single file
    #[instrument(skip(self, content), fields(path = %path.display()))]
    pub fn parse_file(&self, path: &Path, content: &str) -> Result<ParsedFile> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let language = Language::from_extension(ext);

        if language == Language::Unknown {
            return Err(RmaError::UnsupportedLanguage(ext.to_string()).into());
        }

        let mut parser = Parser::new();
        let ts_language = languages::get_language(language)?;
        parser.set_language(&ts_language)?;

        let tree = parser
            .parse(content, None)
            .context("Failed to parse file")?;

        let parse_errors = collect_parse_errors(&tree, path, content);

        debug!(
            "Parsed {} ({}) - {} errors",
            path.display(),
            language,
            parse_errors.len()
        );

        Ok(ParsedFile {
            path: path.to_path_buf(),
            language,
            content: content.to_string(),
            tree,
            parse_errors,
        })
    }

    /// Parse all supported files in a directory tree in parallel
    #[instrument(skip(self))]
    pub fn parse_directory(&self, root: &Path) -> Result<(Vec<ParsedFile>, ParseStats)> {
        info!("Starting parallel parse of {}", root.display());

        let files = walker::collect_files(root, &self.config)?;
        info!("Found {} files to parse", files.len());

        let results: Vec<_> = files
            .par_iter()
            .filter_map(|path| {
                match std::fs::read_to_string(path) {
                    Ok(content) => {
                        if content.len() > self.config.max_file_size {
                            warn!("Skipping large file: {}", path.display());
                            return None;
                        }
                        Some((path.clone(), content))
                    }
                    Err(e) => {
                        warn!("Failed to read {}: {}", path.display(), e);
                        None
                    }
                }
            })
            .map(|(path, content)| {
                let result = self.parse_file(&path, &content);
                (path, result, content.len())
            })
            .collect();

        let mut parsed_files = Vec::new();
        let mut stats = ParseStats::default();

        for (path, result, bytes) in results {
            match result {
                Ok(parsed) => {
                    stats.parse_errors += parsed.parse_errors.len();
                    stats.total_bytes += bytes;
                    stats.files_parsed += 1;
                    parsed_files.push(parsed);
                }
                Err(e) => {
                    if e.downcast_ref::<RmaError>()
                        .map(|e| matches!(e, RmaError::UnsupportedLanguage(_)))
                        .unwrap_or(false)
                    {
                        stats.files_skipped += 1;
                    } else {
                        debug!("Failed to parse {}: {}", path.display(), e);
                        stats.files_failed += 1;
                    }
                }
            }
        }

        info!(
            "Parsing complete: {} parsed, {} failed, {} skipped",
            stats.files_parsed, stats.files_failed, stats.files_skipped
        );

        Ok((parsed_files, stats))
    }
}

/// Collect parse errors from a tree-sitter tree
fn collect_parse_errors(tree: &Tree, path: &Path, content: &str) -> Vec<ParseError> {
    let mut errors = Vec::new();
    let mut cursor = tree.walk();

    collect_errors_recursive(&mut cursor, path, content, &mut errors);

    errors
}

fn collect_errors_recursive(
    cursor: &mut tree_sitter::TreeCursor,
    path: &Path,
    _content: &str,
    errors: &mut Vec<ParseError>,
) {
    let node = cursor.node();

    if node.is_error() || node.is_missing() {
        let start = node.start_position();
        let end = node.end_position();

        errors.push(ParseError {
            location: SourceLocation::new(
                path.to_path_buf(),
                start.row + 1,
                start.column + 1,
                end.row + 1,
                end.column + 1,
            ),
            message: if node.is_missing() {
                format!("Missing {}", node.kind())
            } else {
                "Syntax error".to_string()
            },
        });
    }

    if cursor.goto_first_child() {
        loop {
            collect_errors_recursive(cursor, path, _content, errors);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Helper trait for AST traversal
pub trait AstVisitor {
    fn visit_node(&mut self, node: Node, content: &str);
}

/// Traverse an AST with a visitor
pub fn traverse_ast<V: AstVisitor>(tree: &Tree, content: &str, visitor: &mut V) {
    let mut cursor = tree.walk();
    traverse_recursive(&mut cursor, content, visitor);
}

fn traverse_recursive<V: AstVisitor>(
    cursor: &mut tree_sitter::TreeCursor,
    content: &str,
    visitor: &mut V,
) {
    let node = cursor.node();
    visitor.visit_node(node, content);

    if cursor.goto_first_child() {
        loop {
            traverse_recursive(cursor, content, visitor);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rust_file() {
        let engine = ParserEngine::new(RmaConfig::default());
        let content = r#"
fn main() {
    println!("Hello, world!");
}
"#;
        let result = engine.parse_file(Path::new("test.rs"), content);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.language, Language::Rust);
        assert!(parsed.parse_errors.is_empty());
    }

    #[test]
    fn test_parse_python_file() {
        let engine = ParserEngine::new(RmaConfig::default());
        let content = r#"
def hello():
    print("Hello, world!")

if __name__ == "__main__":
    hello()
"#;
        let result = engine.parse_file(Path::new("test.py"), content);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.language, Language::Python);
    }

    #[test]
    fn test_parse_javascript_file() {
        let engine = ParserEngine::new(RmaConfig::default());
        let content = r#"
function hello() {
    console.log("Hello, world!");
}
hello();
"#;
        let result = engine.parse_file(Path::new("test.js"), content);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.language, Language::JavaScript);
    }

    #[test]
    fn test_unsupported_language() {
        let engine = ParserEngine::new(RmaConfig::default());
        let result = engine.parse_file(Path::new("test.xyz"), "content");
        assert!(result.is_err());
    }
}
