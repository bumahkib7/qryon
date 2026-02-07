//! Tree-sitter AST matching for rule engine
//!
//! Executes pre-compiled tree-sitter S-expression queries against source code,
//! providing structural (AST-level) matching instead of regex-based matching.
//! This handles multi-line patterns naturally since it matches AST nodes.

use rma_common::Language;
use std::collections::HashMap;

/// A tree-sitter based matcher that executes S-expression queries
#[derive(Debug)]
pub struct TreeSitterMatcher {
    query_str: String,
    #[allow(dead_code)]
    capture_names: Vec<String>,
}

/// A single match from a tree-sitter query execution
#[derive(Debug)]
pub struct TsMatch {
    /// 1-based line number of the match
    pub line: usize,
    /// Byte offset of the match start
    pub start_byte: usize,
    /// Byte offset of the match end
    pub end_byte: usize,
    /// The matched source text
    pub text: String,
    /// Named capture bindings (capture_name -> matched text)
    pub bindings: HashMap<String, String>,
}

impl TreeSitterMatcher {
    /// Create a new tree-sitter matcher from a query string and capture names
    pub fn new(query: String, captures: Vec<String>) -> Self {
        Self {
            query_str: query,
            capture_names: captures,
        }
    }

    /// Execute the tree-sitter query against source code and return matches.
    ///
    /// Returns empty vec if the language has no grammar or the query is invalid.
    #[cfg(feature = "tree-sitter-matching")]
    pub fn find_matches(&self, code: &str, language: Language) -> Vec<TsMatch> {
        use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

        // Get the tree-sitter grammar for this language
        let ts_lang = match rma_parser::languages::get_language(language) {
            Ok(lang) => lang,
            Err(_) => return Vec::new(),
        };

        // Parse the source code
        let mut parser = Parser::new();
        if parser.set_language(&ts_lang).is_err() {
            return Vec::new();
        }

        let tree = match parser.parse(code, None) {
            Some(t) => t,
            None => return Vec::new(),
        };

        // Compile the query
        let query = match Query::new(&ts_lang, &self.query_str) {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };

        // Execute query using StreamingIterator (tree-sitter 0.25 API)
        let mut cursor = QueryCursor::new();
        let root = tree.root_node();
        let mut matches = cursor.matches(&query, root, code.as_bytes());

        let mut results = Vec::new();

        loop {
            matches.advance();
            let m = match matches.get() {
                Some(m) => m,
                None => break,
            };

            let mut bindings = HashMap::new();
            let mut match_start = usize::MAX;
            let mut match_end = 0usize;
            let mut match_text = String::new();

            for capture in m.captures {
                let name = &query.capture_names()[capture.index as usize];
                let node = capture.node;
                let text = &code[node.start_byte()..node.end_byte()];

                bindings.insert(name.to_string(), text.to_string());

                // Track the overall match span (union of all captures)
                if node.start_byte() < match_start {
                    match_start = node.start_byte();
                }
                if node.end_byte() > match_end {
                    match_end = node.end_byte();
                    // Use the outermost capture's text as the match text
                    match_text = text.to_string();
                }
            }

            if match_start < usize::MAX {
                // Compute 1-based line number from byte offset
                let line = code[..match_start].matches('\n').count() + 1;

                results.push(TsMatch {
                    line,
                    start_byte: match_start,
                    end_byte: match_end,
                    text: match_text,
                    bindings,
                });
            }
        }

        results
    }

    /// Stub when tree-sitter feature is disabled — always returns empty
    #[cfg(not(feature = "tree-sitter-matching"))]
    pub fn find_matches(&self, _code: &str, _language: Language) -> Vec<TsMatch> {
        Vec::new()
    }

    /// Check whether the given language has a tree-sitter grammar available
    #[cfg(feature = "tree-sitter-matching")]
    pub fn has_grammar(language: Language) -> bool {
        rma_parser::languages::has_grammar(language)
    }

    /// Stub when tree-sitter feature is disabled
    #[cfg(not(feature = "tree-sitter-matching"))]
    pub fn has_grammar(_language: Language) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "tree-sitter-matching")]
    fn test_tree_sitter_call_pattern_python() {
        let matcher = TreeSitterMatcher::new(
            r#"(call function: (identifier) @func (#eq? @func "dangerous") arguments: (argument_list) @args)"#.to_string(),
            vec!["@func".to_string()],
        );
        let matches = matcher.find_matches("x = dangerous(user_input)", Language::Python);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].line, 1);
        assert!(matches[0].bindings.contains_key("func"));
        assert_eq!(matches[0].bindings["func"], "dangerous");
    }

    #[test]
    #[cfg(feature = "tree-sitter-matching")]
    fn test_tree_sitter_no_match() {
        let matcher = TreeSitterMatcher::new(
            r#"(call function: (identifier) @func (#eq? @func "dangerous") arguments: (argument_list) @args)"#.to_string(),
            vec!["@func".to_string()],
        );
        let matches = matcher.find_matches("x = safe_func(user_input)", Language::Python);
        assert!(matches.is_empty());
    }

    #[test]
    #[cfg(feature = "tree-sitter-matching")]
    fn test_tree_sitter_multiline_match() {
        let matcher = TreeSitterMatcher::new(
            r#"(call function: (identifier) @func (#eq? @func "dangerous") arguments: (argument_list) @args)"#.to_string(),
            vec!["@func".to_string()],
        );
        let code = r#"x = dangerous(
    user_input,
    extra_arg
)"#;
        let matches = matcher.find_matches(code, Language::Python);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].line, 1);
    }

    #[test]
    #[cfg(feature = "tree-sitter-matching")]
    fn test_tree_sitter_unsupported_language() {
        let matcher = TreeSitterMatcher::new(
            r#"(call function: (identifier) @func)"#.to_string(),
            vec![],
        );
        // Unknown language should return empty
        let matches = matcher.find_matches("some code", Language::Unknown);
        assert!(matches.is_empty());
    }

    #[test]
    #[cfg(feature = "tree-sitter-matching")]
    fn test_tree_sitter_javascript_call() {
        // Tests that JS call_expression queries work for security-relevant functions
        let matcher = TreeSitterMatcher::new(
            r#"(call_expression function: (identifier) @func (#eq? @func "setTimeout") arguments: (arguments) @args)"#.to_string(),
            vec!["@func".to_string()],
        );
        let matches = matcher.find_matches("setTimeout(callback, 1000)", Language::JavaScript);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].bindings["func"], "setTimeout");
    }

    #[test]
    #[cfg(feature = "tree-sitter-matching")]
    fn test_has_grammar() {
        assert!(TreeSitterMatcher::has_grammar(Language::Python));
        assert!(TreeSitterMatcher::has_grammar(Language::JavaScript));
        assert!(TreeSitterMatcher::has_grammar(Language::Rust));
        assert!(!TreeSitterMatcher::has_grammar(Language::Unknown));
    }
}
