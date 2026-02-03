//! Code metrics computation

use rma_common::{CodeMetrics, Language};
use rma_parser::{AstVisitor, ParsedFile, traverse_ast};
use tree_sitter::Node;

/// Compute metrics for a parsed file
pub fn compute_metrics(parsed: &ParsedFile) -> CodeMetrics {
    let mut collector = MetricsCollector::new(parsed.language);
    traverse_ast(&parsed.tree, &parsed.content, &mut collector);

    // Count lines
    let mut loc = 0;
    let mut comments = 0;
    let mut blank = 0;

    for line in parsed.content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            blank += 1;
        } else if is_comment_line(trimmed, parsed.language) {
            comments += 1;
        } else {
            loc += 1;
        }
    }

    CodeMetrics {
        lines_of_code: loc,
        lines_of_comments: comments,
        blank_lines: blank,
        cyclomatic_complexity: collector.complexity.max(1),
        cognitive_complexity: collector.cognitive_complexity,
        function_count: collector.function_count,
        class_count: collector.class_count,
        import_count: collector.import_count,
    }
}

struct MetricsCollector {
    language: Language,
    complexity: usize,
    cognitive_complexity: usize,
    nesting_depth: usize,
    function_count: usize,
    class_count: usize,
    import_count: usize,
}

impl MetricsCollector {
    fn new(language: Language) -> Self {
        Self {
            language,
            complexity: 1,
            cognitive_complexity: 0,
            nesting_depth: 0,
            function_count: 0,
            class_count: 0,
            import_count: 0,
        }
    }

    /// Check if a node kind represents a branching construct that increases complexity
    fn is_branch(&self, kind: &str) -> bool {
        match self.language {
            Language::Rust => matches!(
                kind,
                "if_expression"
                    | "match_expression"
                    | "while_expression"
                    | "for_expression"
                    | "loop_expression"
                    | "binary_expression"
            ),
            Language::JavaScript | Language::TypeScript => matches!(
                kind,
                "if_statement"
                    | "switch_statement"
                    | "while_statement"
                    | "for_statement"
                    | "for_in_statement"
                    | "do_statement"
                    | "ternary_expression"
                    | "catch_clause"
            ),
            Language::Python => matches!(
                kind,
                "if_statement"
                    | "for_statement"
                    | "while_statement"
                    | "try_statement"
                    | "except_clause"
                    | "with_statement"
                    | "list_comprehension"
            ),
            Language::Go => matches!(
                kind,
                "if_statement"
                    | "for_statement"
                    | "switch_statement"
                    | "select_statement"
                    | "type_switch_statement"
            ),
            Language::Java => matches!(
                kind,
                "if_statement"
                    | "for_statement"
                    | "while_statement"
                    | "do_statement"
                    | "switch_expression"
                    | "catch_clause"
                    | "ternary_expression"
            ),
            // Default for other languages - no complexity analysis
            _ => false,
        }
    }

    /// Check if a node kind increases nesting depth for cognitive complexity
    fn increases_nesting(&self, kind: &str) -> bool {
        match self.language {
            Language::Rust => matches!(
                kind,
                "function_item" | "if_expression" | "match_expression" | "loop_expression"
            ),
            Language::JavaScript | Language::TypeScript => matches!(
                kind,
                "function_declaration"
                    | "arrow_function"
                    | "if_statement"
                    | "switch_statement"
                    | "class_declaration"
            ),
            Language::Python => matches!(
                kind,
                "function_definition" | "class_definition" | "if_statement" | "for_statement"
            ),
            _ => false,
        }
    }

    /// Check if a node kind represents a function definition
    fn is_function(&self, kind: &str) -> bool {
        match self.language {
            Language::Rust => matches!(kind, "function_item"),
            Language::JavaScript | Language::TypeScript => {
                matches!(
                    kind,
                    "function_declaration" | "method_definition" | "arrow_function"
                )
            }
            Language::Python => kind == "function_definition",
            Language::Go => matches!(kind, "function_declaration" | "method_declaration"),
            Language::Java => matches!(kind, "method_declaration" | "constructor_declaration"),
            // Default for other languages
            _ => false,
        }
    }

    /// Check if a node kind represents a class/struct definition
    fn is_class(&self, kind: &str) -> bool {
        match self.language {
            Language::Rust => matches!(kind, "struct_item" | "enum_item"),
            Language::JavaScript | Language::TypeScript => kind == "class_declaration",
            Language::Python => kind == "class_definition",
            Language::Go => kind == "type_declaration",
            Language::Java => matches!(kind, "class_declaration" | "interface_declaration"),
            // Default for other languages
            _ => false,
        }
    }

    /// Check if a node kind represents an import statement
    fn is_import(&self, kind: &str) -> bool {
        match self.language {
            Language::Rust => matches!(kind, "use_declaration" | "extern_crate_declaration"),
            Language::JavaScript | Language::TypeScript => kind == "import_statement",
            Language::Python => matches!(kind, "import_statement" | "import_from_statement"),
            Language::Go => kind == "import_declaration",
            Language::Java => kind == "import_declaration",
            // Default for other languages
            _ => false,
        }
    }
}

impl AstVisitor for MetricsCollector {
    fn visit_node(&mut self, node: Node, _content: &str) {
        let kind = node.kind();

        if self.is_branch(kind) {
            self.complexity += 1;
            self.cognitive_complexity += 1 + self.nesting_depth;
        }

        if self.increases_nesting(kind) {
            self.nesting_depth += 1;
        }

        if self.is_function(kind) {
            self.function_count += 1;
        }

        if self.is_class(kind) {
            self.class_count += 1;
        }

        if self.is_import(kind) {
            self.import_count += 1;
        }
    }
}

/// Check if a line is a comment
fn is_comment_line(line: &str, language: Language) -> bool {
    match language {
        Language::Rust
        | Language::Go
        | Language::Java
        | Language::JavaScript
        | Language::TypeScript => {
            line.starts_with("//") || line.starts_with("/*") || line.starts_with('*')
        }
        Language::Python | Language::Ruby | Language::Bash => {
            line.starts_with('#') || line.starts_with("\"\"\"") || line.starts_with("'''")
        }
        // Default: C-style comments for most languages
        _ => {
            line.starts_with("//")
                || line.starts_with("/*")
                || line.starts_with('*')
                || line.starts_with('#')
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::RmaConfig;
    use rma_parser::ParserEngine;
    use std::path::Path;

    #[test]
    fn test_rust_metrics() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
fn main() {
    if true {
        println!("yes");
    } else {
        println!("no");
    }
}

fn other() {
    for i in 0..10 {
        println!("{}", i);
    }
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let metrics = compute_metrics(&parsed);

        assert_eq!(metrics.function_count, 2);
        assert!(metrics.cyclomatic_complexity >= 3);
    }
}
