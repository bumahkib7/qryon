//! Rule trait and base implementations for security vulnerability DETECTION

use crate::flow::FlowContext;
use rma_common::{Confidence, Finding, FindingCategory, Language};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// A security or code quality rule that DETECTS vulnerabilities
pub trait Rule: Send + Sync {
    /// Unique identifier for this rule
    fn id(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Languages this rule applies to
    fn applies_to(&self, lang: Language) -> bool;

    /// Check a parsed file and return any findings (detected vulnerabilities)
    fn check(&self, parsed: &ParsedFile) -> Vec<Finding>;

    /// Check with flow analysis context (symbol table + taint info)
    ///
    /// Flow-aware rules should override this to use taint and scope information.
    /// Default implementation falls back to `check()`.
    fn check_with_flow(&self, parsed: &ParsedFile, _flow: &FlowContext) -> Vec<Finding> {
        self.check(parsed)
    }

    /// Whether this rule uses flow analysis
    ///
    /// Rules that return true will receive a FlowContext in check_with_flow.
    /// This allows lazy construction of the symbol table only when needed.
    fn uses_flow(&self) -> bool {
        false
    }
}

/// Snippet extraction configuration based on context
#[derive(Debug, Clone, Copy)]
pub enum SnippetContext {
    /// Single-line pattern match (secret, simple issue) - show just that line
    SingleLine,
    /// Expression-level issue - show the expression + minimal context
    Expression,
    /// Statement-level issue - show the statement
    Statement,
    /// Block-level issue (control flow) - show the block structure
    Block,
    /// Function-level issue - show signature + relevant body part
    Function,
    /// Taint flow - show source and sink with path indication
    TaintFlow {
        source_line: usize,
        sink_line: usize,
    },
    /// Multi-line span - show all lines in the span
    MultiLine { start_line: usize, end_line: usize },
}

impl SnippetContext {
    /// Determine the best snippet context from a tree-sitter node
    pub fn from_node(node: &Node, rule_id: &str) -> Self {
        let start_line = node.start_position().row;
        let end_line = node.end_position().row;
        let line_span = end_line - start_line;
        let node_kind = node.kind();

        // Taint/injection rules need more context
        let is_flow_rule = rule_id.contains("injection")
            || rule_id.contains("taint")
            || rule_id.contains("xss")
            || rule_id.contains("traversal");

        // Single line - keep it simple
        if line_span == 0 {
            return Self::SingleLine;
        }

        // Flow rules with multi-line span - show the flow
        if is_flow_rule && line_span > 1 {
            return Self::MultiLine {
                start_line,
                end_line,
            };
        }

        // Determine by node type
        match node_kind {
            // Function definitions - show signature + context
            "function_declaration"
            | "function_definition"
            | "method_definition"
            | "fn_item"
            | "function_item"
            | "arrow_function" => Self::Function,

            // Block structures - show the block
            "if_statement" | "if_expression" | "for_statement" | "while_statement"
            | "try_statement" | "match_expression" | "switch_statement" => Self::Block,

            // Statements - show the statement
            "expression_statement"
            | "return_statement"
            | "variable_declaration"
            | "let_declaration"
            | "assignment_expression" => Self::Statement,

            // Expressions - minimal context
            "call_expression" | "member_expression" | "binary_expression" => Self::Expression,

            // Default based on line span
            _ => {
                if line_span <= 3 {
                    Self::MultiLine {
                        start_line,
                        end_line,
                    }
                } else if line_span <= 10 {
                    Self::Block
                } else {
                    Self::Function
                }
            }
        }
    }

    /// Get the maximum character limit for this context
    pub fn char_limit(&self) -> usize {
        match self {
            Self::SingleLine => 200,
            Self::Expression => 300,
            Self::Statement => 400,
            Self::Block => 800,
            Self::Function => 1200,
            Self::TaintFlow {
                source_line,
                sink_line,
            } => {
                // Scale based on distance
                let distance = sink_line.saturating_sub(*source_line);
                (300 + distance * 50).min(1500)
            }
            Self::MultiLine {
                start_line,
                end_line,
            } => {
                let lines = end_line.saturating_sub(*start_line) + 1;
                (lines * 100).clamp(200, 1000)
            }
        }
    }

    /// Get the number of context lines to show before/after
    pub fn context_lines(&self) -> usize {
        match self {
            Self::SingleLine => 0,
            Self::Expression => 1,
            Self::Statement => 1,
            Self::Block => 2,
            Self::Function => 3,
            Self::TaintFlow { .. } => 2,
            Self::MultiLine { .. } => 1,
        }
    }
}

/// Extract an intelligent snippet based on context
pub fn extract_smart_snippet(node: &Node, content: &str, rule_id: &str) -> Option<String> {
    let ctx = SnippetContext::from_node(node, rule_id);
    let limit = ctx.char_limit();
    let context_lines = ctx.context_lines();

    let text = node.utf8_text(content.as_bytes()).ok()?;
    let char_count = text.chars().count();

    // If within limit, return as-is (possibly with context)
    if char_count <= limit {
        if context_lines > 0 {
            // Add context lines from the source
            return Some(extract_with_context(node, content, context_lines));
        }
        return Some(text.to_string());
    }

    // Need to truncate - be smart about it
    match ctx {
        SnippetContext::SingleLine | SnippetContext::Expression => {
            // Simple truncation for small contexts
            let truncated: String = text.chars().take(limit).collect();
            Some(format!("{}...", truncated.trim_end()))
        }
        SnippetContext::Function => {
            // For functions: show signature + first few lines + "..." + last line
            extract_function_snippet(text, limit)
        }
        SnippetContext::Block => {
            // For blocks: show opening, some body, closing
            extract_block_snippet(text, limit)
        }
        SnippetContext::TaintFlow {
            source_line,
            sink_line,
        } => {
            // Show source line, ..., sink line
            extract_flow_snippet(content, source_line, sink_line, limit)
        }
        _ => {
            // Default: head + ... + tail
            extract_head_tail_snippet(text, limit)
        }
    }
}

/// Extract snippet with surrounding context lines
fn extract_with_context(node: &Node, content: &str, context_lines: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start_line = node.start_position().row;
    let end_line = node.end_position().row;

    let ctx_start = start_line.saturating_sub(context_lines);
    let ctx_end = (end_line + context_lines).min(lines.len().saturating_sub(1));

    lines[ctx_start..=ctx_end].join("\n")
}

/// Extract function snippet: signature + beginning + ... + end
fn extract_function_snippet(text: &str, limit: usize) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= 5 {
        return Some(text.to_string());
    }

    // Show first 3 lines (signature + start of body)
    let head: String = lines[..3].join("\n");
    // Show last 2 lines (end of body + closing brace)
    let tail: String = lines[lines.len() - 2..].join("\n");

    let result = format!(
        "{}\n    // ... ({} lines omitted)\n{}",
        head,
        lines.len() - 5,
        tail
    );

    if result.chars().count() <= limit {
        Some(result)
    } else {
        // Still too long, just truncate
        let truncated: String = text.chars().take(limit).collect();
        Some(format!("{}...", truncated))
    }
}

/// Extract block snippet: opening + some body + closing
fn extract_block_snippet(text: &str, limit: usize) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= 6 {
        return Some(text.to_string());
    }

    // Show first 2 lines + last 2 lines
    let head: String = lines[..2].join("\n");
    let tail: String = lines[lines.len() - 2..].join("\n");

    let result = format!("{}\n  // ... ({} lines)\n{}", head, lines.len() - 4, tail);

    if result.chars().count() <= limit {
        Some(result)
    } else {
        let truncated: String = text.chars().take(limit).collect();
        Some(format!("{}...", truncated))
    }
}

/// Extract taint flow snippet: source line → ... → sink line
fn extract_flow_snippet(
    content: &str,
    source_line: usize,
    sink_line: usize,
    limit: usize,
) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();

    if source_line >= lines.len() || sink_line >= lines.len() {
        return None;
    }

    let source = lines.get(source_line).unwrap_or(&"");
    let sink = lines.get(sink_line).unwrap_or(&"");
    let distance = sink_line.saturating_sub(source_line);

    let result = if distance <= 3 {
        // Close together - show all lines
        lines[source_line..=sink_line].join("\n")
    } else {
        // Far apart - show source, ..., sink
        format!(
            "{}\n  // ... taint flows through {} lines ...\n{}",
            source.trim(),
            distance - 1,
            sink.trim()
        )
    };

    if result.chars().count() <= limit {
        Some(result)
    } else {
        Some(format!(
            "{}...",
            result.chars().take(limit).collect::<String>()
        ))
    }
}

/// Extract head + ... + tail snippet
fn extract_head_tail_snippet(text: &str, limit: usize) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let total = chars.len();

    if total <= limit {
        return Some(text.to_string());
    }

    // Show 60% head, 40% tail
    let head_len = (limit * 6) / 10;
    let tail_len = limit - head_len - 20; // Reserve space for "..."

    let head: String = chars[..head_len].iter().collect();
    let tail: String = chars[total - tail_len..].iter().collect();

    Some(format!("{}...{}", head.trim_end(), tail.trim_start()))
}

/// Helper to create a finding from a line number (for line-based checks)
pub fn create_finding_at_line(
    rule_id: &str,
    path: &std::path::Path,
    line: usize,
    snippet: &str,
    severity: rma_common::Severity,
    message: &str,
    language: Language,
) -> Finding {
    let mut finding = Finding {
        id: format!("{}-{}-1", rule_id, line),
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        severity,
        location: rma_common::SourceLocation::new(path.to_path_buf(), line, 1, line, snippet.len()),
        language,
        snippet: Some(snippet.to_string()),
        suggestion: None,
        fix: None,
        confidence: Confidence::Medium,
        category: infer_category(rule_id),
        fingerprint: None,
        properties: None,
        occurrence_count: None,
        additional_locations: None,
    };
    finding.compute_fingerprint();
    finding
}

/// Helper to create a finding from a tree-sitter node
pub fn create_finding(
    rule_id: &str,
    node: &Node,
    path: &std::path::Path,
    content: &str,
    severity: rma_common::Severity,
    message: &str,
    language: Language,
) -> Finding {
    let start = node.start_position();
    let end = node.end_position();

    // Use intelligent snippet extraction based on context
    let snippet = extract_smart_snippet(node, content, rule_id);

    let mut finding = Finding {
        id: format!("{}-{}-{}", rule_id, start.row, start.column),
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        severity,
        location: rma_common::SourceLocation::new(
            path.to_path_buf(),
            start.row + 1,
            start.column + 1,
            end.row + 1,
            end.column + 1,
        ),
        language,
        snippet,
        suggestion: None,
        fix: None,
        confidence: Confidence::Medium,
        category: infer_category(rule_id),
        fingerprint: None,
        properties: None,
        occurrence_count: None,
        additional_locations: None,
    };
    finding.compute_fingerprint();
    finding
}

/// Create a finding with explicit confidence level
#[allow(clippy::too_many_arguments)]
pub fn create_finding_with_confidence(
    rule_id: &str,
    node: &Node,
    path: &std::path::Path,
    content: &str,
    severity: rma_common::Severity,
    message: &str,
    language: Language,
    confidence: Confidence,
) -> Finding {
    let mut finding = create_finding(rule_id, node, path, content, severity, message, language);
    finding.confidence = confidence;
    finding
}

/// Infer category from rule ID prefix
fn infer_category(rule_id: &str) -> FindingCategory {
    // Security patterns
    if rule_id.contains("injection")
        || rule_id.contains("xss")
        || rule_id.contains("unsafe")
        || rule_id.contains("secret")
        || rule_id.contains("crypto")
        || rule_id.contains("traversal")
        || rule_id.contains("eval")
        || rule_id.contains("exec")
        || rule_id.contains("transmute")
        || rule_id.contains("deserialization")
    {
        return FindingCategory::Security;
    }

    // Quality patterns
    if rule_id.contains("complexity")
        || rule_id.contains("long-function")
        || rule_id.contains("unwrap")
        || rule_id.contains("expect")
        || rule_id.contains("panic")
    {
        return FindingCategory::Quality;
    }

    // Style patterns
    if rule_id.contains("todo")
        || rule_id.contains("fixme")
        || rule_id.contains("console")
        || rule_id.contains("style")
    {
        return FindingCategory::Style;
    }

    // Default based on path prefix
    if rule_id.starts_with("security/") || rule_id.contains("/sql") || rule_id.contains("/command")
    {
        FindingCategory::Security
    } else if rule_id.starts_with("quality/") || rule_id.contains("/quality") {
        FindingCategory::Quality
    } else if rule_id.starts_with("style/") || rule_id.starts_with("generic/todo") {
        FindingCategory::Style
    } else {
        FindingCategory::Quality // Default to quality
    }
}
