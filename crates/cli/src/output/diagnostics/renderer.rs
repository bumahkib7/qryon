//! Rich diagnostic renderer implementation
//!
//! Produces rustc-style diagnostic output with:
//! - Error codes (RMA-S001, etc.)
//! - Source context with line numbers
//! - Underline highlighting
//! - Notes and help messages

use super::{DiagnosticRenderer, codes::REGISTRY, source::SourceCache, spans::SpanRenderer};
use colored::Colorize;
use rma_common::{Finding, Severity};

/// Configuration for the rich diagnostic renderer
#[derive(Debug, Clone)]
pub struct RichDiagnosticConfig {
    /// Number of context lines to show before/after the span
    pub context_lines: usize,
    /// Whether to show the rule note
    pub show_notes: bool,
    /// Whether to show help/suggestions
    pub show_help: bool,
    /// Maximum line width before truncation (0 = no limit)
    pub max_line_width: usize,
}

impl Default for RichDiagnosticConfig {
    fn default() -> Self {
        Self {
            context_lines: 2,
            show_notes: true,
            show_help: true,
            max_line_width: 0,
        }
    }
}

/// Rich diagnostic renderer that produces rustc-style output
pub struct RichDiagnosticRenderer {
    config: RichDiagnosticConfig,
}

impl RichDiagnosticRenderer {
    /// Create a new renderer with default configuration
    pub fn new() -> Self {
        Self {
            config: RichDiagnosticConfig::default(),
        }
    }

    /// Create a renderer with custom configuration
    pub fn with_config(config: RichDiagnosticConfig) -> Self {
        Self { config }
    }

    /// Format the severity header with error code
    fn format_header(&self, finding: &Finding) -> String {
        let code = REGISTRY.get(&finding.rule_id);
        let severity_str = Self::severity_word(finding.severity);
        let code_str = &code.code;

        match finding.severity {
            Severity::Critical => {
                format!(
                    "{}[{}]: {}",
                    severity_str.red().bold(),
                    code_str.red().bold(),
                    finding.message
                )
            }
            Severity::Error => {
                format!(
                    "{}[{}]: {}",
                    severity_str.red().bold(),
                    code_str.red().bold(),
                    finding.message
                )
            }
            Severity::Warning => {
                format!(
                    "{}[{}]: {}",
                    severity_str.yellow().bold(),
                    code_str.yellow().bold(),
                    finding.message
                )
            }
            Severity::Info => {
                format!(
                    "{}[{}]: {}",
                    severity_str.blue().bold(),
                    code_str.blue().bold(),
                    finding.message
                )
            }
        }
    }

    /// Get the severity word
    fn severity_word(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "critical",
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }

    /// Format the location line
    fn format_location(&self, finding: &Finding) -> String {
        let loc = &finding.location;
        format!(
            "  {} {}:{}:{}",
            "-->".blue().bold(),
            loc.file.display(),
            loc.start_line,
            loc.start_column
        )
    }

    /// Format notes section
    fn format_notes(&self, finding: &Finding) -> String {
        if !self.config.show_notes {
            return String::new();
        }

        format!(
            "   {} {}: rule: {}",
            "=".blue().bold(),
            "note".bold(),
            finding.rule_id.dimmed()
        )
    }

    /// Format help section
    fn format_help(&self, finding: &Finding) -> Option<String> {
        if !self.config.show_help {
            return None;
        }

        finding.suggestion.as_ref().map(|suggestion| {
            format!(
                "   {} {}: {}",
                "=".blue().bold(),
                "help".bold(),
                suggestion.green()
            )
        })
    }

    /// Get a label for the span based on severity and rule
    fn get_span_label(&self, finding: &Finding) -> Option<String> {
        // Generate contextual labels based on rule type
        let label = match finding.rule_id.as_str() {
            "rust/unsafe-block" => "unsafe block here",
            "rust/unwrap-used" | "rust/expect-used" => "this can panic",
            "rust/panic-used" => "explicit panic",
            "rust/transmute-used" => "type transmutation here",
            "rust/sql-injection" | "js/sql-injection" | "python/sql-injection" => {
                "SQL query built from untrusted input"
            }
            "rust/command-injection" | "js/command-injection" | "python/shell-injection" => {
                "shell command built from untrusted input"
            }
            "js/eval-usage" | "js/dynamic-code-execution" => "dynamic code execution",
            "js/innerhtml-xss" | "js/innerHTML-usage" => "XSS sink - sanitize input",
            "js/innerhtml-read" => "HTML property read",
            "python/exec-usage" | "python/eval-usage" | "python/dynamic-execution" => {
                "dynamic code execution"
            }
            "generic/hardcoded-secret" | "python/hardcoded-secret" => "secret value here",
            "generic/todo-fixme" => "incomplete code marker",
            "generic/long-function" => "function too long",
            "generic/high-complexity" => "high cyclomatic complexity",
            _ => return None,
        };
        Some(label.to_string())
    }
}

impl Default for RichDiagnosticRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagnosticRenderer for RichDiagnosticRenderer {
    fn render(&self, finding: &Finding, cache: &mut SourceCache) -> String {
        let mut output = String::new();

        // Header: severity[code]: message
        output.push_str(&self.format_header(finding));
        output.push('\n');

        // Location: --> file:line:col
        output.push_str(&self.format_location(finding));
        output.push('\n');

        // Source context with highlighting
        let loc = &finding.location;
        if let Some(source) = cache.get(&loc.file) {
            let label = self.get_span_label(finding);
            let span_output = SpanRenderer::render(
                &source,
                loc.start_line,
                loc.start_column,
                loc.end_line,
                loc.end_column,
                finding.severity,
                self.config.context_lines,
                label.as_deref(),
            );
            output.push_str(&span_output);
        } else {
            // Fallback if source can't be read: show snippet if available
            if let Some(snippet) = &finding.snippet {
                output.push_str(&format!("   {} {}\n", "|".blue(), snippet.dimmed()));
            }
        }

        // Notes
        let notes = self.format_notes(finding);
        if !notes.is_empty() {
            output.push_str(&notes);
            output.push('\n');
        }

        // Help/suggestion
        if let Some(help) = self.format_help(finding) {
            output.push_str(&help);
            output.push('\n');
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::SourceLocation;
    use std::path::PathBuf;

    fn create_test_finding() -> Finding {
        Finding {
            id: "test-1".to_string(),
            rule_id: "rust/unsafe-block".to_string(),
            message: "Unsafe block requires manual security review".to_string(),
            severity: Severity::Warning,
            location: SourceLocation::new(PathBuf::from("test.rs"), 3, 5, 3, 27),
            language: rma_common::Language::Rust,
            snippet: Some("unsafe { ptr::read(x) }".to_string()),
            suggestion: Some("Consider using safe alternatives".to_string()),
            fix: None,
            confidence: rma_common::Confidence::Medium,
            category: rma_common::FindingCategory::Security,
            source: Default::default(),
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        }
    }

    #[test]
    fn test_format_header() {
        let finding = create_test_finding();
        let renderer = RichDiagnosticRenderer::new();
        let header = renderer.format_header(&finding);

        // Header should contain warning, code, and message
        assert!(header.contains("warning"));
        assert!(header.contains("RMA-S001"));
        assert!(header.contains("Unsafe block requires manual security review"));
    }

    #[test]
    fn test_format_location() {
        let finding = create_test_finding();
        let renderer = RichDiagnosticRenderer::new();
        let location = renderer.format_location(&finding);

        assert!(location.contains("-->"));
        assert!(location.contains("test.rs"));
        assert!(location.contains("3:5"));
    }

    #[test]
    fn test_render_with_cache() {
        let finding = create_test_finding();
        let renderer = RichDiagnosticRenderer::new();
        let mut cache = SourceCache::new();

        // Insert test source
        cache.insert(
            PathBuf::from("test.rs"),
            "fn main() {\n    let x = 5;\n    unsafe { ptr::read(x) }\n}".to_string(),
        );

        let output = renderer.render(&finding, &mut cache);

        // Should contain all parts
        assert!(output.contains("warning[RMA-S001]"));
        assert!(output.contains("-->"));
        assert!(output.contains("unsafe"));
        assert!(output.contains("note"));
        assert!(output.contains("help"));
    }

    #[test]
    fn test_render_without_source() {
        let finding = create_test_finding();
        let renderer = RichDiagnosticRenderer::new();
        let mut cache = SourceCache::new();
        // Don't add source to cache

        let output = renderer.render(&finding, &mut cache);

        // Should still render with fallback snippet
        assert!(output.contains("warning[RMA-S001]"));
        assert!(output.contains("unsafe { ptr::read(x) }"));
    }

    #[test]
    fn test_different_severities() {
        let renderer = RichDiagnosticRenderer::new();

        for severity in [
            Severity::Critical,
            Severity::Error,
            Severity::Warning,
            Severity::Info,
        ] {
            let mut finding = create_test_finding();
            finding.severity = severity;
            let header = renderer.format_header(&finding);

            let expected_word = RichDiagnosticRenderer::severity_word(severity);
            assert!(header.contains(expected_word));
        }
    }
}
