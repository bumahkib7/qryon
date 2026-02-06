//! Native Oxc Linter integration for JS/TS analysis
//!
//! Uses the full oxc_linter crate for comprehensive linting with 520+ rules.
//! This provider runs the official oxc linter rules, reducing false positives
//! compared to heuristic-based tree-sitter rules.
//!
//! # Rule ID Namespacing
//!
//! All rule IDs are prefixed with `js/oxc/` or `ts/oxc/` depending on the
//! source file type:
//! - `js/oxc/no-debugger` for JavaScript files
//! - `ts/oxc/no-cond-assign` for TypeScript files

use super::AnalysisProvider;
use anyhow::Result;
use oxc_allocator::Allocator;
use oxc_diagnostics::Severity as OxcSeverity;
use oxc_linter::{
    ConfigStore, ConfigStoreBuilder, ContextSubHost, ExternalPluginStore, LintOptions, Linter,
    ModuleRecord,
};
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use rma_common::{Confidence, Finding, FindingCategory, Language, Severity, SourceLocation};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, warn};

/// Native Oxc Linter provider using the full oxc_linter crate
///
/// This provider runs oxc's full linting pipeline with 520+ rules,
/// providing comprehensive JS/TS analysis with minimal false positives.
pub struct OxcNativeProvider {
    linter: Linter,
}

impl Default for OxcNativeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OxcNativeProvider {
    /// Create a new Oxc Linter provider with default configuration
    pub fn new() -> Self {
        // Build configuration using ConfigStoreBuilder::default()
        // This includes default plugins + correctness rules at warn level
        let mut external_plugin_store = ExternalPluginStore::default();

        let config = ConfigStoreBuilder::default()
            .build(&mut external_plugin_store)
            .expect("Failed to build oxc config");

        let config_store = ConfigStore::new(
            config,
            Default::default(), // nested_configs
            external_plugin_store,
        );

        let linter = Linter::new(LintOptions::default(), config_store, None);

        Self { linter }
    }

    /// Lint a single file using the full oxc linter
    pub fn lint_file(&self, path: &Path, content: &str) -> Result<Vec<Finding>> {
        let allocator = Allocator::default();

        // Determine source type from file extension
        let source_type = SourceType::from_path(path).unwrap_or_default();

        // Parse the source code
        let parser_ret = Parser::new(&allocator, content, source_type).parse();

        if parser_ret.panicked {
            debug!("oxc parser panicked on {}", path.display());
            return Ok(Vec::new());
        }

        // Build semantic analysis with CFG (CRITICAL: linter requires CFG)
        let semantic_ret = SemanticBuilder::new()
            .with_check_syntax_error(true)
            .with_cfg(true) // Required for linter
            .build(&parser_ret.program);

        if !semantic_ret.errors.is_empty() {
            debug!(
                "oxc semantic errors on {}: {}",
                path.display(),
                semantic_ret.errors.len()
            );
        }

        // Create module record from parser output
        let module_record = Arc::new(ModuleRecord::new(
            path,
            &parser_ret.module_record,
            &semantic_ret.semantic,
        ));

        // Create context sub host for the linter
        let context_sub_host = ContextSubHost::new(
            semantic_ret.semantic,
            module_record,
            0, // source_text_offset
        );

        // Run the linter
        let diagnostics = self.linter.run(path, vec![context_sub_host], &allocator);

        // Convert diagnostics to findings
        let mut findings = Vec::new();

        for message in diagnostics {
            // Get rule info - number is the actual rule name, scope is the plugin prefix
            let rule_name = message
                .error
                .code
                .number
                .as_deref()
                .or(message.error.code.scope.as_deref())
                .unwrap_or("unknown");

            // Get labels for location info
            let labels: Vec<_> = message.error.labels.clone().unwrap_or_default();
            let primary_label = labels.first();

            // Extract location from primary label
            let (start_line, start_col, end_line, end_col, snippet) =
                if let Some(label) = primary_label {
                    let start_offset = label.offset();
                    let end_offset = label.offset() + label.len();
                    let (sl, sc) = byte_offset_to_line_col(content, start_offset);
                    let (el, ec) = byte_offset_to_line_col(content, end_offset);

                    // Extract snippet
                    let snip = if end_offset <= content.len() {
                        let text = &content[start_offset..end_offset.min(content.len())];
                        Some(if text.len() > 200 {
                            format!("{}...", &text[..197])
                        } else {
                            text.to_string()
                        })
                    } else {
                        None
                    };

                    (sl, sc, el, ec, snip)
                } else {
                    (1, 1, 1, 1, None)
                };

            // Map oxc severity to RMA severity
            let severity = match message.error.severity {
                OxcSeverity::Error => Severity::Error,
                OxcSeverity::Warning => Severity::Warning,
                OxcSeverity::Advice => Severity::Info,
            };

            // Determine language prefix based on source type
            let lang_prefix = if source_type.is_typescript() {
                "ts"
            } else {
                "js"
            };

            // Create namespaced rule ID
            let rule_id = format!("{}/oxc/{}", lang_prefix, rule_name);

            // Determine finding category (default to Quality for most rules)
            let category = if rule_name.contains("security")
                || rule_name.contains("eval")
                || rule_name.contains("xss")
            {
                FindingCategory::Security
            } else if rule_name.contains("perf") {
                FindingCategory::Performance
            } else {
                FindingCategory::Quality
            };

            let confidence = Confidence::High; // oxc rules are well-tested

            let language = if source_type.is_typescript() {
                Language::TypeScript
            } else {
                Language::JavaScript
            };

            let location =
                SourceLocation::new(path.to_path_buf(), start_line, start_col, end_line, end_col);

            // Get the message text
            let msg_text = message.error.to_string();

            // Extract help text as suggestion
            let suggestion = message.error.help.as_ref().map(|h| h.to_string());

            let mut finding = Finding {
                id: format!("{}:{}:{}", rule_id, path.display(), start_line),
                rule_id,
                message: msg_text,
                severity,
                location,
                language,
                snippet,
                suggestion,
                fix: None,
                confidence,
                category,
                source: rma_common::FindingSource::Oxc,
                fingerprint: None,
                properties: None,
                occurrence_count: None,
                additional_locations: None,
            };
            finding.compute_fingerprint();
            findings.push(finding);
        }

        Ok(findings)
    }
}

impl AnalysisProvider for OxcNativeProvider {
    fn name(&self) -> &'static str {
        "oxc"
    }

    fn description(&self) -> &'static str {
        "Native Rust JS/TS linting using oxc_linter (520+ rules)"
    }

    fn supports_language(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn is_available(&self) -> bool {
        true // Always available - native dependency
    }

    fn version(&self) -> Option<String> {
        Some("0.55.0".to_string()) // oxc version
    }

    fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>> {
        // Skip non-JS/TS files
        let ext = path.extension().and_then(|e| e.to_str());
        match ext {
            Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts") => {}
            _ => return Ok(Vec::new()),
        }

        let content = std::fs::read_to_string(path)?;
        self.lint_file(path, &content)
    }

    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        use walkdir::WalkDir;

        let mut all_findings = Vec::new();

        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            let ext = file_path.extension().and_then(|e| e.to_str());

            // Skip non-JS/TS files
            match ext {
                Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts") => {}
                _ => continue,
            }

            // Skip common directories
            let path_str = file_path.to_string_lossy();
            if path_str.contains("node_modules")
                || path_str.contains(".git")
                || path_str.contains("/dist/")
                || path_str.contains("/build/")
                || path_str.contains("\\dist\\")
                || path_str.contains("\\build\\")
            {
                continue;
            }

            match self.analyze_file(file_path) {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => {
                    warn!("Failed to analyze {}: {}", file_path.display(), e);
                }
            }
        }

        Ok(all_findings)
    }
}

/// Convert byte offset to line/column (1-indexed)
fn byte_offset_to_line_col(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    let mut current_offset = 0;

    for ch in content.chars() {
        if current_offset >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
        current_offset += ch.len_utf8();
    }

    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = OxcNativeProvider::new();
        assert!(provider.is_available());
        assert!(provider.supports_language(Language::JavaScript));
        assert!(provider.supports_language(Language::TypeScript));
        assert!(!provider.supports_language(Language::Rust));
        assert_eq!(provider.name(), "oxc");
    }

    #[test]
    fn test_detect_debugger() {
        let provider = OxcNativeProvider::new();
        let content = "function test() { debugger; return 1; }";
        let findings = provider.lint_file(Path::new("test.js"), content).unwrap();

        // Should have a finding for debugger statement
        let debugger_finding = findings.iter().find(|f| f.rule_id.contains("debugger"));
        assert!(
            debugger_finding.is_some(),
            "Should detect debugger statement. Findings: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_typescript_support() {
        let provider = OxcNativeProvider::new();
        let content = r#"
            function greet(name: string): void {
                debugger;
                console.log(`Hello, ${name}`);
            }
        "#;
        let findings = provider.lint_file(Path::new("test.ts"), content).unwrap();

        // Should have ts/ prefix for TypeScript files
        let ts_finding = findings.iter().find(|f| f.rule_id.starts_with("ts/oxc/"));
        assert!(
            ts_finding.is_some() || findings.is_empty(),
            "TypeScript files should use ts/oxc/ prefix if findings exist"
        );
    }

    #[test]
    fn test_tsx_template_literal_no_false_positive() {
        // This test verifies that oxc doesn't trigger false positives on
        // template literals in JSX className props
        let provider = OxcNativeProvider::new();
        let content = r#"
            const Button = ({ active }) => (
                <button className={`btn ${active ? 'active' : 'inactive'}`}>
                    Click me
                </button>
            );
        "#;
        let findings = provider
            .lint_file(Path::new("Button.tsx"), content)
            .unwrap();

        // Should NOT have false positive for className
        let false_pos = findings.iter().find(|f| {
            f.message.contains("btn") || f.message.contains("active") || f.message.contains("h-3")
        });
        assert!(
            false_pos.is_none(),
            "TSX template literals should not trigger false positives: {:?}",
            false_pos
        );
    }

    #[test]
    fn test_clean_code() {
        let provider = OxcNativeProvider::new();
        let content = r#"
            function add(a, b) {
                return a + b;
            }
            export { add };
        "#;
        let findings = provider.lint_file(Path::new("test.js"), content).unwrap();
        // Clean code should have minimal findings
        assert!(
            findings.len() < 5,
            "Clean code should have few findings, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}
