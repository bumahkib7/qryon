//! Conversion from RMA findings to LSP diagnostics
//!
//! This module handles the translation between RMA's internal `Finding` type
//! and the Language Server Protocol's `Diagnostic` type.

use rma_common::{Confidence, Finding, Severity};
use tower_lsp::lsp_types::*;

/// Convert RMA findings to LSP diagnostics
pub fn findings_to_diagnostics(findings: &[Finding]) -> Vec<Diagnostic> {
    findings.iter().map(finding_to_diagnostic).collect()
}

/// Convert a single finding to an LSP diagnostic
pub fn finding_to_diagnostic(finding: &Finding) -> Diagnostic {
    let severity = severity_to_lsp(&finding.severity);
    let tags = diagnostic_tags(finding);

    // Build message with confidence indicator for low-confidence findings
    let message = if finding.confidence == Confidence::Low {
        format!(
            "{} (low confidence - may be false positive)",
            finding.message
        )
    } else {
        finding.message.clone()
    };

    Diagnostic {
        range: Range {
            start: Position {
                line: finding.location.start_line.saturating_sub(1) as u32,
                character: finding.location.start_column.saturating_sub(1) as u32,
            },
            end: Position {
                line: finding.location.end_line.saturating_sub(1) as u32,
                character: finding.location.end_column.saturating_sub(1) as u32,
            },
        },
        severity: Some(severity),
        code: Some(NumberOrString::String(finding.rule_id.clone())),
        code_description: code_description(&finding.rule_id),
        source: Some("rma".to_string()),
        message,
        related_information: related_info(finding),
        tags,
        data: serde_json::to_value(DiagnosticData {
            rule_id: finding.rule_id.clone(),
            category: finding.category.to_string(),
            confidence: finding.confidence.to_string(),
            suggestion: finding.suggestion.clone(),
        })
        .ok(),
    }
}

/// Additional data attached to diagnostics for code actions
#[derive(serde::Serialize, serde::Deserialize)]
struct DiagnosticData {
    rule_id: String,
    category: String,
    confidence: String,
    suggestion: Option<String>,
}

/// Convert RMA severity to LSP severity
fn severity_to_lsp(severity: &Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Critical => DiagnosticSeverity::ERROR,
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
        Severity::Info => DiagnosticSeverity::INFORMATION,
    }
}

/// Generate code description with documentation URL
fn code_description(rule_id: &str) -> Option<CodeDescription> {
    // Generate a URL to RMA documentation for this rule
    // This could be customized based on deployment
    let url = format!(
        "https://github.com/bumahkib7/rust-monorepo-analyzer/blob/main/docs/rules/{}.md",
        rule_id.replace('/', "-")
    );

    Url::parse(&url).ok().map(|href| CodeDescription { href })
}

/// Get diagnostic tags based on finding
fn diagnostic_tags(finding: &Finding) -> Option<Vec<DiagnosticTag>> {
    let mut tags = Vec::new();

    // Mark TODO/FIXME as unnecessary
    if finding.rule_id.contains("todo") || finding.rule_id.contains("fixme") {
        tags.push(DiagnosticTag::UNNECESSARY);
    }

    // Mark deprecated patterns
    if finding.message.to_lowercase().contains("deprecated") {
        tags.push(DiagnosticTag::DEPRECATED);
    }

    // Mark dead code findings
    if finding.rule_id.contains("dead-code") || finding.rule_id.contains("unused") {
        tags.push(DiagnosticTag::UNNECESSARY);
    }

    if tags.is_empty() { None } else { Some(tags) }
}

/// Generate related information if the finding has a suggestion
fn related_info(finding: &Finding) -> Option<Vec<DiagnosticRelatedInformation>> {
    finding.suggestion.as_ref().map(|suggestion| {
        vec![DiagnosticRelatedInformation {
            location: Location {
                uri: Url::from_file_path(&finding.location.file)
                    .unwrap_or_else(|_| Url::parse("file:///unknown").expect("valid URL")),
                range: Range {
                    start: Position {
                        line: finding.location.start_line.saturating_sub(1) as u32,
                        character: finding.location.start_column.saturating_sub(1) as u32,
                    },
                    end: Position {
                        line: finding.location.end_line.saturating_sub(1) as u32,
                        character: finding.location.end_column.saturating_sub(1) as u32,
                    },
                },
            },
            message: format!("Suggestion: {}", suggestion),
        }]
    })
}

/// Convert LSP severity back to RMA severity (for filtering)
#[allow(dead_code)]
pub fn lsp_to_severity(severity: DiagnosticSeverity) -> Severity {
    match severity {
        DiagnosticSeverity::ERROR => Severity::Error,
        DiagnosticSeverity::WARNING => Severity::Warning,
        DiagnosticSeverity::INFORMATION => Severity::Info,
        DiagnosticSeverity::HINT => Severity::Info,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::{FindingCategory, Language, SourceLocation};
    use std::path::PathBuf;

    fn make_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            id: "test-1".to_string(),
            rule_id: rule_id.to_string(),
            message: "Test finding message".to_string(),
            severity,
            location: SourceLocation::new(PathBuf::from("test.rs"), 10, 5, 12, 10),
            language: Language::Rust,
            snippet: None,
            suggestion: None,
            fix: None,
            confidence: Confidence::Medium,
            category: FindingCategory::Security,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        }
    }

    #[test]
    fn test_finding_to_diagnostic() {
        let finding = make_finding("rust/unsafe-block", Severity::Warning);
        let diagnostic = finding_to_diagnostic(&finding);

        assert_eq!(diagnostic.range.start.line, 9); // 0-indexed
        assert_eq!(diagnostic.range.start.character, 4);
        assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(
            diagnostic.code,
            Some(NumberOrString::String("rust/unsafe-block".to_string()))
        );
        assert_eq!(diagnostic.source, Some("rma".to_string()));
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            severity_to_lsp(&Severity::Critical),
            DiagnosticSeverity::ERROR
        );
        assert_eq!(severity_to_lsp(&Severity::Error), DiagnosticSeverity::ERROR);
        assert_eq!(
            severity_to_lsp(&Severity::Warning),
            DiagnosticSeverity::WARNING
        );
        assert_eq!(
            severity_to_lsp(&Severity::Info),
            DiagnosticSeverity::INFORMATION
        );
    }

    #[test]
    fn test_todo_tags() {
        let finding = make_finding("generic/todo-comment", Severity::Info);
        let tags = diagnostic_tags(&finding);
        assert!(tags.is_some());
        assert!(tags.unwrap().contains(&DiagnosticTag::UNNECESSARY));
    }

    #[test]
    fn test_deprecated_tags() {
        let mut finding = make_finding("test/deprecated", Severity::Warning);
        finding.message = "Using deprecated API".to_string();
        let tags = diagnostic_tags(&finding);
        assert!(tags.is_some());
        assert!(tags.unwrap().contains(&DiagnosticTag::DEPRECATED));
    }

    #[test]
    fn test_low_confidence_message() {
        let mut finding = make_finding("rust/potential-issue", Severity::Warning);
        finding.confidence = Confidence::Low;
        let diagnostic = finding_to_diagnostic(&finding);
        assert!(diagnostic.message.contains("low confidence"));
    }

    #[test]
    fn test_code_description() {
        let desc = code_description("rust/unsafe-block");
        assert!(desc.is_some());
        let url = desc.unwrap().href;
        assert!(url.as_str().contains("rust-unsafe-block"));
    }

    #[test]
    fn test_related_info_with_suggestion() {
        let mut finding = make_finding("rust/unwrap-used", Severity::Warning);
        finding.suggestion = Some("Use ? operator instead".to_string());
        let info = related_info(&finding);
        assert!(info.is_some());
        assert!(info.unwrap()[0].message.contains("Use ? operator"));
    }
}
