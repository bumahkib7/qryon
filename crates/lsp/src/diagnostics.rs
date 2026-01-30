//! Conversion from RMA findings to LSP diagnostics

use rma_common::{Finding, Severity};
use tower_lsp::lsp_types::*;

/// Convert RMA findings to LSP diagnostics
pub fn findings_to_diagnostics(findings: &[Finding]) -> Vec<Diagnostic> {
    findings.iter().map(finding_to_diagnostic).collect()
}

/// Convert a single finding to an LSP diagnostic
pub fn finding_to_diagnostic(finding: &Finding) -> Diagnostic {
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
        severity: Some(severity_to_lsp(&finding.severity)),
        code: Some(NumberOrString::String(finding.rule_id.clone())),
        code_description: None,
        source: Some("rma".to_string()),
        message: finding.message.clone(),
        related_information: None,
        tags: diagnostic_tags(finding),
        data: None,
    }
}

/// Convert RMA severity to LSP severity
fn severity_to_lsp(severity: &Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Critical | Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
        Severity::Info => DiagnosticSeverity::INFORMATION,
    }
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

    if tags.is_empty() {
        None
    } else {
        Some(tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::SourceLocation;
    use std::path::PathBuf;

    #[test]
    fn test_finding_to_diagnostic() {
        let finding = Finding {
            id: "test-1".to_string(),
            rule_id: "rust/unsafe-block".to_string(),
            message: "Unsafe block found".to_string(),
            severity: Severity::Warning,
            location: SourceLocation::new(PathBuf::from("test.rs"), 10, 5, 12, 10),
            language: rma_common::Language::Rust,
            snippet: None,
            suggestion: None,
        };

        let diagnostic = finding_to_diagnostic(&finding);

        assert_eq!(diagnostic.range.start.line, 9); // 0-indexed
        assert_eq!(diagnostic.range.start.character, 4);
        assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(
            diagnostic.code,
            Some(NumberOrString::String("rust/unsafe-block".to_string()))
        );
    }
}
