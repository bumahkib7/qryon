//! Tree-sitter query execution engine for embedded rules
//!
//! Runs pre-compiled tree-sitter S-expression queries from the embedded ruleset
//! against already-parsed files (leveraging `ParsedFile.tree`), avoiding re-parsing.
//! Returns findings with precise AST-level locations plus a set of rule IDs that
//! were successfully executed via tree-sitter, so the caller can skip regex fallback
//! for those rules.

use rma_common::{
    Confidence, Finding, FindingCategory, FindingSource, Severity, SourceLocation,
};
use rma_parser::ParsedFile;
use rma_rules::embedded::{CompiledRuleSet, MatchStrategy};
use std::collections::HashSet;
use tree_sitter::{Query, QueryCursor, StreamingIterator};
use tracing::debug;

/// Run tree-sitter queries from the embedded ruleset against a parsed file.
///
/// Returns `(findings, matched_rule_ids)` where `matched_rule_ids` contains the IDs
/// of rules whose S-expression compiled and was executed (regardless of whether it
/// produced matches). The caller should skip regex fallback for these rules.
pub fn run_ts_queries(
    parsed: &ParsedFile,
    ruleset: &CompiledRuleSet,
) -> (Vec<Finding>, HashSet<String>) {
    let mut findings = Vec::new();
    let mut matched_ids = HashSet::new();

    // Get the tree-sitter language grammar
    let ts_language = match rma_parser::languages::get_language(parsed.language) {
        Ok(lang) => lang,
        Err(_) => return (findings, matched_ids),
    };

    let lang_str = parsed.language.to_string().to_lowercase();
    let rules = ruleset.rules_for_language(&lang_str);

    for rule in rules {
        // Only process TreeSitterQuery rules
        let query_str = match &rule.strategy {
            MatchStrategy::TreeSitterQuery { query, .. } => query,
            _ => continue,
        };

        // Try to compile the S-expression query
        let query = match Query::new(&ts_language, query_str) {
            Ok(q) => q,
            Err(_) => {
                // Query failed to compile for this language — let regex handle it
                continue;
            }
        };

        // Mark this rule as handled by tree-sitter (even if it finds 0 matches)
        matched_ids.insert(rule.id.clone());

        // Execute query against the already-parsed tree (StreamingIterator API)
        let mut cursor = QueryCursor::new();
        let root = parsed.tree.root_node();
        let mut matches = cursor.matches(&query, root, parsed.content.as_bytes());

        let severity = parse_severity(&rule.severity);
        let confidence = rule
            .confidence
            .as_deref()
            .map(parse_confidence)
            .unwrap_or_default();
        let category = rule
            .category
            .as_deref()
            .map(infer_category)
            .unwrap_or(FindingCategory::Security);

        loop {
            matches.advance();
            let m = match matches.get() {
                Some(m) => m,
                None => break,
            };

            // Compute the match span as the union of all captures
            let mut match_start_byte = usize::MAX;
            let mut match_end_byte = 0usize;
            let mut match_text = String::new();

            for capture in m.captures {
                let node = capture.node;
                if node.start_byte() < match_start_byte {
                    match_start_byte = node.start_byte();
                }
                if node.end_byte() > match_end_byte {
                    match_end_byte = node.end_byte();
                    match_text = parsed.content[node.start_byte()..node.end_byte()].to_string();
                }
            }

            if match_start_byte >= usize::MAX {
                continue;
            }

            // Compute line/column from byte offsets
            let start_line = parsed.content[..match_start_byte]
                .matches('\n')
                .count()
                + 1;
            let start_col = match_start_byte
                - parsed.content[..match_start_byte]
                    .rfind('\n')
                    .map(|p| p + 1)
                    .unwrap_or(0)
                + 1;
            let end_line = parsed.content[..match_end_byte].matches('\n').count() + 1;
            let end_col = match_end_byte
                - parsed.content[..match_end_byte]
                    .rfind('\n')
                    .map(|p| p + 1)
                    .unwrap_or(0)
                + 1;

            let snippet = match_text.lines().next().unwrap_or("").trim().to_string();

            // Build properties with cwe/owasp/references
            let mut props = std::collections::HashMap::new();
            if let Some(ref cwe) = rule.cwe {
                props.insert("cwe".into(), serde_json::json!(cwe));
            }
            if let Some(ref owasp) = rule.owasp {
                props.insert("owasp".into(), serde_json::json!(owasp));
            }
            if let Some(ref refs) = rule.references {
                props.insert("references".into(), serde_json::json!(refs));
            }

            let mut finding = Finding {
                id: format!("{}-{}-1", rule.id, start_line),
                rule_id: rule.id.clone(),
                message: rule.message.clone(),
                severity,
                location: SourceLocation::new(
                    parsed.path.clone(),
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                ),
                language: parsed.language,
                snippet: Some(snippet),
                suggestion: rule.fix.clone(),
                fix: None,
                confidence,
                category,
                subcategory: rule.subcategory.clone(),
                technology: rule.technology.clone(),
                impact: rule.impact.clone(),
                likelihood: rule.likelihood.clone(),
                source: FindingSource::Builtin,
                fingerprint: None,
                properties: if props.is_empty() { None } else { Some(props) },
                occurrence_count: None,
                additional_locations: None,
            };

            // Default subcategory for builtin findings missing it
            if finding.subcategory.is_none() {
                finding.subcategory = Some(vec![
                    if finding.category == FindingCategory::Security {
                        "vuln".to_string()
                    } else {
                        "other".to_string()
                    }
                ]);
            }

            finding.compute_fingerprint();
            findings.push(finding);
        }
    }

    debug!(
        "TS query matcher: {} findings from {} rules for {}",
        findings.len(),
        matched_ids.len(),
        parsed.path.display()
    );

    (findings, matched_ids)
}

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "ERROR" => Severity::Error,
        "WARNING" => Severity::Warning,
        "INFO" => Severity::Info,
        _ => Severity::Warning,
    }
}

fn parse_confidence(s: &str) -> Confidence {
    match s.to_uppercase().as_str() {
        "HIGH" => Confidence::High,
        "MEDIUM" => Confidence::Medium,
        "LOW" => Confidence::Low,
        _ => Confidence::Medium,
    }
}

fn infer_category(cat: &str) -> FindingCategory {
    let lower = cat.to_lowercase();
    if lower.contains("security") {
        FindingCategory::Security
    } else if lower.contains("performance") {
        FindingCategory::Performance
    } else if lower.contains("correctness") || lower.contains("bug") || lower.contains("quality")
    {
        FindingCategory::Quality
    } else if lower.contains("style") || lower.contains("best-practice") {
        FindingCategory::Style
    } else if lower.contains("maintainability") {
        FindingCategory::Quality
    } else {
        FindingCategory::Quality
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("ERROR"), Severity::Error);
        assert_eq!(parse_severity("warning"), Severity::Warning);
        assert_eq!(parse_severity("INFO"), Severity::Info);
        assert_eq!(parse_severity("unknown"), Severity::Warning);
    }

    #[test]
    fn test_infer_category() {
        assert_eq!(infer_category("security"), FindingCategory::Security);
        assert_eq!(infer_category("performance"), FindingCategory::Performance);
        assert_eq!(infer_category("correctness"), FindingCategory::Quality);
        assert_eq!(infer_category("style"), FindingCategory::Style);
        assert_eq!(infer_category("maintainability"), FindingCategory::Quality);
    }
}
