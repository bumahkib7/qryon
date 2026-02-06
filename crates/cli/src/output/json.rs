//! JSON output formatting
//!
//! Produces enterprise-ready JSON output with:
//! - Schema versioning for API stability
//! - Fingerprints for baseline comparison
//! - Confidence levels for triage
//! - Category classification

use anyhow::Result;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use std::path::PathBuf;
use std::time::Duration;

/// Current JSON schema version
/// Increment when making breaking changes to the schema
pub const SCHEMA_VERSION: u32 = 1;

/// Output results in JSON format
pub fn output(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    output_file: Option<PathBuf>,
) -> Result<()> {
    output_with_path(results, summary, duration, output_file, None)
}

/// Output results in JSON format with scanned path
pub fn output_with_path(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    output_file: Option<PathBuf>,
    scanned_path: Option<&str>,
) -> Result<()> {
    let output = serde_json::json!({
        // Schema metadata for API stability
        "schema_version": SCHEMA_VERSION,
        "tool": "rma",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "scanned_path": scanned_path.unwrap_or("."),

        // Scan summary
        "summary": {
            "files_analyzed": summary.files_analyzed,
            "total_findings": summary.total_findings,
            "total_loc": summary.total_loc,
            "total_complexity": summary.total_complexity,
            "by_severity": {
                "critical": summary.critical_count,
                "error": summary.error_count,
                "warning": summary.warning_count,
                "info": summary.info_count,
            },
            "by_category": count_by_category(results),
        },
        "duration_ms": duration.as_millis(),

        // File results with findings
        "results": results.iter().map(|r| {
            serde_json::json!({
                "path": r.path,
                "language": format!("{}", r.language).to_lowercase(),
                "metrics": r.metrics,
                "findings": r.findings.iter().map(|f| {
                    serde_json::json!({
                        // Core fields
                        "rule_id": f.rule_id,
                        "severity": format!("{}", f.severity),
                        "message": f.message,

                        // Location details
                        "location": {
                            "file": f.location.file.display().to_string(),
                            "start_line": f.location.start_line,
                            "start_column": f.location.start_column,
                            "end_line": f.location.end_line,
                            "end_column": f.location.end_column,
                        },

                        // Enterprise fields
                        "source": format!("{}", f.source),
                        "confidence": format!("{}", f.confidence),
                        "category": format!("{}", f.category),
                        "fingerprint": f.fingerprint,

                        // Optional fields
                        "snippet": f.snippet,
                        "suggestion": f.suggestion,

                        // Deduplication fields (when same rule fires multiple times in same file)
                        "occurrence_count": f.occurrence_count,
                        "additional_locations": f.additional_locations,
                    })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    });

    let json = serde_json::to_string_pretty(&output)?;

    if let Some(path) = output_file {
        std::fs::write(&path, &json)?;
        eprintln!("JSON output written to: {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}

/// Count findings by category
fn count_by_category(results: &[FileAnalysis]) -> serde_json::Value {
    let mut security = 0;
    let mut quality = 0;
    let mut performance = 0;
    let mut style = 0;

    for result in results {
        for finding in &result.findings {
            match finding.category {
                rma_common::FindingCategory::Security => security += 1,
                rma_common::FindingCategory::Quality => quality += 1,
                rma_common::FindingCategory::Performance => performance += 1,
                rma_common::FindingCategory::Style => style += 1,
            }
        }
    }

    serde_json::json!({
        "security": security,
        "quality": quality,
        "performance": performance,
        "style": style,
    })
}
