//! JSON output formatting
//!
//! Produces enterprise-ready JSON output with:
//! - Schema versioning for API stability
//! - Fingerprints for baseline comparison
//! - Confidence levels for triage
//! - Category classification
//!
//! Finding serialization delegates to `serde_json::to_value(finding)` so that
//! new `Finding` fields are automatically included in JSON output without
//! updating this module.

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
        "schema_version": SCHEMA_VERSION,
        "tool": "rma",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "scanned_path": scanned_path.unwrap_or("."),

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

        "results": results.iter().map(|r| {
            serde_json::json!({
                "path": r.path,
                "language": format!("{}", r.language).to_lowercase(),
                "metrics": r.metrics,
                "findings": r.findings.iter()
                    .filter_map(|f| serialize_finding(f).ok())
                    .collect::<Vec<_>>()
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

/// Serialize a Finding to a JSON value.
///
/// Delegates to `serde_json::to_value` so all `Finding` fields (including
/// future additions) are automatically included, respecting `skip_serializing_if`
/// annotations. Then patches the `location.file` field from a PathBuf to a
/// display string and drops internal-only fields.
fn serialize_finding(finding: &rma_common::Finding) -> Result<serde_json::Value> {
    let mut val = serde_json::to_value(finding)?;

    // Patch location.file: PathBuf serializes as-is, but we want a display string
    if let Some(loc) = val.get_mut("location") {
        if let Some(file) = loc.get("file") {
            if let Some(file_str) = file.as_str() {
                loc["file"] = serde_json::Value::String(file_str.to_string());
            }
        }
    }

    // Drop internal fields not useful in JSON output
    val.as_object_mut().map(|o| {
        o.remove("id"); // Internal ID (rule_id-line-col), not useful externally
        o.remove("language"); // Already on the parent file entry
        o.remove("fix"); // Structured fix is for SARIF/autofix, not human JSON
    });

    Ok(val)
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
