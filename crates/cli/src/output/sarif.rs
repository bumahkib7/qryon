//! SARIF output formatting

use anyhow::Result;
use rma_analyzer::FileAnalysis;
use rma_common::{Confidence, FindingCategory, Severity};
use std::path::PathBuf;

/// Normalize a file path for SARIF output
/// Removes ./ prefix and ensures it's a clean relative path
fn normalize_sarif_path(path: &std::path::Path) -> String {
    let path_str = path.display().to_string();
    // Remove leading ./ or ./
    let normalized = path_str
        .strip_prefix("./")
        .or_else(|| path_str.strip_prefix(".\\"))
        .unwrap_or(&path_str);
    normalized.to_string()
}

/// Check if a rule_id is an OSV vulnerability finding
fn is_osv_finding(rule_id: &str) -> bool {
    rule_id.starts_with("deps/osv/")
}

/// Extract OSV metadata from finding message for SARIF properties
fn extract_osv_metadata(message: &str, rule_id: &str) -> Option<serde_json::Value> {
    // OSV findings have messages like:
    // "npm lodash is vulnerable: ... (GHSA-xxx). Fixed in version X.Y.Z"
    // Rule ID format: deps/osv/GHSA-xxx or deps/osv/CVE-xxx

    let osv_id = rule_id.strip_prefix("deps/osv/")?;

    // Try to extract ecosystem and package from message
    // Format: "<ecosystem> <package> is vulnerable: ..."
    let parts: Vec<&str> = message.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        let ecosystem = parts[0];
        let package = parts[1];

        return Some(serde_json::json!({
            "osv": {
                "id": osv_id,
                "ecosystem": ecosystem,
                "package": package
            }
        }));
    }

    Some(serde_json::json!({
        "osv": {
            "id": osv_id
        }
    }))
}

/// Output results in SARIF 2.1.0 format
pub fn output(results: &[FileAnalysis], output_file: Option<PathBuf>) -> Result<()> {
    let rules: Vec<_> = results
        .iter()
        .flat_map(|r| &r.findings)
        .map(|f| &f.rule_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .map(|rule_id| {
            let mut rule = serde_json::json!({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": rule_id
                }
            });

            // Add OSV-specific rule properties
            if is_osv_finding(rule_id)
                && let Some(osv_id) = rule_id.strip_prefix("deps/osv/")
            {
                rule["properties"] = serde_json::json!({
                    "category": "security/vulnerability",
                    "osvId": osv_id
                });
            }

            rule
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RMA",
                    "fullName": "Rust Monorepo Analyzer",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/bumahkib7/rust-monorepo-analyzer",
                    "rules": rules
                }
            },
            "results": results.iter().flat_map(|r| {
                r.findings.iter().map(|f| {
                    let mut result = serde_json::json!({
                        "ruleId": f.rule_id,
                        "ruleIndex": rules.iter().position(|rule| {
                            rule.get("id").and_then(|v| v.as_str()) == Some(&f.rule_id)
                        }).unwrap_or(0),
                        "level": match f.severity {
                            Severity::Critical => "error",
                            Severity::Error => "error",
                            Severity::Warning => "warning",
                            Severity::Info => "note",
                        },
                        "message": {
                            "text": &f.message
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": normalize_sarif_path(&f.location.file),
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "startLine": f.location.start_line,
                                    "startColumn": f.location.start_column,
                                    "endLine": f.location.end_line,
                                    "endColumn": f.location.end_column,
                                    "snippet": f.snippet.as_ref().map(|s| serde_json::json!({
                                        "text": s
                                    }))
                                }
                            }
                        }]
                    });
                    // Add structured fix if available (preferred), otherwise fall back to suggestion
                    if let Some(fix) = &f.fix {
                        result["fixes"] = serde_json::json!([{
                            "description": {
                                "text": &fix.description
                            },
                            "artifactChanges": [{
                                "artifactLocation": {
                                    "uri": normalize_sarif_path(&f.location.file)
                                },
                                "replacements": [{
                                    "deletedRegion": {
                                        "startLine": f.location.start_line,
                                        "startColumn": f.location.start_column,
                                        "endLine": f.location.end_line,
                                        "endColumn": f.location.end_column,
                                        "byteOffset": fix.start_byte,
                                        "byteLength": fix.end_byte - fix.start_byte
                                    },
                                    "insertedContent": {
                                        "text": &fix.replacement
                                    }
                                }]
                            }]
                        }]);
                    } else if let Some(suggestion) = &f.suggestion {
                        // Fall back to simple description-only fix for backward compatibility
                        result["fixes"] = serde_json::json!([{
                            "description": {
                                "text": suggestion
                            }
                        }]);
                    }

                    // Add properties with additional metadata
                    let mut properties = serde_json::json!({
                        "confidence": match f.confidence {
                            Confidence::High => "high",
                            Confidence::Medium => "medium",
                            Confidence::Low => "low",
                        },
                        "category": match f.category {
                            FindingCategory::Security => "security",
                            FindingCategory::Quality => "quality",
                            FindingCategory::Performance => "performance",
                            FindingCategory::Style => "style",
                        }
                    });

                    // Add fingerprint if available
                    if let Some(ref fingerprint) = f.fingerprint {
                        properties["fingerprint"] = serde_json::json!(fingerprint);
                    }

                    // Add OSV-specific metadata for vulnerability findings
                    if is_osv_finding(&f.rule_id)
                        && let Some(osv_meta) = extract_osv_metadata(&f.message, &f.rule_id)
                        && let Some(osv_obj) = osv_meta.get("osv")
                    {
                        properties["osv"] = osv_obj.clone();
                    }

                    // Add custom properties from finding (reachability, import_hits, etc.)
                    if let Some(ref finding_props) = f.properties {
                        for (key, value) in finding_props {
                            properties[key] = value.clone();
                        }
                    }

                    result["properties"] = properties;
                    result
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>(),
            "automationDetails": {
                "id": format!("rma-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"))
            }
        }]
    });

    let json = serde_json::to_string_pretty(&sarif)?;

    if let Some(path) = output_file {
        std::fs::write(&path, &json)?;
        eprintln!("SARIF output written to: {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}
