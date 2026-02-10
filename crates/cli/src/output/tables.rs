//! Table output formatting using comfy-table

use anyhow::Result;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use rma_common::Severity;
use std::path::PathBuf;
use std::time::Duration;

/// Create a styled table
pub fn create_table() -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table
}

/// Output a findings table
#[allow(dead_code)]
pub fn output_findings_table(results: &[FileAnalysis]) {
    let mut table = create_table();

    table.set_header(vec![
        Cell::new("Severity").add_attribute(Attribute::Bold),
        Cell::new("File").add_attribute(Attribute::Bold),
        Cell::new("Line").add_attribute(Attribute::Bold),
        Cell::new("Rule").add_attribute(Attribute::Bold),
        Cell::new("Message").add_attribute(Attribute::Bold),
    ]);

    for result in results {
        for finding in &result.findings {
            let severity_cell = match finding.severity {
                Severity::Critical => Cell::new("CRIT")
                    .fg(Color::Red)
                    .add_attribute(Attribute::Bold),
                Severity::Error => Cell::new("ERR").fg(Color::Red),
                Severity::Warning => Cell::new("WARN").fg(Color::Yellow),
                Severity::Info => Cell::new("INFO").fg(Color::Blue),
            };

            let file_path = finding
                .location
                .file
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| finding.location.file.display().to_string());

            table.add_row(vec![
                severity_cell,
                Cell::new(&file_path),
                Cell::new(format!(
                    "{}:{}",
                    finding.location.start_line, finding.location.start_column
                ))
                .set_alignment(CellAlignment::Right),
                Cell::new(&finding.rule_id).fg(Color::DarkGrey),
                Cell::new(truncate(&finding.message, 50)),
            ]);
        }
    }

    println!("{}", table);
}

/// Output a summary table
#[allow(dead_code)]
pub fn output_summary_table(summary: &AnalysisSummary, duration: Duration) {
    let mut table = create_table();

    table.set_header(vec![
        Cell::new("Metric").add_attribute(Attribute::Bold),
        Cell::new("Value").add_attribute(Attribute::Bold),
    ]);

    table.add_row(vec![
        Cell::new("Files Analyzed"),
        Cell::new(summary.files_analyzed),
    ]);
    table.add_row(vec![
        Cell::new("Total Lines"),
        Cell::new(format_number(summary.total_loc)),
    ]);
    table.add_row(vec![
        Cell::new("Complexity Score"),
        Cell::new(summary.total_complexity),
    ]);
    table.add_row(vec![
        Cell::new("Duration"),
        Cell::new(format!("{:.2}s", duration.as_secs_f64())),
    ]);
    table.add_row(vec![
        Cell::new("Critical Issues").fg(Color::Red),
        Cell::new(summary.critical_count).fg(if summary.critical_count > 0 {
            Color::Red
        } else {
            Color::Green
        }),
    ]);
    table.add_row(vec![
        Cell::new("Errors").fg(Color::Red),
        Cell::new(summary.error_count).fg(if summary.error_count > 0 {
            Color::Red
        } else {
            Color::Green
        }),
    ]);
    table.add_row(vec![
        Cell::new("Warnings").fg(Color::Yellow),
        Cell::new(summary.warning_count).fg(if summary.warning_count > 0 {
            Color::Yellow
        } else {
            Color::Green
        }),
    ]);
    table.add_row(vec![
        Cell::new("Info").fg(Color::Blue),
        Cell::new(summary.info_count),
    ]);

    println!("{}", table);
}

/// Output results in Markdown table format
pub fn output_markdown(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let mut output = String::new();

    // Summary section
    output.push_str("# Qryon Analysis Report\n\n");
    output.push_str("## Summary\n\n");
    output.push_str("| Metric | Value |\n");
    output.push_str("|--------|-------|\n");
    output.push_str(&format!(
        "| Files Analyzed | {} |\n",
        summary.files_analyzed
    ));
    output.push_str(&format!(
        "| Total Lines | {} |\n",
        format_number(summary.total_loc)
    ));
    output.push_str(&format!("| Duration | {:.2}s |\n", duration.as_secs_f64()));
    output.push_str(&format!("| Critical | {} |\n", summary.critical_count));
    output.push_str(&format!("| Errors | {} |\n", summary.error_count));
    output.push_str(&format!("| Warnings | {} |\n", summary.warning_count));
    output.push_str(&format!("| Info | {} |\n", summary.info_count));
    output.push('\n');

    // Findings section
    let has_findings = results.iter().any(|r| !r.findings.is_empty());

    if has_findings {
        output.push_str("## Findings\n\n");
        output.push_str("| Severity | File | Line | Rule | Message |\n");
        output.push_str("|----------|------|------|------|--------|\n");

        for result in results {
            for finding in &result.findings {
                let severity = match finding.severity {
                    Severity::Critical => "🔴 CRITICAL",
                    Severity::Error => "🟠 ERROR",
                    Severity::Warning => "🟡 WARNING",
                    Severity::Info => "🔵 INFO",
                };

                let file = finding
                    .location
                    .file
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                output.push_str(&format!(
                    "| {} | {} | {}:{} | `{}` | {} |\n",
                    severity,
                    file,
                    finding.location.start_line,
                    finding.location.start_column,
                    finding.rule_id,
                    escape_markdown(&finding.message)
                ));
            }
        }
    } else {
        output.push_str("## Findings\n\n");
        output.push_str("✅ No issues found!\n");
    }

    output.push_str(&format!(
        "\n---\n*Generated by Qryon v{}*\n",
        env!("CARGO_PKG_VERSION")
    ));

    if let Some(path) = output_file {
        std::fs::write(&path, &output)?;
        eprintln!("Markdown output written to: {}", path.display());
    } else {
        println!("{}", output);
    }

    Ok(())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
}

fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn escape_markdown(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('\r', "")
}
