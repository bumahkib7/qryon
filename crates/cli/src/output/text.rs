//! Text output formatting with smart limiting and grouping

use crate::GroupBy;
use crate::output::OutputOptions;
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use rma_common::{Finding, Severity};
use std::collections::HashMap;
use std::time::Duration;

/// Output results in human-readable text format (legacy, uses defaults)
#[allow(dead_code)] // Public API for text output
pub fn output(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
) -> Result<()> {
    output_with_options(results, summary, duration, &OutputOptions::default())
}

/// Output results with smart limiting and grouping options
pub fn output_with_options(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    options: &OutputOptions,
) -> Result<()> {
    // Always print the summary header first
    print_summary_box(summary, duration, results);

    // If quiet mode, stop here
    if options.quiet {
        return Ok(());
    }

    // Collect all findings
    let all_findings: Vec<(&FileAnalysis, &Finding)> = results
        .iter()
        .flat_map(|r| r.findings.iter().map(move |f| (r, f)))
        .collect();

    if all_findings.is_empty() {
        println!();
        println!("{}", "  No issues found! Your code looks great.".green());
        println!();
        return Ok(());
    }

    // Print details based on grouping and limiting options
    println!();
    print_findings_with_options(results, &all_findings, options);

    Ok(())
}

/// Print the summary box with scan results
fn print_summary_box(summary: &AnalysisSummary, duration: Duration, results: &[FileAnalysis]) {
    let width = 64;

    println!();
    println!("{}", format_box_top(width).cyan());
    println!("{}", format_box_line("  RMA Scan Complete", width).cyan());
    println!("{}", format_box_separator(width).cyan());

    // Files scanned | Time | Rules
    let stats_line = format!(
        "  Files scanned: {}  |  Time: {}  |  Findings: {}",
        format_number(summary.files_analyzed),
        format_duration(duration),
        summary.total_findings
    );
    println!("{}", format_box_line(&stats_line, width).cyan());

    println!("{}", format_box_separator(width).cyan());

    // Severity counts with icons
    let severity_line = format!(
        "  {} Critical: {}   {} Error: {}   {} Warning: {}   {} Info: {}",
        "X".red().bold(),
        format_count(summary.critical_count, Severity::Critical),
        "!".bright_red(),
        format_count(summary.error_count, Severity::Error),
        "!".yellow(),
        format_count(summary.warning_count, Severity::Warning),
        "i".blue(),
        format_count(summary.info_count, Severity::Info),
    );
    println!("{}", format_box_line(&severity_line, width).cyan());

    // Engine breakdown
    let engine_counts = get_engine_counts(results);
    if !engine_counts.is_empty() {
        println!("{}", format_box_separator(width).cyan());
        let engines_str = engine_counts
            .iter()
            .map(|(src, cnt)| format!("{}: {}", src, cnt))
            .collect::<Vec<_>>()
            .join(", ");
        let engine_line = format!("  Engines: {}", engines_str);
        println!("{}", format_box_line(&engine_line, width).cyan());
    }

    // Top issues section
    let top_issues = get_top_issues(results, 3);
    if !top_issues.is_empty() {
        println!("{}", format_box_separator(width).cyan());
        println!("{}", format_box_line("  Top Issues:", width).cyan());
        for (rule_id, count) in top_issues {
            let issue_line = format!("    * {} ({} findings)", rule_id, count);
            println!("{}", format_box_line(&issue_line, width).cyan());
        }
    }

    println!("{}", format_box_bottom(width).cyan());
}

/// Get finding counts by source engine
fn get_engine_counts(results: &[FileAnalysis]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    for result in results {
        for finding in &result.findings {
            *counts.entry(finding.source.to_string()).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted
}

/// Get top N rule IDs by finding count
fn get_top_issues(results: &[FileAnalysis], limit: usize) -> Vec<(String, usize)> {
    let mut rule_counts: HashMap<String, usize> = HashMap::new();

    for result in results {
        for finding in &result.findings {
            *rule_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = rule_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(limit);
    sorted
}

/// Print findings with grouping, limiting, and collapse options
fn print_findings_with_options(
    results: &[FileAnalysis],
    all_findings: &[(&FileAnalysis, &Finding)],
    options: &OutputOptions,
) {
    let total_count = all_findings.len();
    let display_limit = options.limit.min(total_count);

    match options.group_by {
        GroupBy::File => print_grouped_by_file(results, options, display_limit, total_count),
        GroupBy::Rule => print_grouped_by_rule(all_findings, options, display_limit, total_count),
        GroupBy::Severity => {
            print_grouped_by_severity(all_findings, options, display_limit, total_count)
        }
        GroupBy::None => print_flat_list(all_findings, options, display_limit, total_count),
    }
}

/// Print findings grouped by file
fn print_grouped_by_file(
    results: &[FileAnalysis],
    options: &OutputOptions,
    display_limit: usize,
    total_count: usize,
) {
    let mut displayed = 0;

    for result in results {
        if result.findings.is_empty() {
            continue;
        }

        if displayed >= display_limit {
            break;
        }

        // File header
        let file_path = &result.path;
        let finding_count = result.findings.len();
        println!(
            "{} {} ({} findings) {}",
            "--".dimmed(),
            file_path.bright_white(),
            finding_count.to_string().yellow(),
            "-".repeat(50usize.saturating_sub(file_path.len())).dimmed()
        );

        if options.collapse {
            // Collapse mode: group by rule within file
            print_collapsed_findings(&result.findings, file_path);
            displayed += finding_count;
        } else {
            // Normal mode: show each finding
            for finding in &result.findings {
                if displayed >= display_limit {
                    break;
                }
                print_finding_line(finding);
                displayed += 1;
            }
        }
        println!();
    }

    print_truncation_message(displayed, total_count, options);
}

/// Print findings grouped by rule ID
fn print_grouped_by_rule(
    all_findings: &[(&FileAnalysis, &Finding)],
    options: &OutputOptions,
    display_limit: usize,
    total_count: usize,
) {
    let mut by_rule: HashMap<String, Vec<(&FileAnalysis, &Finding)>> = HashMap::new();

    for (result, finding) in all_findings {
        by_rule
            .entry(finding.rule_id.clone())
            .or_default()
            .push((result, finding));
    }

    let mut rules: Vec<_> = by_rule.into_iter().collect();
    rules.sort_by(|a, b| b.1.len().cmp(&a.1.len())); // Sort by count descending

    let mut displayed = 0;

    for (rule_id, findings) in rules {
        if displayed >= display_limit {
            break;
        }

        // Rule header
        let finding_count = findings.len();
        println!(
            "{} {} ({} findings) {}",
            "--".dimmed(),
            rule_id.cyan().bold(),
            finding_count.to_string().yellow(),
            "-".repeat(50usize.saturating_sub(rule_id.len())).dimmed()
        );

        if options.collapse {
            // Show collapsed summary
            let first = &findings[0];
            let severity_str = format_severity_short(first.1.severity);
            println!(
                "  {} at multiple locations (x{} occurrences)",
                severity_str, finding_count
            );
            println!(
                "    {} First: {}:{}",
                "|->".dimmed(),
                first.0.path.dimmed(),
                first.1.location.start_line.to_string().dimmed()
            );
            if !options.expand {
                println!("    {} Use --expand to see all locations", "|->".dimmed());
            } else {
                for (result, finding) in findings.iter().skip(1).take(5) {
                    println!(
                        "    {} {}:{}",
                        "|->".dimmed(),
                        result.path.dimmed(),
                        finding.location.start_line.to_string().dimmed()
                    );
                }
                if findings.len() > 6 {
                    println!("    {} ... and {} more", "|->".dimmed(), findings.len() - 6);
                }
            }
            displayed += finding_count;
        } else {
            for (result, finding) in findings {
                if displayed >= display_limit {
                    break;
                }
                print_finding_with_file(result, finding);
                displayed += 1;
            }
        }
        println!();
    }

    print_truncation_message(displayed, total_count, options);
}

/// Print findings grouped by severity
fn print_grouped_by_severity(
    all_findings: &[(&FileAnalysis, &Finding)],
    options: &OutputOptions,
    display_limit: usize,
    total_count: usize,
) {
    let severity_order = [
        Severity::Critical,
        Severity::Error,
        Severity::Warning,
        Severity::Info,
    ];

    let mut by_severity: HashMap<Severity, Vec<(&FileAnalysis, &Finding)>> = HashMap::new();

    for (result, finding) in all_findings {
        by_severity
            .entry(finding.severity)
            .or_default()
            .push((result, finding));
    }

    let mut displayed = 0;

    for severity in severity_order {
        if let Some(findings) = by_severity.get(&severity) {
            if displayed >= display_limit {
                break;
            }

            // Severity header
            let severity_name = match severity {
                Severity::Critical => "CRITICAL".red().bold(),
                Severity::Error => "ERROR".bright_red(),
                Severity::Warning => "WARNING".yellow(),
                Severity::Info => "INFO".blue(),
            };
            println!(
                "{} {} ({} findings) {}",
                "--".dimmed(),
                severity_name,
                findings.len().to_string().yellow(),
                "-".repeat(45).dimmed()
            );

            if options.collapse {
                // Group by rule within severity
                let mut by_rule: HashMap<String, Vec<&(&FileAnalysis, &Finding)>> = HashMap::new();
                for item in findings {
                    by_rule
                        .entry(item.1.rule_id.clone())
                        .or_default()
                        .push(item);
                }

                for (rule_id, items) in by_rule {
                    println!(
                        "  {} (x{} in {})",
                        rule_id.dimmed(),
                        items.len(),
                        items[0].0.path.dimmed()
                    );
                }
                displayed += findings.len();
            } else {
                for (result, finding) in findings {
                    if displayed >= display_limit {
                        break;
                    }
                    print_finding_with_file(result, finding);
                    displayed += 1;
                }
            }
            println!();
        }
    }

    print_truncation_message(displayed, total_count, options);
}

/// Print findings as a flat list (no grouping)
fn print_flat_list(
    all_findings: &[(&FileAnalysis, &Finding)],
    options: &OutputOptions,
    display_limit: usize,
    total_count: usize,
) {
    let mut displayed = 0;

    for (result, finding) in all_findings {
        if displayed >= display_limit {
            break;
        }
        print_finding_with_file(result, finding);
        displayed += 1;
    }

    print_truncation_message(displayed, total_count, options);
}

/// Print collapsed findings for a file
fn print_collapsed_findings(findings: &[Finding], file_path: &str) {
    let mut by_rule: HashMap<String, Vec<&Finding>> = HashMap::new();

    for finding in findings {
        by_rule
            .entry(finding.rule_id.clone())
            .or_default()
            .push(finding);
    }

    for (rule_id, rule_findings) in by_rule {
        if rule_findings.len() == 1 {
            print_finding_line(rule_findings[0]);
        } else {
            let first = rule_findings[0];
            println!(
                "  {} at {} (x{} occurrences)",
                rule_id.dimmed(),
                file_path.dimmed(),
                rule_findings.len()
            );
            println!(
                "    {} First: line {}",
                "|->".dimmed(),
                first.location.start_line
            );
            println!("    {} Use --expand to see all locations", "|->".dimmed());
        }
    }
}

/// Print a single finding line (compact format)
fn print_finding_line(finding: &Finding) {
    let severity = format_severity_short(finding.severity);
    let location = format!(
        "{}:{}",
        finding.location.start_line, finding.location.start_column
    );

    println!(
        "  {:>5}  {}  {}  {}  {}",
        location.dimmed(),
        severity,
        finding.source.to_string().dimmed(),
        finding.rule_id.dimmed(),
        truncate(&finding.message, 50)
    );
}

/// Print a finding with file path
fn print_finding_with_file(result: &FileAnalysis, finding: &Finding) {
    let severity = format_severity_short(finding.severity);
    let location = format!(
        "{}:{}:{}",
        result.path, finding.location.start_line, finding.location.start_column
    );

    println!(
        "  {}  {}  {}  {}  {}",
        location.dimmed(),
        severity,
        finding.source.to_string().dimmed(),
        finding.rule_id.cyan(),
        truncate(&finding.message, 40)
    );
}

/// Print truncation message if there are more findings
fn print_truncation_message(displayed: usize, total: usize, _options: &OutputOptions) {
    if displayed < total {
        let remaining = total - displayed;
        println!();
        println!(
            "{}",
            format!(
                "... and {} more findings (use --all to see all, or --limit=N to adjust)",
                remaining
            )
            .dimmed()
        );
        println!();
        println!(
            "{}",
            format!("Showing {}-{} of {} findings.", 1, displayed, total).dimmed()
        );
    }
}

/// Format severity as short colored string
fn format_severity_short(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => "crit".red().bold(),
        Severity::Error => "error".bright_red(),
        Severity::Warning => "warn".yellow(),
        Severity::Info => "info".blue(),
    }
}

/// Format count with severity-appropriate coloring
fn format_count(count: usize, severity: Severity) -> colored::ColoredString {
    if count == 0 {
        count.to_string().dimmed()
    } else {
        match severity {
            Severity::Critical => count.to_string().red().bold(),
            Severity::Error => count.to_string().bright_red(),
            Severity::Warning => count.to_string().yellow(),
            Severity::Info => count.to_string().blue(),
        }
    }
}

/// Output results in compact single-line format
pub fn output_compact(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
) -> Result<()> {
    for result in results {
        for finding in &result.findings {
            let severity_char = match finding.severity {
                Severity::Critical => "C",
                Severity::Error => "E",
                Severity::Warning => "W",
                Severity::Info => "I",
            };
            println!(
                "{}:{}:{}:{}:{}:[{}] {}",
                finding.location.file.display(),
                finding.location.start_line,
                finding.location.start_column,
                severity_char,
                finding.source,
                finding.rule_id,
                finding.message
            );
        }
    }

    eprintln!(
        "\n{} files, {} findings in {:.2}s",
        summary.files_analyzed,
        summary.total_findings,
        duration.as_secs_f64()
    );

    Ok(())
}

// ============================================================================
// Box drawing helpers
// ============================================================================

fn format_box_top(width: usize) -> String {
    format!("{}{}{}", BOX_TL, BOX_H.repeat(width - 2), BOX_TR)
}

fn format_box_bottom(width: usize) -> String {
    format!("{}{}{}", BOX_BL, BOX_H.repeat(width - 2), BOX_BR)
}

fn format_box_separator(width: usize) -> String {
    format!("{}{}{}", BOX_ML, BOX_H.repeat(width - 2), BOX_MR)
}

fn format_box_line(content: &str, width: usize) -> String {
    let visible_len = strip_ansi_codes(content).len();
    let padding = (width - 2).saturating_sub(visible_len);
    format!("{}{}{}{}", BOX_V, content, " ".repeat(padding), BOX_V)
}

// Box drawing characters
const BOX_TL: &str = "\u{2554}"; // top-left corner
const BOX_TR: &str = "\u{2557}"; // top-right corner
const BOX_BL: &str = "\u{255A}"; // bottom-left corner
const BOX_BR: &str = "\u{255D}"; // bottom-right corner
const BOX_H: &str = "\u{2550}"; // horizontal line
const BOX_V: &str = "\u{2551}"; // vertical line
const BOX_ML: &str = "\u{2560}"; // middle-left (T-junction)
const BOX_MR: &str = "\u{2563}"; // middle-right (T-junction)

// ============================================================================
// Utility functions
// ============================================================================

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
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

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else {
        let mins = (secs / 60.0).floor();
        let remaining_secs = secs - (mins * 60.0);
        format!("{}m {:.0}s", mins, remaining_secs)
    }
}

/// Strip ANSI escape codes for length calculation
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::new();
    let mut in_escape = false;

    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs_f64(1.5)), "1.5s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a long string", 10), "this is...");
    }

    #[test]
    fn test_strip_ansi_codes() {
        assert_eq!(strip_ansi_codes("hello"), "hello");
        assert_eq!(strip_ansi_codes("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(
            strip_ansi_codes("\x1b[1m\x1b[32mbold green\x1b[0m"),
            "bold green"
        );
    }

    #[test]
    fn test_box_drawing() {
        let top = format_box_top(20);
        assert!(top.starts_with(BOX_TL));
        assert!(top.ends_with(BOX_TR));

        let bottom = format_box_bottom(20);
        assert!(bottom.starts_with(BOX_BL));
        assert!(bottom.ends_with(BOX_BR));
    }
}
