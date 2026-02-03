//! HTML output formatting
//!
//! Produces self-contained HTML security reports with:
//! - Summary statistics by severity
//! - Filterable findings table with JavaScript interactivity
//! - Breakdown by rule table
//! - Professional styling for team sharing
//! - Responsive design with mobile support

use anyhow::Result;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use rma_common::Severity;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default output filename for HTML reports
pub const DEFAULT_HTML_FILENAME: &str = "rma-report.html";

/// Generate a self-contained HTML report
pub fn output(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    output_file: Option<PathBuf>,
    project_root: Option<&Path>,
) -> Result<()> {
    let html = generate_html(results, summary, duration, project_root);

    if let Some(path) = output_file {
        std::fs::write(&path, &html)?;
        eprintln!("HTML report written to: {}", path.display());
    } else {
        // Write to default file if no output specified
        let default_path = PathBuf::from(DEFAULT_HTML_FILENAME);
        std::fs::write(&default_path, &html)?;
        eprintln!("HTML report written to: {}", default_path.display());
    }

    Ok(())
}

/// Generate the complete HTML report as a string
pub fn generate_html(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    project_root: Option<&Path>,
) -> String {
    let project_name = project_root
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("Project");

    let generated_at = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    // Collect all findings with file context
    let mut all_findings: Vec<FindingRow> = Vec::new();
    for result in results {
        for finding in &result.findings {
            let file_path = finding
                .location
                .file
                .strip_prefix(project_root.unwrap_or(Path::new(".")))
                .unwrap_or(&finding.location.file)
                .display()
                .to_string();

            all_findings.push(FindingRow {
                severity: finding.severity,
                rule_id: finding.rule_id.clone(),
                file: file_path,
                line: finding.location.start_line,
                message: html_escape(&finding.message),
                snippet: finding.snippet.as_ref().map(|s| html_escape(s)),
                suggestion: finding.suggestion.as_ref().map(|s| html_escape(s)),
            });
        }
    }

    // Calculate rule breakdown
    let rule_breakdown = calculate_rule_breakdown(&all_findings);

    // Build HTML
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RMA Security Report - {project_name}</title>
    {css}
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>RMA Security Report</h1>
            <div class="subtitle">{project_name}</div>
            <div class="meta">
                <span>Generated: {generated_at}</span>
                <span>Duration: {duration}</span>
                <span>Files: {files_analyzed}</span>
            </div>
        </header>

        <section class="summary">
            <h2>Summary</h2>
            <div class="stat-cards">
                <div class="stat-card critical">
                    <div class="stat-number">{critical_count}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card error">
                    <div class="stat-number">{error_count}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-number">{warning_count}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{info_count}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            <div class="total-findings">
                Total Findings: <strong>{total_findings}</strong>
            </div>
        </section>

        <section class="findings-section">
            <h2>Findings</h2>
            <div class="filter-buttons">
                <button class="filter-btn active" data-filter="all">All ({total_findings})</button>
                <button class="filter-btn filter-critical" data-filter="critical">Critical ({critical_count})</button>
                <button class="filter-btn filter-error" data-filter="error">High ({error_count})</button>
                <button class="filter-btn filter-warning" data-filter="warning">Medium ({warning_count})</button>
                <button class="filter-btn filter-info" data-filter="info">Low ({info_count})</button>
            </div>
            {findings_table}
        </section>

        <section class="rules-section">
            <h2>Breakdown by Rule</h2>
            {rules_table}
        </section>

        <footer class="footer">
            <p>Generated by RMA (Rust Monorepo Analyzer) v{version}</p>
        </footer>
    </div>
    {javascript}
</body>
</html>"#,
        project_name = html_escape(project_name),
        css = generate_css(),
        generated_at = generated_at,
        duration = format_duration(duration),
        files_analyzed = summary.files_analyzed,
        critical_count = summary.critical_count,
        error_count = summary.error_count,
        warning_count = summary.warning_count,
        info_count = summary.info_count,
        total_findings = summary.total_findings,
        findings_table = generate_findings_table(&all_findings),
        rules_table = generate_rules_table(&rule_breakdown),
        version = env!("CARGO_PKG_VERSION"),
        javascript = generate_javascript(),
    )
}

struct FindingRow {
    severity: Severity,
    rule_id: String,
    file: String,
    line: usize,
    message: String,
    snippet: Option<String>,
    suggestion: Option<String>,
}

struct RuleStats {
    rule_id: String,
    count: usize,
    critical: usize,
    error: usize,
    warning: usize,
    info: usize,
}

fn calculate_rule_breakdown(findings: &[FindingRow]) -> Vec<RuleStats> {
    let mut stats_map: HashMap<String, RuleStats> = HashMap::new();

    for finding in findings {
        let entry = stats_map
            .entry(finding.rule_id.clone())
            .or_insert(RuleStats {
                rule_id: finding.rule_id.clone(),
                count: 0,
                critical: 0,
                error: 0,
                warning: 0,
                info: 0,
            });

        entry.count += 1;
        match finding.severity {
            Severity::Critical => entry.critical += 1,
            Severity::Error => entry.error += 1,
            Severity::Warning => entry.warning += 1,
            Severity::Info => entry.info += 1,
        }
    }

    let mut stats: Vec<RuleStats> = stats_map.into_values().collect();
    stats.sort_by(|a, b| b.count.cmp(&a.count));
    stats
}

fn generate_findings_table(findings: &[FindingRow]) -> String {
    if findings.is_empty() {
        return r#"<div class="no-findings">No findings detected. Great job!</div>"#.to_string();
    }

    let mut rows = String::new();
    for finding in findings {
        let severity_class = match finding.severity {
            Severity::Critical => "critical",
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };

        let severity_label = match finding.severity {
            Severity::Critical => "Critical",
            Severity::Error => "High",
            Severity::Warning => "Medium",
            Severity::Info => "Low",
        };

        let details = if finding.snippet.is_some() || finding.suggestion.is_some() {
            let mut detail_html = String::new();
            if let Some(ref snippet) = finding.snippet {
                detail_html.push_str(&format!(
                    r#"<div class="snippet"><code>{}</code></div>"#,
                    snippet
                ));
            }
            if let Some(ref suggestion) = finding.suggestion {
                detail_html.push_str(&format!(
                    r#"<div class="suggestion">Suggestion: {}</div>"#,
                    suggestion
                ));
            }
            format!(r#"<div class="finding-details">{}</div>"#, detail_html)
        } else {
            String::new()
        };

        rows.push_str(&format!(
            r#"<tr class="finding-row" data-severity="{severity_class}">
                <td><span class="badge badge-{severity_class}">{severity_label}</span></td>
                <td class="rule-id">{rule_id}</td>
                <td class="file-path">{file}</td>
                <td class="line-number">{line}</td>
                <td class="message">{message}{details}</td>
            </tr>"#,
            severity_class = severity_class,
            severity_label = severity_label,
            rule_id = html_escape(&finding.rule_id),
            file = html_escape(&finding.file),
            line = finding.line,
            message = finding.message,
            details = details,
        ));
    }

    format!(
        r#"<div class="table-wrapper">
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Rule ID</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>"#,
        rows = rows
    )
}

fn generate_rules_table(rules: &[RuleStats]) -> String {
    if rules.is_empty() {
        return r#"<div class="no-findings">No rules triggered.</div>"#.to_string();
    }

    let mut rows = String::new();
    for rule in rules {
        rows.push_str(&format!(
            r#"<tr>
                <td class="rule-id">{rule_id}</td>
                <td class="count">{count}</td>
                <td class="count critical-count">{critical}</td>
                <td class="count error-count">{error}</td>
                <td class="count warning-count">{warning}</td>
                <td class="count info-count">{info}</td>
            </tr>"#,
            rule_id = html_escape(&rule.rule_id),
            count = rule.count,
            critical = rule.critical,
            error = rule.error,
            warning = rule.warning,
            info = rule.info,
        ));
    }

    format!(
        r#"<div class="table-wrapper">
            <table class="rules-table">
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Total</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>"#,
        rows = rows
    )
}

fn generate_css() -> &'static str {
    r#"<style>
:root {
    --critical-color: #dc2626;
    --critical-bg: #fef2f2;
    --error-color: #ea580c;
    --error-bg: #fff7ed;
    --warning-color: #ca8a04;
    --warning-bg: #fefce8;
    --info-color: #2563eb;
    --info-bg: #eff6ff;
    --text-primary: #1f2937;
    --text-secondary: #6b7280;
    --bg-primary: #ffffff;
    --bg-secondary: #f9fafb;
    --border-color: #e5e7eb;
    --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    color: var(--text-primary);
    background-color: var(--bg-secondary);
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 2rem;
}

.header {
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
    color: white;
    padding: 2rem;
    border-radius: 12px;
    margin-bottom: 2rem;
    box-shadow: var(--shadow-lg);
}

.header h1 {
    font-size: 2rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
}

.header .subtitle {
    font-size: 1.25rem;
    opacity: 0.9;
    margin-bottom: 1rem;
}

.header .meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    font-size: 0.875rem;
    opacity: 0.8;
}

.summary, .findings-section, .rules-section {
    background: var(--bg-primary);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: var(--shadow);
}

h2 {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 1.25rem;
    padding-bottom: 0.75rem;
    border-bottom: 2px solid var(--border-color);
}

.stat-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1rem;
    margin-bottom: 1rem;
}

.stat-card {
    padding: 1.25rem;
    border-radius: 8px;
    text-align: center;
    transition: transform 0.2s ease;
}

.stat-card:hover {
    transform: translateY(-2px);
}

.stat-card.critical {
    background: var(--critical-bg);
    border: 1px solid var(--critical-color);
}

.stat-card.critical .stat-number {
    color: var(--critical-color);
}

.stat-card.error {
    background: var(--error-bg);
    border: 1px solid var(--error-color);
}

.stat-card.error .stat-number {
    color: var(--error-color);
}

.stat-card.warning {
    background: var(--warning-bg);
    border: 1px solid var(--warning-color);
}

.stat-card.warning .stat-number {
    color: var(--warning-color);
}

.stat-card.info {
    background: var(--info-bg);
    border: 1px solid var(--info-color);
}

.stat-card.info .stat-number {
    color: var(--info-color);
}

.stat-number {
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 0.5rem;
}

.stat-label {
    font-size: 0.875rem;
    font-weight: 500;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.total-findings {
    text-align: center;
    font-size: 1rem;
    color: var(--text-secondary);
    padding-top: 1rem;
    border-top: 1px solid var(--border-color);
}

.filter-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.filter-btn {
    padding: 0.5rem 1rem;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    background: var(--bg-primary);
    color: var(--text-secondary);
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.2s ease;
}

.filter-btn:hover {
    border-color: #3b82f6;
    color: #3b82f6;
}

.filter-btn.active {
    background: #3b82f6;
    border-color: #3b82f6;
    color: white;
}

.filter-btn.filter-critical.active {
    background: var(--critical-color);
    border-color: var(--critical-color);
}

.filter-btn.filter-error.active {
    background: var(--error-color);
    border-color: var(--error-color);
}

.filter-btn.filter-warning.active {
    background: var(--warning-color);
    border-color: var(--warning-color);
}

.filter-btn.filter-info.active {
    background: var(--info-color);
    border-color: var(--info-color);
}

.table-wrapper {
    overflow-x: auto;
}

.findings-table, .rules-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
}

.findings-table th, .findings-table td,
.rules-table th, .rules-table td {
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}

.findings-table th, .rules-table th {
    background: var(--bg-secondary);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
}

.finding-row:hover {
    background: var(--bg-secondary);
}

.finding-row.hidden {
    display: none;
}

.badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.025em;
}

.badge-critical {
    background: var(--critical-bg);
    color: var(--critical-color);
    border: 1px solid var(--critical-color);
}

.badge-error {
    background: var(--error-bg);
    color: var(--error-color);
    border: 1px solid var(--error-color);
}

.badge-warning {
    background: var(--warning-bg);
    color: var(--warning-color);
    border: 1px solid var(--warning-color);
}

.badge-info {
    background: var(--info-bg);
    color: var(--info-color);
    border: 1px solid var(--info-color);
}

.rule-id {
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 0.8rem;
    color: var(--text-secondary);
}

.file-path {
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 0.8rem;
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.line-number {
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    text-align: center;
    color: var(--text-secondary);
}

.message {
    max-width: 400px;
}

.finding-details {
    margin-top: 0.5rem;
    padding-top: 0.5rem;
    border-top: 1px dashed var(--border-color);
}

.snippet {
    background: var(--bg-secondary);
    padding: 0.5rem;
    border-radius: 4px;
    margin-bottom: 0.5rem;
    overflow-x: auto;
}

.snippet code {
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    font-size: 0.8rem;
    white-space: pre-wrap;
    word-break: break-all;
}

.suggestion {
    font-style: italic;
    color: var(--info-color);
    font-size: 0.85rem;
}

.count {
    text-align: center;
    font-weight: 600;
}

.critical-count { color: var(--critical-color); }
.error-count { color: var(--error-color); }
.warning-count { color: var(--warning-color); }
.info-count { color: var(--info-color); }

.no-findings {
    text-align: center;
    padding: 3rem;
    color: #059669;
    font-size: 1.125rem;
    background: #ecfdf5;
    border-radius: 8px;
    border: 1px solid #059669;
}

.footer {
    text-align: center;
    padding: 1.5rem;
    color: var(--text-secondary);
    font-size: 0.875rem;
}

@media (max-width: 768px) {
    .container {
        padding: 1rem;
    }

    .header {
        padding: 1.5rem;
    }

    .header h1 {
        font-size: 1.5rem;
    }

    .header .meta {
        flex-direction: column;
        gap: 0.5rem;
    }

    .stat-cards {
        grid-template-columns: repeat(2, 1fr);
    }

    .stat-number {
        font-size: 2rem;
    }

    .filter-buttons {
        overflow-x: auto;
        flex-wrap: nowrap;
        -webkit-overflow-scrolling: touch;
    }

    .filter-btn {
        flex-shrink: 0;
    }

    .file-path {
        max-width: 150px;
    }

    .message {
        max-width: 200px;
    }
}

@media print {
    .filter-buttons {
        display: none;
    }

    .finding-row.hidden {
        display: table-row !important;
    }

    .container {
        max-width: 100%;
    }

    .header {
        background: #1e40af !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }
}
</style>"#
}

fn generate_javascript() -> &'static str {
    r#"<script>
document.addEventListener('DOMContentLoaded', function() {
    const filterButtons = document.querySelectorAll('.filter-btn');
    const findingRows = document.querySelectorAll('.finding-row');

    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.dataset.filter;

            // Update active button
            filterButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');

            // Filter rows
            findingRows.forEach(row => {
                if (filter === 'all') {
                    row.classList.remove('hidden');
                } else {
                    const severity = row.dataset.severity;
                    if (severity === filter) {
                        row.classList.remove('hidden');
                    } else {
                        row.classList.add('hidden');
                    }
                }
            });
        });
    });
});
</script>"#
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Format duration for display
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.2}s", secs)
    } else {
        let mins = (secs / 60.0).floor();
        let remaining_secs = secs - (mins * 60.0);
        format!("{}m {:.0}s", mins as u64, remaining_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::{CodeMetrics, Finding, SourceLocation};
    use std::path::PathBuf;

    fn create_test_finding(severity: Severity, rule_id: &str, message: &str) -> Finding {
        Finding {
            id: format!("test-{}", rule_id.replace('/', "-")),
            rule_id: rule_id.to_string(),
            message: message.to_string(),
            severity,
            location: SourceLocation::new(PathBuf::from("test.rs"), 10, 1, 10, 20),
            language: rma_common::Language::Rust,
            snippet: Some("let x = dangerous();".to_string()),
            suggestion: Some("Use safe_function instead".to_string()),
            fix: None,
            confidence: rma_common::Confidence::High,
            category: rma_common::FindingCategory::Security,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        }
    }

    fn create_test_results() -> (Vec<FileAnalysis>, AnalysisSummary) {
        let findings = vec![
            create_test_finding(
                Severity::Critical,
                "security/sql-injection",
                "SQL injection vulnerability",
            ),
            create_test_finding(Severity::Error, "security/xss", "Cross-site scripting"),
            create_test_finding(
                Severity::Warning,
                "security/weak-hash",
                "Weak hash algorithm",
            ),
            create_test_finding(Severity::Info, "style/naming", "Non-standard naming"),
        ];

        let results = vec![FileAnalysis {
            path: "src/main.rs".to_string(),
            language: rma_common::Language::Rust,
            metrics: CodeMetrics::default(),
            findings: findings.clone(),
        }];

        let summary = AnalysisSummary {
            files_analyzed: 1,
            total_findings: 4,
            total_loc: 100,
            total_complexity: 5,
            critical_count: 1,
            error_count: 1,
            warning_count: 1,
            info_count: 1,
        };

        (results, summary)
    }

    #[test]
    fn test_html_contains_doctype() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.starts_with("<!DOCTYPE html>"));
    }

    #[test]
    fn test_html_ends_with_closing_tag() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.trim().ends_with("</html>"));
    }

    #[test]
    fn test_html_contains_findings() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("SQL injection vulnerability"));
        assert!(html.contains("Cross-site scripting"));
        assert!(html.contains("Weak hash algorithm"));
        assert!(html.contains("Non-standard naming"));
    }

    #[test]
    fn test_html_contains_severity_badges() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("badge-critical"));
        assert!(html.contains("badge-error"));
        assert!(html.contains("badge-warning"));
        assert!(html.contains("badge-info"));
    }

    #[test]
    fn test_html_contains_rule_ids() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("security/sql-injection"));
        assert!(html.contains("security/xss"));
        assert!(html.contains("security/weak-hash"));
        assert!(html.contains("style/naming"));
    }

    #[test]
    fn test_html_contains_summary_stats() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        // Check for stat cards
        assert!(html.contains(r#"class="stat-card critical""#));
        assert!(html.contains(r#"class="stat-card error""#));
        assert!(html.contains(r#"class="stat-card warning""#));
        assert!(html.contains(r#"class="stat-card info""#));
    }

    #[test]
    fn test_html_contains_filter_buttons() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains(r#"data-filter="all""#));
        assert!(html.contains(r#"data-filter="critical""#));
        assert!(html.contains(r#"data-filter="error""#));
        assert!(html.contains(r#"data-filter="warning""#));
        assert!(html.contains(r#"data-filter="info""#));
    }

    #[test]
    fn test_html_contains_javascript() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("<script>"));
        assert!(html.contains("addEventListener"));
        assert!(html.contains("</script>"));
    }

    #[test]
    fn test_html_contains_css() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("<style>"));
        assert!(html.contains("</style>"));
        assert!(html.contains(":root"));
    }

    #[test]
    fn test_html_escapes_special_characters() {
        let escaped = html_escape("<script>alert('xss')</script>");
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_html_contains_rules_breakdown() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("Breakdown by Rule"));
        assert!(html.contains(r#"class="rules-table""#));
    }

    #[test]
    fn test_empty_findings_shows_success_message() {
        let results: Vec<FileAnalysis> = vec![];
        let summary = AnalysisSummary {
            files_analyzed: 5,
            total_findings: 0,
            total_loc: 500,
            total_complexity: 10,
            critical_count: 0,
            error_count: 0,
            warning_count: 0,
            info_count: 0,
        };

        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("No findings detected"));
    }

    #[test]
    fn test_format_duration_milliseconds() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(5)), "5.00s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(125)), "2m 5s");
    }

    #[test]
    fn test_html_is_responsive() {
        let (results, summary) = create_test_results();
        let html = generate_html(&results, &summary, Duration::from_secs(1), None);

        assert!(html.contains("@media (max-width: 768px)"));
        assert!(html.contains(r#"name="viewport""#));
    }
}
