//! Pretty output formatting for findings
//!
//! Provides beautiful, colored output with:
//! - Severity-based colors and icons
//! - Code snippets with context
//! - Diff-style suggestions
//! - Box drawing for grouped output
//! - Multiple output formats (Pretty, Compact, JSON, SARIF, GitHub)

#![allow(dead_code)] // Module is new and not yet fully integrated

use crate::output::diagnostics::SourceCache;
use colored::{Color, Colorize};
use rma_common::{Finding, Fix, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ============================================================================
// Configuration
// ============================================================================

/// Output format options
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PrettyFormat {
    /// Full colored output with snippets
    #[default]
    Pretty,
    /// One line per finding
    Compact,
    /// JSON output
    Json,
    /// SARIF format
    Sarif,
    /// GitHub Actions annotations
    Github,
}

/// Configuration for pretty output
#[derive(Clone, Debug)]
pub struct PrettyConfig {
    /// Output format
    pub format: PrettyFormat,
    /// Number of context lines before/after the finding
    pub context_lines: usize,
    /// Whether to show suggestions
    pub show_suggestions: bool,
    /// Whether to show notes (confidence, CWE, etc.)
    pub show_notes: bool,
    /// Whether to use colors
    pub use_colors: bool,
    /// Whether to use Unicode characters (emojis, box drawing)
    pub use_unicode: bool,
    /// Terminal width (0 = auto-detect)
    pub terminal_width: usize,
    /// Whether to group findings by file
    pub group_by_file: bool,
}

impl Default for PrettyConfig {
    fn default() -> Self {
        Self {
            format: PrettyFormat::Pretty,
            context_lines: 2,
            show_suggestions: true,
            show_notes: true,
            use_colors: Self::supports_color(),
            use_unicode: Self::supports_unicode(),
            terminal_width: 0, // Auto-detect
            group_by_file: true,
        }
    }
}

impl PrettyConfig {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a compact configuration for CI
    pub fn compact() -> Self {
        Self {
            format: PrettyFormat::Compact,
            context_lines: 0,
            show_suggestions: false,
            show_notes: false,
            use_colors: false,
            use_unicode: false,
            terminal_width: 0,
            group_by_file: false,
        }
    }

    /// Check if the terminal supports colors
    fn supports_color() -> bool {
        // Check for common environment variables that disable color
        if std::env::var("NO_COLOR").is_ok() {
            return false;
        }
        if std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false) {
            return false;
        }
        // Check if stdout is a terminal
        atty_check()
    }

    /// Check if the terminal supports Unicode
    fn supports_unicode() -> bool {
        // Check for UTF-8 locale
        std::env::var("LANG")
            .map(|l| l.contains("UTF-8") || l.contains("utf-8") || l.contains("utf8"))
            .unwrap_or(false)
            || std::env::var("LC_ALL")
                .map(|l| l.contains("UTF-8") || l.contains("utf-8") || l.contains("utf8"))
                .unwrap_or(false)
            || cfg!(target_os = "macos") // macOS typically supports Unicode
    }

    /// Get the terminal width
    pub fn get_terminal_width(&self) -> usize {
        if self.terminal_width > 0 {
            return self.terminal_width;
        }
        get_terminal_width()
    }
}

/// Check if stdout is a TTY
fn atty_check() -> bool {
    // Use crossterm's tty check which works cross-platform
    crossterm::tty::IsTty::is_tty(&std::io::stdout())
}

/// Get terminal width using crossterm
fn get_terminal_width() -> usize {
    crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(80)
}

// ============================================================================
// Severity Styling
// ============================================================================

/// Get color and icon for a severity level
pub fn severity_style(severity: Severity) -> (Color, &'static str) {
    match severity {
        Severity::Critical => (Color::Red, "\u{1F534}"), // Red circle emoji
        Severity::Error => (Color::Red, "\u{274C}"),     // X mark emoji
        Severity::Warning => (Color::Yellow, "\u{26A0}\u{FE0F}"), // Warning emoji
        Severity::Info => (Color::Blue, "\u{2139}\u{FE0F}"), // Info emoji
    }
}

/// Get ASCII-safe icon for severity (fallback)
pub fn severity_icon_ascii(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "[!!]",
        Severity::Error => "[E]",
        Severity::Warning => "[W]",
        Severity::Info => "[i]",
    }
}

/// Get the severity word
pub fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

/// Colorize text based on severity
pub fn colorize_severity(text: &str, severity: Severity, use_colors: bool) -> String {
    if !use_colors {
        return text.to_string();
    }
    match severity {
        Severity::Critical => text.red().bold().to_string(),
        Severity::Error => text.red().bold().to_string(),
        Severity::Warning => text.yellow().bold().to_string(),
        Severity::Info => text.blue().to_string(),
    }
}

// ============================================================================
// Pretty Finding Renderer
// ============================================================================

/// Renders findings in a beautiful format
pub struct PrettyRenderer {
    config: PrettyConfig,
}

impl PrettyRenderer {
    /// Create a new pretty renderer
    pub fn new() -> Self {
        Self {
            config: PrettyConfig::default(),
        }
    }

    /// Create a renderer with custom configuration
    pub fn with_config(config: PrettyConfig) -> Self {
        Self { config }
    }

    /// Render a single finding
    pub fn render_finding(&self, finding: &Finding, cache: &mut SourceCache) -> String {
        match self.config.format {
            PrettyFormat::Pretty => self.render_pretty(finding, cache),
            PrettyFormat::Compact => self.render_compact(finding),
            PrettyFormat::Json => self.render_json(finding),
            PrettyFormat::Sarif => self.render_sarif(finding),
            PrettyFormat::Github => self.render_github(finding),
        }
    }

    /// Render multiple findings
    pub fn render_findings(&self, findings: &[Finding], cache: &mut SourceCache) -> String {
        match self.config.format {
            PrettyFormat::Pretty if self.config.group_by_file => {
                self.render_grouped(findings, cache)
            }
            _ => findings
                .iter()
                .map(|f| self.render_finding(f, cache))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    // ========================================================================
    // Pretty Format
    // ========================================================================

    /// Render finding in pretty format
    fn render_pretty(&self, finding: &Finding, cache: &mut SourceCache) -> String {
        let mut output = String::new();

        // Header line: icon severity[rule]: message
        output.push_str(&self.format_header(finding));
        output.push('\n');

        // Location: --> file:line:col
        output.push_str(&self.format_location(finding));
        output.push('\n');

        // Code snippet with context
        if let Some(source) = cache.get(&finding.location.file) {
            output.push_str(&self.format_snippet(finding, &source.content));
        } else if let Some(snippet) = &finding.snippet {
            // Fallback to embedded snippet
            output.push_str(&self.format_fallback_snippet(finding, snippet));
        }

        // Suggestion / Fix
        if self.config.show_suggestions {
            if let Some(fix) = &finding.fix {
                output.push_str(&self.format_fix(finding, fix, cache));
            } else if let Some(suggestion) = &finding.suggestion {
                output.push_str(&self.format_suggestion(suggestion));
            }
        }

        // Notes (CWE, confidence, category)
        if self.config.show_notes {
            output.push_str(&self.format_notes(finding));
        }

        output
    }

    /// Format the header line
    fn format_header(&self, finding: &Finding) -> String {
        let (color, icon) = severity_style(finding.severity);
        let severity = severity_word(finding.severity);

        let icon_str = if self.config.use_unicode {
            format!("{} ", icon)
        } else {
            format!("{} ", severity_icon_ascii(finding.severity))
        };

        if self.config.use_colors {
            format!(
                "{}{}[{}]: {}",
                icon_str,
                severity.color(color).bold(),
                finding.rule_id.color(color).bold(),
                finding.message
            )
        } else {
            format!(
                "{}{}[{}]: {}",
                icon_str, severity, finding.rule_id, finding.message
            )
        }
    }

    /// Format the location line
    fn format_location(&self, finding: &Finding) -> String {
        let loc = &finding.location;
        let arrow = if self.config.use_unicode {
            "\u{250C}\u{2500}"
        } else {
            "-->"
        };

        if self.config.use_colors {
            format!(
                "   {} {}:{}:{}",
                arrow.blue().bold(),
                loc.file.display(),
                loc.start_line,
                loc.start_column
            )
        } else {
            format!(
                "   {} {}:{}:{}",
                arrow,
                loc.file.display(),
                loc.start_line,
                loc.start_column
            )
        }
    }

    /// Format code snippet with context
    fn format_snippet(&self, finding: &Finding, source: &str) -> String {
        let mut output = String::new();
        let lines: Vec<&str> = source.lines().collect();
        let loc = &finding.location;

        // Calculate line range with context
        let start_line = loc
            .start_line
            .saturating_sub(self.config.context_lines)
            .max(1);
        let end_line = (loc.end_line + self.config.context_lines).min(lines.len());

        // Calculate gutter width
        let gutter_width = end_line.to_string().len();

        // Add empty gutter line
        output.push_str(&self.format_gutter_line(gutter_width, None, false));
        output.push('\n');

        for line_num in start_line..=end_line {
            if line_num > lines.len() {
                break;
            }

            let line_content = lines.get(line_num - 1).unwrap_or(&"");
            let in_span = line_num >= loc.start_line && line_num <= loc.end_line;

            // Line with gutter
            output.push_str(&self.format_code_line(gutter_width, line_num, line_content, in_span));
            output.push('\n');

            // Underline for highlighted lines
            if in_span && line_num == loc.start_line {
                let underline = self.create_underline(
                    finding,
                    line_content,
                    if loc.start_line == loc.end_line {
                        Some((loc.start_column, loc.end_column))
                    } else {
                        Some((loc.start_column, line_content.len() + 1))
                    },
                );
                output.push_str(&self.format_gutter_line(gutter_width, None, true));
                output.push_str(&underline);
                output.push('\n');

                // Label line
                if let Some(label) = self.get_finding_label(finding) {
                    let padding = " ".repeat(loc.start_column);
                    let pipe = if self.config.use_unicode {
                        "\u{2502}"
                    } else {
                        "|"
                    };
                    output.push_str(&self.format_gutter_line(gutter_width, None, true));
                    output.push_str(&format!(
                        "{}{}",
                        padding,
                        if self.config.use_colors {
                            colorize_severity(pipe, finding.severity, true)
                        } else {
                            pipe.to_string()
                        }
                    ));
                    output.push('\n');
                    output.push_str(&self.format_gutter_line(gutter_width, None, true));
                    output.push_str(&format!(
                        "{}{}",
                        padding,
                        if self.config.use_colors {
                            colorize_severity(&label, finding.severity, true)
                        } else {
                            label
                        }
                    ));
                    output.push('\n');
                }
            }
        }

        // Add empty gutter line at end
        output.push_str(&self.format_gutter_line(gutter_width, None, false));
        output.push('\n');

        output
    }

    /// Format a gutter line
    fn format_gutter_line(&self, width: usize, line_num: Option<usize>, highlight: bool) -> String {
        let gutter = if let Some(num) = line_num {
            format!("{:>width$}", num, width = width)
        } else {
            " ".repeat(width)
        };

        let pipe = if self.config.use_unicode {
            "\u{2502}"
        } else {
            "|"
        };

        if self.config.use_colors {
            if highlight {
                format!("{} {} ", gutter.blue(), pipe.blue().bold())
            } else {
                format!("{} {} ", gutter.blue(), pipe.blue())
            }
        } else {
            format!("{} {} ", gutter, pipe)
        }
    }

    /// Format a code line with gutter
    fn format_code_line(
        &self,
        gutter_width: usize,
        line_num: usize,
        content: &str,
        in_span: bool,
    ) -> String {
        let gutter = format!("{:>width$}", line_num, width = gutter_width);
        let pipe = if self.config.use_unicode {
            "\u{2502}"
        } else {
            "|"
        };

        if self.config.use_colors {
            if in_span {
                format!("{} {} {}", gutter.blue(), pipe.blue().bold(), content)
            } else {
                format!("{} {} {}", gutter.blue(), pipe.blue(), content.dimmed())
            }
        } else {
            format!("{} {} {}", gutter, pipe, content)
        }
    }

    /// Create underline for a span
    fn create_underline(
        &self,
        finding: &Finding,
        _line: &str,
        range: Option<(usize, usize)>,
    ) -> String {
        let (start, end) = range.unwrap_or((1, 10));
        let padding = " ".repeat(start.saturating_sub(1));
        let underline_char = "^";
        let underline_len = end.saturating_sub(start).max(1);
        let underline = underline_char.repeat(underline_len);

        if self.config.use_colors {
            format!(
                "{}{}",
                padding,
                colorize_severity(&underline, finding.severity, true)
            )
        } else {
            format!("{}{}", padding, underline)
        }
    }

    /// Get a contextual label for the finding
    fn get_finding_label(&self, finding: &Finding) -> Option<String> {
        let label = match finding.rule_id.as_str() {
            s if s.contains("sql-injection") => "SQL query built from untrusted input",
            s if s.contains("command-injection") || s.contains("shell-injection") => {
                "Shell command built from untrusted input"
            }
            s if s.contains("xss") || s.contains("innerhtml") => "XSS sink - sanitize input",
            s if s.contains("eval") || s.contains("dynamic-execution") => "Dynamic code execution",
            s if s.contains("secret") || s.contains("password") => "Sensitive data exposed",
            s if s.contains("unsafe") => "Unsafe block requires review",
            s if s.contains("unwrap") || s.contains("expect") => "This can panic at runtime",
            _ => return None,
        };
        Some(label.to_string())
    }

    /// Format fallback snippet when source is not available
    fn format_fallback_snippet(&self, _finding: &Finding, snippet: &str) -> String {
        let pipe = if self.config.use_unicode {
            "\u{2502}"
        } else {
            "|"
        };

        if self.config.use_colors {
            format!("   {} {}\n", pipe.blue(), snippet.dimmed())
        } else {
            format!("   {} {}\n", pipe, snippet)
        }
    }

    /// Format a fix with diff-style display
    fn format_fix(&self, finding: &Finding, fix: &Fix, cache: &mut SourceCache) -> String {
        let mut output = String::new();

        let eq = if self.config.use_colors {
            "=".blue().bold().to_string()
        } else {
            "=".to_string()
        };

        output.push_str(&format!(
            "   {} {}: {}\n",
            eq,
            "suggestion".bold(),
            fix.description
        ));

        // Try to show diff
        if let Some(source) = cache.get(&finding.location.file) {
            if fix.start_byte < source.content.len() && fix.end_byte <= source.content.len() {
                let original = &source.content[fix.start_byte..fix.end_byte];

                // Format as diff
                let minus = if self.config.use_colors {
                    "-".red().to_string()
                } else {
                    "-".to_string()
                };
                let plus = if self.config.use_colors {
                    "+".green().to_string()
                } else {
                    "+".to_string()
                };

                for line in original.lines() {
                    if self.config.use_colors {
                        output.push_str(&format!("     {} {}\n", minus, line.red()));
                    } else {
                        output.push_str(&format!("     {} {}\n", minus, line));
                    }
                }
                for line in fix.replacement.lines() {
                    if self.config.use_colors {
                        output.push_str(&format!("     {} {}\n", plus, line.green()));
                    } else {
                        output.push_str(&format!("     {} {}\n", plus, line));
                    }
                }
            }
        }

        output
    }

    /// Format a suggestion
    fn format_suggestion(&self, suggestion: &str) -> String {
        let eq = if self.config.use_colors {
            "=".blue().bold().to_string()
        } else {
            "=".to_string()
        };
        let help = if self.config.use_colors {
            "help".bold().to_string()
        } else {
            "help".to_string()
        };
        let suggestion_colored = if self.config.use_colors {
            suggestion.green().to_string()
        } else {
            suggestion.to_string()
        };

        format!("   {} {}: {}\n", eq, help, suggestion_colored)
    }

    /// Format notes (CWE, confidence, category)
    fn format_notes(&self, finding: &Finding) -> String {
        let eq = if self.config.use_colors {
            "=".blue().bold().to_string()
        } else {
            "=".to_string()
        };

        let mut parts = Vec::new();

        // Add category
        parts.push(format!("{}", finding.category));

        // Add confidence
        parts.push(format!("Confidence: {}", finding.confidence));

        // Check for CWE in properties
        if let Some(props) = &finding.properties {
            if let Some(cwe) = props.get("cwe") {
                if let Some(cwe_str) = cwe.as_str() {
                    parts.push(cwe_str.to_string());
                }
            }
        }

        if self.config.use_colors {
            format!(
                "   {} {}: {}\n",
                eq,
                "note".bold(),
                parts.join(" | ").dimmed()
            )
        } else {
            format!("   {} note: {}\n", eq, parts.join(" | "))
        }
    }

    // ========================================================================
    // Compact Format
    // ========================================================================

    /// Render finding in compact format (one line per finding)
    fn render_compact(&self, finding: &Finding) -> String {
        let severity_char = match finding.severity {
            Severity::Critical => "critical",
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };

        format!(
            "{}:{}:{}: {}[{}] {}",
            finding.location.file.display(),
            finding.location.start_line,
            finding.location.start_column,
            severity_char,
            finding.rule_id,
            finding.message
        )
    }

    // ========================================================================
    // JSON Format
    // ========================================================================

    /// Render finding as JSON
    fn render_json(&self, finding: &Finding) -> String {
        serde_json::to_string_pretty(finding).unwrap_or_else(|_| "{}".to_string())
    }

    // ========================================================================
    // SARIF Format
    // ========================================================================

    /// Render finding in SARIF format (simplified)
    fn render_sarif(&self, finding: &Finding) -> String {
        // This is a simplified SARIF result - full SARIF needs the complete document structure
        serde_json::json!({
            "ruleId": finding.rule_id,
            "level": match finding.severity {
                Severity::Critical | Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "note"
            },
            "message": {
                "text": finding.message
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.location.file.display().to_string()
                    },
                    "region": {
                        "startLine": finding.location.start_line,
                        "startColumn": finding.location.start_column,
                        "endLine": finding.location.end_line,
                        "endColumn": finding.location.end_column
                    }
                }
            }]
        })
        .to_string()
    }

    // ========================================================================
    // GitHub Actions Format
    // ========================================================================

    /// Render finding as GitHub Actions annotation
    fn render_github(&self, finding: &Finding) -> String {
        let level = match finding.severity {
            Severity::Critical | Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "notice",
        };

        let file = finding.location.file.display().to_string();
        let message = finding
            .message
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");

        format!(
            "::{} file={},line={},col={},endLine={},endColumn={},title={}::{}",
            level,
            file,
            finding.location.start_line,
            finding.location.start_column,
            finding.location.end_line,
            finding.location.end_column,
            finding.rule_id,
            message
        )
    }

    // ========================================================================
    // Grouped Output
    // ========================================================================

    /// Render findings grouped by file with box drawing
    fn render_grouped(&self, findings: &[Finding], cache: &mut SourceCache) -> String {
        let mut output = String::new();

        // Group by file
        let mut by_file: HashMap<PathBuf, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            by_file
                .entry(finding.location.file.clone())
                .or_default()
                .push(finding);
        }

        let terminal_width = self.config.get_terminal_width();

        for (file, file_findings) in by_file.iter() {
            output.push_str(&self.render_file_group(file, file_findings, terminal_width, cache));
            output.push('\n');
        }

        output
    }

    /// Render a group of findings for a single file
    fn render_file_group(
        &self,
        file: &Path,
        findings: &[&Finding],
        width: usize,
        cache: &mut SourceCache,
    ) -> String {
        let mut output = String::new();

        // Box characters
        let (tl, tr, bl, br, h, v) = if self.config.use_unicode {
            (
                "\u{250C}", "\u{2510}", "\u{2514}", "\u{2518}", "\u{2500}", "\u{2502}",
            )
        } else {
            ("+", "+", "+", "+", "-", "|")
        };
        let (lt, rt) = if self.config.use_unicode {
            ("\u{251C}", "\u{2524}")
        } else {
            ("+", "+")
        };

        let inner_width = width.saturating_sub(4).min(76);

        // Header: file path and count
        let file_str = file.display().to_string();
        let count_str = format!("{} issues", findings.len());
        let padding = inner_width.saturating_sub(file_str.len() + count_str.len());

        // Top border
        let top_border = format!("{}{}{}", tl, h.repeat(inner_width + 2), tr);
        if self.config.use_colors {
            output.push_str(&top_border.cyan().to_string());
        } else {
            output.push_str(&top_border);
        }
        output.push('\n');

        // File header
        let header = format!(
            "{} {}{}{} {}",
            v,
            file_str,
            " ".repeat(padding),
            count_str,
            v
        );
        if self.config.use_colors {
            output.push_str(&header.cyan().to_string());
        } else {
            output.push_str(&header);
        }
        output.push('\n');

        // Separator
        let sep = format!("{}{}{}", lt, h.repeat(inner_width + 2), rt);
        if self.config.use_colors {
            output.push_str(&sep.cyan().to_string());
        } else {
            output.push_str(&sep);
        }
        output.push('\n');

        // Findings as compact rows
        for finding in findings {
            let loc = format!(
                "{}:{}",
                finding.location.start_line, finding.location.start_column
            );
            let icon = if self.config.use_unicode {
                severity_style(finding.severity).1
            } else {
                severity_icon_ascii(finding.severity)
            };

            // Truncate rule_id and message to fit
            let rule_id = if finding.rule_id.len() > 16 {
                format!("{}...", &finding.rule_id[..13])
            } else {
                finding.rule_id.clone()
            };

            let max_msg_len = inner_width.saturating_sub(loc.len() + rule_id.len() + 10);
            let msg = if finding.message.len() > max_msg_len {
                format!("{}...", &finding.message[..max_msg_len.saturating_sub(3)])
            } else {
                finding.message.clone()
            };

            let row = format!("{} {:>6}  {} {:16} {} {}", v, loc, icon, rule_id, msg, v);

            if self.config.use_colors {
                output.push_str(&v.cyan().to_string());
                output.push_str(&format!(" {:>6}  ", loc));
                output.push_str(icon);
                output.push(' ');
                output.push_str(&colorize_severity(&rule_id, finding.severity, true));
                output.push_str(&format!("{:width$}", "", width = 16 - rule_id.len()));
                output.push(' ');
                output.push_str(&msg);
                // Pad to align right border
                let current_len = 1 + 1 + 6 + 2 + icon.chars().count() + 1 + 16 + 1 + msg.len();
                let pad = (inner_width + 3).saturating_sub(current_len);
                output.push_str(&" ".repeat(pad));
                output.push_str(&v.cyan().to_string());
            } else {
                output.push_str(&row);
            }
            output.push('\n');
        }

        // Bottom border
        let bottom_border = format!("{}{}{}", bl, h.repeat(inner_width + 2), br);
        if self.config.use_colors {
            output.push_str(&bottom_border.cyan().to_string());
        } else {
            output.push_str(&bottom_border);
        }
        output.push('\n');

        // Render detailed findings
        for finding in findings {
            output.push_str(&self.render_pretty(finding, cache));
            output.push('\n');
        }

        output
    }
}

impl Default for PrettyRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Box Drawing Helpers
// ============================================================================

/// Box drawing characters
pub struct BoxChars {
    pub top_left: &'static str,
    pub top_right: &'static str,
    pub bottom_left: &'static str,
    pub bottom_right: &'static str,
    pub horizontal: &'static str,
    pub vertical: &'static str,
    pub left_tee: &'static str,
    pub right_tee: &'static str,
    pub top_tee: &'static str,
    pub bottom_tee: &'static str,
    pub cross: &'static str,
}

impl BoxChars {
    /// Unicode box drawing characters
    pub const UNICODE: BoxChars = BoxChars {
        top_left: "\u{250C}",
        top_right: "\u{2510}",
        bottom_left: "\u{2514}",
        bottom_right: "\u{2518}",
        horizontal: "\u{2500}",
        vertical: "\u{2502}",
        left_tee: "\u{251C}",
        right_tee: "\u{2524}",
        top_tee: "\u{252C}",
        bottom_tee: "\u{2534}",
        cross: "\u{253C}",
    };

    /// ASCII fallback characters
    pub const ASCII: BoxChars = BoxChars {
        top_left: "+",
        top_right: "+",
        bottom_left: "+",
        bottom_right: "+",
        horizontal: "-",
        vertical: "|",
        left_tee: "+",
        right_tee: "+",
        top_tee: "+",
        bottom_tee: "+",
        cross: "+",
    };

    /// Double-line Unicode box drawing characters
    pub const DOUBLE: BoxChars = BoxChars {
        top_left: "\u{2554}",
        top_right: "\u{2557}",
        bottom_left: "\u{255A}",
        bottom_right: "\u{255D}",
        horizontal: "\u{2550}",
        vertical: "\u{2551}",
        left_tee: "\u{2560}",
        right_tee: "\u{2563}",
        top_tee: "\u{2566}",
        bottom_tee: "\u{2569}",
        cross: "\u{256C}",
    };

    /// Get appropriate box characters based on Unicode support
    pub fn get(use_unicode: bool) -> &'static BoxChars {
        if use_unicode {
            &Self::UNICODE
        } else {
            &Self::ASCII
        }
    }
}

/// Draw a horizontal box with content
pub fn draw_box(content: &[String], width: usize, use_unicode: bool, use_colors: bool) -> String {
    let chars = BoxChars::get(use_unicode);
    let mut output = String::new();

    let inner_width = width.saturating_sub(2);

    // Top border
    let top = format!(
        "{}{}{}",
        chars.top_left,
        chars.horizontal.repeat(inner_width),
        chars.top_right
    );
    if use_colors {
        output.push_str(&top.cyan().to_string());
    } else {
        output.push_str(&top);
    }
    output.push('\n');

    // Content lines
    for line in content {
        let padding = inner_width.saturating_sub(line.chars().count());
        let row = format!(
            "{}{}{}{}",
            chars.vertical,
            line,
            " ".repeat(padding),
            chars.vertical
        );
        if use_colors {
            output.push_str(&chars.vertical.cyan().to_string());
            output.push_str(line);
            output.push_str(&" ".repeat(padding));
            output.push_str(&chars.vertical.cyan().to_string());
        } else {
            output.push_str(&row);
        }
        output.push('\n');
    }

    // Bottom border
    let bottom = format!(
        "{}{}{}",
        chars.bottom_left,
        chars.horizontal.repeat(inner_width),
        chars.bottom_right
    );
    if use_colors {
        output.push_str(&bottom.cyan().to_string());
    } else {
        output.push_str(&bottom);
    }
    output.push('\n');

    output
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::{Confidence, FindingCategory, SourceLocation};

    fn create_test_finding() -> Finding {
        Finding {
            id: "test-1".to_string(),
            rule_id: "js/sql-injection".to_string(),
            message: "SQL injection vulnerability".to_string(),
            severity: Severity::Error,
            location: SourceLocation::new(PathBuf::from("src/db/users.js"), 42, 15, 42, 65),
            language: rma_common::Language::JavaScript,
            snippet: Some("const query = \"SELECT * FROM users WHERE id = \" + userId;".to_string()),
            suggestion: Some("Use parameterized queries: db.query(\"SELECT * FROM users WHERE id = ?\", [userId])".to_string()),
            fix: None,
            confidence: Confidence::High,
            category: FindingCategory::Security,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        }
    }

    #[test]
    fn test_severity_style() {
        let (color, icon) = severity_style(Severity::Critical);
        assert_eq!(color, Color::Red);
        assert!(!icon.is_empty());

        let (color, icon) = severity_style(Severity::Warning);
        assert_eq!(color, Color::Yellow);
        assert!(!icon.is_empty());
    }

    #[test]
    fn test_render_compact() {
        let finding = create_test_finding();
        let renderer = PrettyRenderer::with_config(PrettyConfig::compact());
        let mut cache = SourceCache::new();

        let output = renderer.render_finding(&finding, &mut cache);

        assert!(output.contains("src/db/users.js"));
        assert!(output.contains("42:15"));
        assert!(output.contains("js/sql-injection"));
        assert!(output.contains("SQL injection"));
    }

    #[test]
    fn test_render_github() {
        let finding = create_test_finding();
        let config = PrettyConfig {
            format: PrettyFormat::Github,
            ..Default::default()
        };
        let renderer = PrettyRenderer::with_config(config);
        let mut cache = SourceCache::new();

        let output = renderer.render_finding(&finding, &mut cache);

        assert!(output.starts_with("::error"));
        assert!(output.contains("file="));
        assert!(output.contains("line=42"));
        assert!(output.contains("title=js/sql-injection"));
    }

    #[test]
    fn test_box_chars() {
        let unicode = BoxChars::get(true);
        assert_eq!(unicode.top_left, "\u{250C}");

        let ascii = BoxChars::get(false);
        assert_eq!(ascii.top_left, "+");
    }

    #[test]
    fn test_draw_box() {
        let content = vec!["Hello".to_string(), "World".to_string()];
        let output = draw_box(&content, 20, false, false);

        assert!(output.contains("+------------------+"));
        assert!(output.contains("|Hello"));
        assert!(output.contains("|World"));
    }

    #[test]
    fn test_terminal_width() {
        let config = PrettyConfig {
            terminal_width: 100,
            ..Default::default()
        };
        assert_eq!(config.get_terminal_width(), 100);

        let config_auto = PrettyConfig {
            terminal_width: 0,
            ..Default::default()
        };
        // Should return some reasonable value
        assert!(config_auto.get_terminal_width() >= 40);
    }

    #[test]
    fn test_colorize_severity() {
        let colored = colorize_severity("test", Severity::Error, true);
        // When colors are enabled, string should have ANSI codes
        assert!(!colored.is_empty());

        let uncolored = colorize_severity("test", Severity::Error, false);
        assert_eq!(uncolored, "test");
    }
}
