//! Scan progress tracking with streaming output support
//!
//! This module provides a sophisticated progress tracking system for scan operations,
//! with support for:
//! - Multi-line progress bars showing overall progress and current file
//! - Real-time findings counter with severity breakdown
//! - Streaming output mode for immediate finding display
//! - ETA and speed calculations
//! - Non-TTY detection for CI/script environments
//! - Animated final summary

use crate::output::diagnostics::{DiagnosticRenderer, RichDiagnosticRenderer, SourceCache};
use crate::ui::theme::Theme;
use colored::Colorize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rma_common::{Finding, Language, Severity};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for scan progress display
#[derive(Debug, Clone)]
pub struct ScanProgressConfig {
    /// Show progress bars (auto-disabled for non-TTY)
    pub show_progress: bool,
    /// Stream findings as they're discovered
    pub stream_findings: bool,
    /// Quiet mode - suppress most output
    pub quiet: bool,
}

impl ScanProgressConfig {
    /// Create config from CLI flags
    pub fn from_args(no_progress: bool, stream: bool, quiet: bool) -> Self {
        let is_tty = std::io::stdout().is_terminal();
        Self {
            show_progress: !no_progress && is_tty && !quiet,
            stream_findings: stream,
            quiet,
        }
    }
}

/// Main progress tracker for scan operations
pub struct ScanProgress {
    config: ScanProgressConfig,
    #[allow(dead_code)] // Reserved for future multi-bar features
    multi: MultiProgress,
    main_bar: Option<ProgressBar>,
    current_file_bar: Option<ProgressBar>,
    status_bar: Option<ProgressBar>,

    // Counters
    findings_count: AtomicUsize,
    critical_count: AtomicUsize,
    error_count: AtomicUsize,
    warning_count: AtomicUsize,
    info_count: AtomicUsize,

    // Language tracking
    languages: Arc<Mutex<HashMap<Language, usize>>>,

    // Timing
    start_time: Instant,
    total_files: u64,

    // For streaming mode
    source_cache: Mutex<SourceCache>,
    renderer: RichDiagnosticRenderer,
}

impl ScanProgress {
    /// Create a new scan progress tracker
    pub fn new(total_files: u64, config: ScanProgressConfig) -> Self {
        let multi = MultiProgress::new();

        let (main_bar, current_file_bar, status_bar) = if config.show_progress {
            // Main progress bar with file count and ETA
            let main = multi.add(ProgressBar::new(total_files));
            main.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} {msg}\n{wide_bar:.cyan/dim} {pos}/{len} ({percent}%) ETA: {eta}")
                    .expect("Invalid progress template")
                    .progress_chars("████░"),
            );
            main.set_message("Scanning");
            main.enable_steady_tick(Duration::from_millis(100));

            // Current file indicator
            let current = multi.add(ProgressBar::new_spinner());
            current.set_style(
                ProgressStyle::default_spinner()
                    .template("  {spinner:.dim} Current: {msg}")
                    .expect("Invalid spinner template")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
            current.enable_steady_tick(Duration::from_millis(80));

            // Status bar for findings count
            let status = multi.add(ProgressBar::new_spinner());
            status.set_style(
                ProgressStyle::default_spinner()
                    .template("  {msg}")
                    .expect("Invalid status template"),
            );
            status.set_message("Found: 0 issues");

            (Some(main), Some(current), Some(status))
        } else {
            (None, None, None)
        };

        Self {
            config,
            multi,
            main_bar,
            current_file_bar,
            status_bar,
            findings_count: AtomicUsize::new(0),
            critical_count: AtomicUsize::new(0),
            error_count: AtomicUsize::new(0),
            warning_count: AtomicUsize::new(0),
            info_count: AtomicUsize::new(0),
            languages: Arc::new(Mutex::new(HashMap::new())),
            start_time: Instant::now(),
            total_files,
            source_cache: Mutex::new(SourceCache::new()),
            renderer: RichDiagnosticRenderer::new(),
        }
    }

    /// Set the current file being processed
    pub fn set_current_file(&self, path: &Path) {
        if let Some(ref bar) = self.current_file_bar {
            let display_path = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());

            // Truncate if too long
            let max_len = 60;
            let display = if display_path.len() > max_len {
                format!("...{}", &display_path[display_path.len() - max_len + 3..])
            } else {
                display_path
            };

            bar.set_message(display);
        }
    }

    /// Increment file counter
    pub fn inc_file(&self) {
        if let Some(ref bar) = self.main_bar {
            bar.inc(1);
            self.update_speed();
        }
    }

    /// Track a language being analyzed
    pub fn track_language(&self, lang: Language) {
        if let Ok(mut langs) = self.languages.lock() {
            *langs.entry(lang).or_insert(0) += 1;
        }
    }

    /// Add a finding and update counters
    pub fn add_finding(&self, finding: &Finding) {
        self.findings_count.fetch_add(1, Ordering::SeqCst);

        match finding.severity {
            Severity::Critical => {
                self.critical_count.fetch_add(1, Ordering::SeqCst);
            }
            Severity::Error => {
                self.error_count.fetch_add(1, Ordering::SeqCst);
            }
            Severity::Warning => {
                self.warning_count.fetch_add(1, Ordering::SeqCst);
            }
            Severity::Info => {
                self.info_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        self.update_findings_display();

        // Stream the finding if in streaming mode
        if self.config.stream_findings {
            self.stream_finding(finding);
        }
    }

    /// Stream a finding to output immediately
    fn stream_finding(&self, finding: &Finding) {
        if let Ok(mut cache) = self.source_cache.lock() {
            // Suspend progress bars while printing
            if let Some(ref bar) = self.main_bar {
                bar.suspend(|| {
                    let output = self.renderer.render(finding, &mut cache);
                    print!("{}", output);
                    println!(); // Extra line for separation
                });
            } else {
                // No progress bar, just print
                let output = self.renderer.render(finding, &mut cache);
                print!("{}", output);
                println!();
            }
        }
    }

    /// Update the findings display
    fn update_findings_display(&self) {
        if let Some(ref bar) = self.status_bar {
            let critical = self.critical_count.load(Ordering::SeqCst);
            let error = self.error_count.load(Ordering::SeqCst);
            let warning = self.warning_count.load(Ordering::SeqCst);
            let info = self.info_count.load(Ordering::SeqCst);

            let mut parts = Vec::new();

            if critical > 0 {
                parts.push(format!("{} critical", critical).red().bold().to_string());
            }
            if error > 0 {
                parts.push(format!("{} errors", error).bright_red().to_string());
            }
            if warning > 0 {
                parts.push(format!("{} warnings", warning).yellow().to_string());
            }
            if info > 0 {
                parts.push(format!("{} info", info).blue().to_string());
            }

            let message = if parts.is_empty() {
                "Found: 0 issues".to_string()
            } else {
                format!("Found: {}", parts.join(", "))
            };

            bar.set_message(message);
        }
    }

    /// Update speed display
    fn update_speed(&self) {
        if let Some(ref bar) = self.main_bar {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            let processed = bar.position();

            if elapsed > 0.0 {
                let speed = processed as f64 / elapsed;
                let remaining = self.total_files.saturating_sub(processed);
                let _eta = if speed > 0.0 {
                    remaining as f64 / speed
                } else {
                    0.0
                };

                bar.set_message(format!(
                    "Scanning {} Speed: {:.0} files/sec",
                    "".dimmed(),
                    speed
                ));
            }
        }
    }

    /// Finish progress with success animation
    pub fn finish(&self) {
        let duration = self.start_time.elapsed();
        let total = self.findings_count.load(Ordering::SeqCst);
        let critical = self.critical_count.load(Ordering::SeqCst);
        let error = self.error_count.load(Ordering::SeqCst);
        let warning = self.warning_count.load(Ordering::SeqCst);
        let info = self.info_count.load(Ordering::SeqCst);

        // Finish progress bars
        if let Some(ref bar) = self.main_bar {
            bar.finish_and_clear();
        }
        if let Some(ref bar) = self.current_file_bar {
            bar.finish_and_clear();
        }
        if let Some(ref bar) = self.status_bar {
            bar.finish_and_clear();
        }

        if self.config.quiet {
            return;
        }

        // Print final summary
        println!();
        println!(
            "{} {}",
            Theme::success_mark(),
            format!("Scan complete in {}", format_duration(duration))
                .green()
                .bold()
        );

        // Language breakdown
        if let Ok(langs) = self.languages.lock() {
            if !langs.is_empty() {
                let lang_count = langs.len();
                println!(
                    "  {} Analyzed {} files across {} languages",
                    Theme::bullet(),
                    format_number(self.total_files as usize).bright_white(),
                    lang_count.to_string().cyan()
                );
            }
        }

        // Findings summary
        if total > 0 {
            let mut parts = Vec::new();
            if critical > 0 {
                parts.push(format!("{} critical", critical).red().bold().to_string());
            }
            if error > 0 {
                parts.push(format!("{} errors", error).bright_red().to_string());
            }
            if warning > 0 {
                parts.push(format!("{} warnings", warning).yellow().to_string());
            }
            if info > 0 {
                parts.push(format!("{} info", info).blue().to_string());
            }

            println!(
                "  {} Found {} issues ({})",
                Theme::bullet(),
                total.to_string().yellow().bold(),
                parts.join(", ")
            );
        } else {
            println!("  {} {}", Theme::bullet(), "No issues found!".green());
        }

        println!();
    }

    /// Get total findings count
    #[allow(dead_code)] // Public API for external consumers
    pub fn total_findings(&self) -> usize {
        self.findings_count.load(Ordering::SeqCst)
    }

    /// Get findings breakdown
    #[allow(dead_code)] // Public API for external consumers
    pub fn findings_breakdown(&self) -> (usize, usize, usize, usize) {
        (
            self.critical_count.load(Ordering::SeqCst),
            self.error_count.load(Ordering::SeqCst),
            self.warning_count.load(Ordering::SeqCst),
            self.info_count.load(Ordering::SeqCst),
        )
    }
}

/// Progress spinner for indeterminate phases
#[allow(dead_code)] // Public API for CLI progress display
pub struct PhaseSpinner {
    bar: Option<ProgressBar>,
    start_time: Instant,
    show_progress: bool,
}

#[allow(dead_code)] // Public API for CLI progress display
impl PhaseSpinner {
    /// Create a new phase spinner
    pub fn new(message: &str, show_progress: bool) -> Self {
        let bar = if show_progress {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .expect("Invalid spinner template")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
            pb.set_message(message.to_string());
            pb.enable_steady_tick(Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };

        Self {
            bar,
            start_time: Instant::now(),
            show_progress,
        }
    }

    /// Update the spinner message
    pub fn set_message(&self, message: &str) {
        if let Some(ref bar) = self.bar {
            bar.set_message(message.to_string());
        }
    }

    /// Finish with success
    pub fn finish_success(&self, message: &str) {
        if let Some(ref bar) = self.bar {
            let duration = self.start_time.elapsed();
            bar.finish_with_message(format!(
                "{} {} {}",
                Theme::success_mark(),
                message,
                format!("({:.2}s)", duration.as_secs_f64()).dimmed()
            ));
        }
    }

    /// Finish with warning
    pub fn finish_warning(&self, message: &str) {
        if let Some(ref bar) = self.bar {
            bar.finish_with_message(format!("{} {}", Theme::warning_mark(), message));
        }
    }

    /// Finish with error
    pub fn finish_error(&self, message: &str) {
        if let Some(ref bar) = self.bar {
            bar.finish_with_message(format!("{} {}", Theme::error_mark(), message));
        }
    }

    /// Get elapsed duration
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

/// Multi-phase progress tracker for complex operations
#[allow(dead_code)] // Public API for CLI multi-phase progress display
pub struct MultiPhaseProgress {
    multi: MultiProgress,
    phases: Vec<PhaseInfo>,
    current_phase: usize,
    show_progress: bool,
}

#[allow(dead_code)] // Public API for CLI multi-phase progress display
struct PhaseInfo {
    name: String,
    bar: Option<ProgressBar>,
    completed: bool,
}

#[allow(dead_code)] // Public API for CLI multi-phase progress display
impl MultiPhaseProgress {
    /// Create a new multi-phase progress tracker
    pub fn new(show_progress: bool) -> Self {
        Self {
            multi: MultiProgress::new(),
            phases: Vec::new(),
            current_phase: 0,
            show_progress,
        }
    }

    /// Add a phase with indeterminate progress
    pub fn add_spinner_phase(&mut self, name: &str) -> usize {
        let bar = if self.show_progress {
            let pb = self.multi.add(ProgressBar::new_spinner());
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .expect("Invalid spinner template")
                    .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
            );
            pb.set_message(format!("{} {}", "⋯".dimmed(), name));
            Some(pb)
        } else {
            None
        };

        self.phases.push(PhaseInfo {
            name: name.to_string(),
            bar,
            completed: false,
        });

        self.phases.len() - 1
    }

    /// Start a phase
    pub fn start_phase(&mut self, index: usize) {
        if let Some(phase) = self.phases.get_mut(index) {
            if let Some(ref bar) = phase.bar {
                bar.enable_steady_tick(Duration::from_millis(80));
                bar.set_message(phase.name.clone());
            }
            self.current_phase = index;
        }
    }

    /// Complete a phase
    pub fn complete_phase(&mut self, index: usize, message: Option<&str>) {
        if let Some(phase) = self.phases.get_mut(index) {
            phase.completed = true;
            if let Some(ref bar) = phase.bar {
                let msg = message.unwrap_or(&phase.name);
                bar.finish_with_message(format!("{} {}", Theme::success_mark(), msg));
            }
        }
    }

    /// Fail a phase
    pub fn fail_phase(&mut self, index: usize, message: &str) {
        if let Some(phase) = self.phases.get_mut(index) {
            if let Some(ref bar) = phase.bar {
                bar.finish_with_message(format!("{} {}", Theme::error_mark(), message));
            }
        }
    }
}

/// Format a duration for display
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else {
        let mins = (secs / 60.0).floor();
        let remaining = secs - (mins * 60.0);
        format!("{}m {:.0}s", mins, remaining)
    }
}

/// Format a number with thousands separators
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

/// Streaming finding printer for immediate output
#[allow(dead_code)] // Public API for streaming output mode
pub struct StreamingOutput {
    cache: SourceCache,
    renderer: RichDiagnosticRenderer,
    count: usize,
}

#[allow(dead_code)] // Public API for streaming output mode
impl StreamingOutput {
    /// Create a new streaming output handler
    pub fn new() -> Self {
        Self {
            cache: SourceCache::new(),
            renderer: RichDiagnosticRenderer::new(),
            count: 0,
        }
    }

    /// Print a finding immediately
    pub fn print_finding(&mut self, finding: &Finding) {
        let output = self.renderer.render(finding, &mut self.cache);
        print!("{}", output);
        println!(); // Extra line for separation
        self.count += 1;
    }

    /// Print a finding in compact format
    pub fn print_finding_compact(&mut self, finding: &Finding) {
        let severity_char = match finding.severity {
            Severity::Critical => "C".red().bold(),
            Severity::Error => "E".bright_red(),
            Severity::Warning => "W".yellow(),
            Severity::Info => "I".blue(),
        };

        println!(
            "{}:{}:{}: {} [{}] {}",
            finding.location.file.display().to_string().bright_white(),
            finding.location.start_line.to_string().dimmed(),
            finding.location.start_column.to_string().dimmed(),
            severity_char,
            finding.rule_id.dimmed(),
            finding.message
        );

        self.count += 1;
    }

    /// Get total printed count
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for StreamingOutput {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::{Confidence, FindingCategory, SourceLocation};
    use std::path::PathBuf;

    fn create_test_finding(severity: Severity) -> Finding {
        Finding {
            id: "test-1".to_string(),
            rule_id: "test/rule".to_string(),
            message: "Test finding".to_string(),
            severity,
            location: SourceLocation {
                file: PathBuf::from("test.rs"),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 10,
            },
            language: Language::Rust,
            snippet: Some("fn test()".to_string()),
            suggestion: None,
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
    fn test_scan_progress_config() {
        let config = ScanProgressConfig::from_args(false, true, false);
        assert!(config.stream_findings);
        assert!(!config.quiet);

        let quiet_config = ScanProgressConfig::from_args(false, false, true);
        assert!(quiet_config.quiet);
        assert!(!quiet_config.show_progress);
    }

    #[test]
    fn test_findings_counter() {
        let config = ScanProgressConfig {
            show_progress: false,
            stream_findings: false,
            quiet: true,
        };

        let progress = ScanProgress::new(100, config);

        progress.add_finding(&create_test_finding(Severity::Critical));
        progress.add_finding(&create_test_finding(Severity::Error));
        progress.add_finding(&create_test_finding(Severity::Warning));
        progress.add_finding(&create_test_finding(Severity::Info));

        assert_eq!(progress.total_findings(), 4);

        let (critical, error, warning, info) = progress.findings_breakdown();
        assert_eq!(critical, 1);
        assert_eq!(error, 1);
        assert_eq!(warning, 1);
        assert_eq!(info, 1);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs_f64(1.5)), "1.5s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(100), "100");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1000000), "1,000,000");
    }

    #[test]
    fn test_phase_spinner() {
        let spinner = PhaseSpinner::new("Testing", false);
        spinner.set_message("Updated");
        assert!(spinner.elapsed() >= Duration::ZERO);
    }
}
