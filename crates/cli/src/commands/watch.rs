//! Watch command implementation - Real-time file monitoring with interactive controls
//!
//! Features:
//! - Debounced file watching (coalesces rapid changes)
//! - Interactive keyboard shortcuts
//! - Clear screen mode
//! - AI analysis integration
//! - Parallel batch analysis

use crate::ui::theme::Theme;
use anyhow::{Context, Result};
use colored::Colorize;
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{self, ClearType},
};
use rma_analyzer::AnalyzerEngine;
use rma_common::{RmaConfig, Severity};
use rma_indexer::watcher::{self, FileEvent};
use rma_parser::ParserEngine;
use std::collections::HashMap;
use std::io::{Write, stdout};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct WatchArgs {
    pub path: PathBuf,
    pub interval: String,
    pub ai: bool,
    pub pattern: Option<String>,
    pub clear: bool,
    pub quiet: bool,
    pub errors_only: bool,
    pub initial_scan: bool,
    pub interactive: bool,
}

/// Watch mode state
#[derive(Default)]
struct WatchState {
    /// Total files analyzed this session
    files_analyzed: usize,
    /// Total findings this session
    total_findings: usize,
    /// Critical findings count
    critical_count: usize,
    /// Error findings count
    error_count: usize,
    /// Warning findings count
    warning_count: usize,
    /// Last analysis time
    last_analysis: Option<Instant>,
    /// Show summary mode (compact view)
    summary_mode: bool,
    /// Filter to errors only
    errors_only: bool,
    /// Paused state
    paused: bool,
}

/// Messages for the watch event loop
enum WatchMessage {
    /// File system event (debounced)
    FileChanged(Vec<FileEvent>),
    /// Keyboard command
    Command(WatchCommand),
}

/// User commands from keyboard
#[derive(Debug, Clone)]
enum WatchCommand {
    Quit,
    Clear,
    RerunAll,
    ToggleSummary,
    ToggleErrorsOnly,
    TogglePause,
    ShowHelp,
}

pub fn run(args: WatchArgs) -> Result<()> {
    // Parse debounce interval
    let debounce_ms = parse_interval(&args.interval)?;

    // Use tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_watch(args, debounce_ms))
}

async fn async_watch(args: WatchArgs, debounce_ms: u64) -> Result<()> {
    let mut state = WatchState {
        errors_only: args.errors_only,
        ..Default::default()
    };

    // Setup engines
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = AnalyzerEngine::new(config);

    // Create message channel
    let (tx, mut rx) = mpsc::channel::<WatchMessage>(100);

    // Start file watcher with debouncing
    let watcher_tx = tx.clone();
    let watch_path = args.path.clone();
    let pattern = args.pattern.clone();
    let debounce_duration = Duration::from_millis(debounce_ms);

    std::thread::spawn(move || {
        if let Err(e) = run_file_watcher(watch_path, pattern, debounce_duration, watcher_tx) {
            eprintln!("File watcher error: {}", e);
        }
    });

    // Start keyboard handler if interactive
    let running = Arc::new(AtomicBool::new(true));
    if args.interactive && !args.quiet {
        let kb_tx = tx.clone();
        let kb_running = running.clone();
        std::thread::spawn(move || {
            run_keyboard_handler(kb_tx, kb_running);
        });
    }

    // Print header
    if !args.quiet {
        print_header(&args, debounce_ms);
    }

    // Initial scan of existing files (optional)
    if args.initial_scan {
        if !args.quiet {
            print_line(&format!(
                "{} Scanning existing files...",
                Theme::info_mark()
            ));
            print_line("");
        }
        initial_scan(
            &args.path,
            &args.pattern,
            &parser,
            &analyzer,
            &mut state,
            args.quiet,
        );
    } else if !args.quiet {
        print_line(&format!("{} Watching for changes...", Theme::info_mark()));
        print_line("");
    }

    // Main event loop
    while let Some(msg) = rx.recv().await {
        match msg {
            WatchMessage::FileChanged(events) if !state.paused => {
                if args.clear {
                    clear_screen();
                    print_status_bar(&args, &state);
                }

                let start = Instant::now();
                let mut batch_findings = 0;

                for event in events {
                    if !args.quiet {
                        print_line(&format!(
                            "{} {} {}",
                            Theme::arrow(),
                            format!("{:?}", event.kind).dimmed(),
                            Theme::path(&event.path)
                        ));
                    }

                    // Analyze the file
                    if let Ok(content) = std::fs::read_to_string(&event.path)
                        && let Ok(parsed) = parser.parse_file(&event.path, &content)
                    {
                        match analyzer.analyze_file(&parsed) {
                            Ok(analysis) => {
                                state.files_analyzed += 1;
                                let findings_count = analysis.findings.len();
                                batch_findings += findings_count;

                                // Update state counters
                                for f in &analysis.findings {
                                    state.total_findings += 1;
                                    match f.severity {
                                        Severity::Critical => state.critical_count += 1,
                                        Severity::Error => state.error_count += 1,
                                        Severity::Warning => state.warning_count += 1,
                                        Severity::Info => {}
                                    }
                                }

                                // Display findings
                                if !args.quiet {
                                    display_findings(&analysis.findings, &state);
                                }
                            }
                            Err(e) => {
                                if !args.quiet {
                                    print_line(&format!(
                                        "   {} Analysis failed: {}",
                                        Theme::error_mark(),
                                        e
                                    ));
                                }
                            }
                        }
                    }
                }

                state.last_analysis = Some(Instant::now());

                if !args.quiet && batch_findings > 0 {
                    let elapsed = start.elapsed();
                    print_line(&format!(
                        "{} Analyzed in {:.0?}",
                        Theme::info_mark(),
                        elapsed
                    ));
                }

                if !args.quiet {
                    print_line("");
                }
            }

            WatchMessage::FileChanged(_) => {
                // Paused, ignore file changes
            }

            WatchMessage::Command(cmd) => {
                match cmd {
                    WatchCommand::Quit => {
                        running.store(false, Ordering::SeqCst);
                        if !args.quiet {
                            print_line(&format!("{} Goodbye!", Theme::info_mark()));
                        }
                        break;
                    }
                    WatchCommand::Clear => {
                        clear_screen();
                        print_status_bar(&args, &state);
                    }
                    WatchCommand::RerunAll => {
                        if !args.quiet {
                            print_line(&format!(
                                "{} Re-running analysis on all files...",
                                Theme::info_mark()
                            ));
                        }
                        // TODO: Implement full re-analysis
                    }
                    WatchCommand::ToggleSummary => {
                        state.summary_mode = !state.summary_mode;
                        if !args.quiet {
                            print_line(&format!(
                                "{} Summary mode: {}",
                                Theme::info_mark(),
                                if state.summary_mode { "ON" } else { "OFF" }
                            ));
                        }
                    }
                    WatchCommand::ToggleErrorsOnly => {
                        state.errors_only = !state.errors_only;
                        if !args.quiet {
                            print_line(&format!(
                                "{} Errors only: {}",
                                Theme::info_mark(),
                                if state.errors_only { "ON" } else { "OFF" }
                            ));
                        }
                    }
                    WatchCommand::TogglePause => {
                        state.paused = !state.paused;
                        if !args.quiet {
                            print_line(&format!(
                                "{} {}",
                                Theme::info_mark(),
                                if state.paused {
                                    "Paused - file changes ignored".yellow()
                                } else {
                                    "Resumed - watching for changes".green()
                                }
                            ));
                        }
                    }
                    WatchCommand::ShowHelp => {
                        print_help();
                    }
                }
            }
        }
    }

    // Cleanup
    if args.interactive {
        let _ = terminal::disable_raw_mode();
    }

    Ok(())
}

/// Initial scan of existing files in directory
fn initial_scan(
    path: &PathBuf,
    pattern: &Option<String>,
    parser: &ParserEngine,
    analyzer: &AnalyzerEngine,
    state: &mut WatchState,
    quiet: bool,
) {
    let start = Instant::now();
    let mut files_with_findings = 0;

    let entries = walkdir::WalkDir::new(path)
        .max_depth(10)
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in entries {
        let file_path = entry.path();

        // Skip non-files
        if !file_path.is_file() {
            continue;
        }

        // Use centralized filtering from watcher module
        if watcher::is_ignored_path(file_path) {
            continue;
        }

        if !watcher::is_source_file(file_path) {
            continue;
        }

        // Apply pattern filter
        let path_str = file_path.to_string_lossy();
        if let Some(pat) = pattern
            && !path_str.contains(pat)
        {
            continue;
        }

        // Analyze file
        if let Ok(content) = std::fs::read_to_string(file_path)
            && let Ok(parsed) = parser.parse_file(file_path, &content)
            && let Ok(analysis) = analyzer.analyze_file(&parsed)
        {
            state.files_analyzed += 1;

            if !analysis.findings.is_empty() {
                files_with_findings += 1;

                // Update state counters
                for f in &analysis.findings {
                    state.total_findings += 1;
                    match f.severity {
                        Severity::Critical => state.critical_count += 1,
                        Severity::Error => state.error_count += 1,
                        Severity::Warning => state.warning_count += 1,
                        Severity::Info => {}
                    }
                }

                // Display findings
                if !quiet {
                    print_line(&format!("{} {}", Theme::arrow(), Theme::path(file_path)));
                    display_findings(&analysis.findings, state);
                    print_line("");
                }
            }
        }
    }

    if !quiet {
        let elapsed = start.elapsed();
        print_line(&format!(
            "{} Initial scan: {} files, {} with findings ({:.0?})",
            Theme::success_mark(),
            state.files_analyzed,
            files_with_findings,
            elapsed
        ));
        print_line("");
        print_line(&format!("{} Watching for changes...", Theme::info_mark()));
        print_line("");
    }
}

/// Run the file watcher with debouncing
fn run_file_watcher(
    path: PathBuf,
    pattern: Option<String>,
    debounce: Duration,
    tx: mpsc::Sender<WatchMessage>,
) -> Result<()> {
    let (_watcher, file_rx) = watcher::watch_directory(&path)?;

    let mut pending_events: HashMap<PathBuf, FileEvent> = HashMap::new();
    let mut last_flush = Instant::now();

    loop {
        // Check for events with timeout
        match file_rx.recv_timeout(Duration::from_millis(50)) {
            Ok(event) => {
                let events = watcher::filter_source_events(vec![event]);
                for ev in events {
                    // Apply pattern filter
                    if let Some(ref pat) = pattern {
                        let path_str = ev.path.to_string_lossy();
                        if !path_str.contains(pat) {
                            continue;
                        }
                    }
                    // Coalesce events for the same file
                    pending_events.insert(ev.path.clone(), ev);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Check if we should flush pending events
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }

        // Flush if debounce period has passed and we have events
        if !pending_events.is_empty() && last_flush.elapsed() >= debounce {
            let events: Vec<FileEvent> = pending_events.drain().map(|(_, v)| v).collect();
            if tx.blocking_send(WatchMessage::FileChanged(events)).is_err() {
                break;
            }
            last_flush = Instant::now();
        }
    }

    Ok(())
}

/// Run keyboard input handler
fn run_keyboard_handler(tx: mpsc::Sender<WatchMessage>, running: Arc<AtomicBool>) {
    // Enable raw mode for keyboard input
    if terminal::enable_raw_mode().is_err() {
        return;
    }

    while running.load(Ordering::SeqCst) {
        if event::poll(Duration::from_millis(100)).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
        {
            let cmd = match key {
                KeyEvent {
                    code: KeyCode::Char('q'),
                    ..
                }
                | KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers: KeyModifiers::CONTROL,
                    ..
                } => Some(WatchCommand::Quit),

                KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers: KeyModifiers::NONE,
                    ..
                } => Some(WatchCommand::Clear),

                KeyEvent {
                    code: KeyCode::Char('r'),
                    ..
                } => Some(WatchCommand::RerunAll),

                KeyEvent {
                    code: KeyCode::Char('s'),
                    ..
                } => Some(WatchCommand::ToggleSummary),

                KeyEvent {
                    code: KeyCode::Char('e'),
                    ..
                } => Some(WatchCommand::ToggleErrorsOnly),

                KeyEvent {
                    code: KeyCode::Char('p'),
                    ..
                } => Some(WatchCommand::TogglePause),

                KeyEvent {
                    code: KeyCode::Char('?'),
                    ..
                }
                | KeyEvent {
                    code: KeyCode::Char('h'),
                    ..
                } => Some(WatchCommand::ShowHelp),

                _ => None,
            };

            if let Some(cmd) = cmd
                && tx.blocking_send(WatchMessage::Command(cmd)).is_err()
            {
                break;
            }
        }
    }

    let _ = terminal::disable_raw_mode();
}

/// Display findings based on current state/filters
fn display_findings(findings: &[rma_common::Finding], state: &WatchState) {
    // Filter findings
    let filtered: Vec<_> = if state.errors_only {
        findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::Error))
            .collect()
    } else {
        findings.iter().collect()
    };

    if filtered.is_empty() {
        print_line(&format!("   {} No issues found", Theme::success_mark()));
        return;
    }

    // Count by severity
    let crits = filtered
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let errs = filtered
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warns = filtered
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let infos = filtered.len() - crits - errs - warns;

    if state.summary_mode {
        // Compact one-line summary
        let mut parts = Vec::new();
        if crits > 0 {
            parts.push(format!("{} crit", crits).red().to_string());
        }
        if errs > 0 {
            parts.push(format!("{} err", errs).yellow().to_string());
        }
        if warns > 0 {
            parts.push(format!("{} warn", warns).blue().to_string());
        }
        if infos > 0 {
            parts.push(format!("{} info", infos).dimmed().to_string());
        }
        print_line(&format!(
            "   {} {}",
            Theme::warning_mark(),
            parts.join(" | ")
        ));
    } else {
        // Detailed view - show each finding on its own line
        for finding in &filtered {
            let sev = match finding.severity {
                Severity::Critical => "CRIT".red().bold().to_string(),
                Severity::Error => "ERR ".yellow().to_string(),
                Severity::Warning => "WARN".blue().to_string(),
                Severity::Info => "INFO".dimmed().to_string(),
            };
            print_line(&format!(
                "   {} {:>4}:{:<3} {} {}",
                sev,
                finding.location.start_line,
                finding.location.start_column,
                finding.rule_id.dimmed(),
                truncate_message(&finding.message, 50)
            ));
        }
    }
}

/// Truncate message to max length
fn truncate_message(msg: &str, max: usize) -> String {
    if msg.len() <= max {
        msg.to_string()
    } else {
        format!("{}...", &msg[..max - 3])
    }
}

/// Print a line with proper newline handling (works with raw mode)
fn print_line(s: &str) {
    print!("{}\r\n", s);
    let _ = stdout().flush();
}

fn print_header(args: &WatchArgs, debounce_ms: u64) {
    print_line("");
    print_line(&format!("{}", "👁  Qryon Watch Mode".cyan().bold()));
    print_line(&Theme::separator(60));
    print_line(&format!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    ));
    print_line(&format!(
        "  {} {}",
        "Debounce:".dimmed(),
        format!("{}ms", debounce_ms).bright_white()
    ));

    if let Some(ref pattern) = args.pattern {
        print_line(&format!(
            "  {} {}",
            "Pattern:".dimmed(),
            pattern.bright_white()
        ));
    }

    if args.ai {
        print_line(&format!("  {} {}", "AI:".dimmed(), "enabled".green()));
    }

    if args.interactive {
        print_line("");
        print_line(&format!(
            "  {}",
            "Keys: [q]uit [c]lear [r]erun [s]ummary [e]rrors [p]ause [?]help".dimmed()
        ));
    } else {
        print_line(&format!("  Press {} to stop", "Ctrl+C".yellow()));
    }

    print_line(&Theme::separator(60));
    print_line("");
}

fn print_status_bar(args: &WatchArgs, state: &WatchState) {
    print_line(&format!(
        "{} {} | Files: {} | Findings: {} ({} crit, {} err, {} warn){}",
        "👁 ".cyan(),
        args.path.display().to_string().dimmed(),
        state.files_analyzed.to_string().bright_white(),
        state.total_findings.to_string().bright_white(),
        state.critical_count.to_string().red(),
        state.error_count.to_string().yellow(),
        state.warning_count.to_string().blue(),
        if state.paused {
            " [PAUSED]".yellow().to_string()
        } else {
            String::new()
        }
    ));
    print_line(&Theme::separator(60));
    print_line("");
}

fn print_help() {
    print_line("");
    print_line(&format!("{}", "Keyboard Shortcuts".cyan().bold()));
    print_line(&Theme::separator(40));
    print_line(&format!("  {}  Quit watch mode", "q".yellow()));
    print_line(&format!("  {}  Clear screen", "c".yellow()));
    print_line(&format!("  {}  Re-run all files", "r".yellow()));
    print_line(&format!("  {}  Toggle summary view", "s".yellow()));
    print_line(&format!("  {}  Toggle errors only", "e".yellow()));
    print_line(&format!("  {}  Pause/resume", "p".yellow()));
    print_line(&format!("  {}  Show this help", "?".yellow()));
    print_line(&Theme::separator(40));
    print_line("");
}

fn clear_screen() {
    let mut stdout = stdout();
    let _ = stdout.execute(terminal::Clear(ClearType::All));
    let _ = stdout.execute(crossterm::cursor::MoveTo(0, 0));
    let _ = stdout.flush();
}

/// Parse interval string like "500ms" or "1s" into milliseconds
fn parse_interval(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();

    if let Some(ms) = s.strip_suffix("ms") {
        ms.parse::<u64>().context("Invalid milliseconds value")
    } else if let Some(secs) = s.strip_suffix('s') {
        let secs: f64 = secs.parse().context("Invalid seconds value")?;
        Ok((secs * 1000.0) as u64)
    } else {
        // Default to milliseconds if no suffix
        s.parse::<u64>()
            .context("Invalid interval - use format like '500ms' or '1s'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_interval_ms() {
        assert_eq!(parse_interval("500ms").unwrap(), 500);
        assert_eq!(parse_interval("100ms").unwrap(), 100);
    }

    #[test]
    fn test_parse_interval_seconds() {
        assert_eq!(parse_interval("1s").unwrap(), 1000);
        assert_eq!(parse_interval("0.5s").unwrap(), 500);
        assert_eq!(parse_interval("2s").unwrap(), 2000);
    }

    #[test]
    fn test_parse_interval_no_suffix() {
        assert_eq!(parse_interval("500").unwrap(), 500);
    }
}
