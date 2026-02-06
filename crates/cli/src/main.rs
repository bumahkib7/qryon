//! RMA CLI - Rust Monorepo Analyzer Command Line Interface
//!
//! A sophisticated, intelligent, color-coded CLI for code analysis and security scanning.

mod commands;
mod filter;
mod output;
mod progress;
mod tui;
mod ui;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use colored::Colorize;
use std::io;
use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// RMA - Ultra-fast Rust-native code intelligence and security analyzer
///
/// Analyzes codebases for security vulnerabilities, code quality issues,
/// and provides intelligent insights with optional AI-powered deep analysis.
#[derive(Parser)]
#[command(name = "rma")]
#[command(author = "RMA Team <rma@example.com>")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Ultra-fast code intelligence and security analyzer", long_about = None)]
#[command(after_help = format!(
    "{}\n  {} {}\n  {} {}\n  {} {}",
    "Examples:".cyan().bold(),
    "$".dimmed(), "rma scan ./my-project --format json",
    "$".dimmed(), "rma watch . --ai",
    "$".dimmed(), "rma search 'sql injection' --limit 10"
))]
#[command(propagate_version = true)]
pub struct Cli {
    /// Verbosity level (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Disable colored output
    #[arg(long, global = true, env = "NO_COLOR")]
    pub no_color: bool,

    /// Configuration file path
    #[arg(short, long, global = true, env = "RMA_CONFIG")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Scan a repository for security issues and code metrics
    ///
    /// Filtering examples:
    ///   rma scan --severity error                    # Only errors and critical
    ///   rma scan --rules "sql-*,xss-*"               # Only SQL/XSS rules
    ///   rma scan --exclude-rules "style/*"           # Exclude style rules
    ///   rma scan --files "src/**/*.rs"               # Only Rust files in src/
    ///   rma scan --category security --high-confidence
    ///   rma scan --search "injection"                # Search in messages
    ///   rma scan --preset-security                   # Security-focused preset
    ///   rma scan --preset-ci                         # CI-optimized preset
    ///   rma scan --filter-profile security           # Use saved profile
    ///   rma scan --explain                           # Show filter breakdown
    #[command(visible_alias = "s")]
    Scan {
        /// Path to the repository to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format (text, json, sarif)
        #[arg(short, long, default_value = "text", value_enum)]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        /// Minimum severity to report
        #[arg(short, long, default_value = "warning", value_enum)]
        severity: SeverityArg,

        /// Profile to use (fast, balanced, strict)
        #[arg(short = 'p', long)]
        profile: Option<String>,

        /// Ruleset to use (security, maintainability, or custom)
        #[arg(long)]
        ruleset: Option<String>,

        /// Enable incremental mode (only scan changed files)
        #[arg(short, long)]
        incremental: bool,

        /// Number of parallel workers (0 = auto-detect)
        #[arg(short = 'j', long, default_value = "0")]
        jobs: usize,

        /// Languages to scan (comma-separated: rust,js,ts,py,go,java)
        #[arg(short, long, value_delimiter = ',')]
        languages: Option<Vec<String>>,

        /// Enable AI-powered deep analysis
        #[arg(long, visible_alias = "ai")]
        ai_analysis: bool,

        /// AI provider (claude, openai, local)
        #[arg(long, default_value = "claude", requires = "ai_analysis")]
        ai_provider: String,

        /// Show detailed timing information
        #[arg(long)]
        timing: bool,

        /// Exclude patterns (glob)
        #[arg(short = 'x', long, value_delimiter = ',')]
        exclude: Option<Vec<String>>,

        /// Only report new findings (requires baseline)
        #[arg(long)]
        baseline_mode: bool,

        /// Include suppressed findings in output (normally hidden)
        #[arg(long)]
        include_suppressed: bool,

        /// Only scan files changed since base ref (for PR workflows)
        #[arg(long)]
        changed_only: bool,

        /// Base git ref to compare against (default: origin/main)
        #[arg(long, default_value = "origin/main", requires = "changed_only")]
        base: String,

        /// Analysis providers to use (comma-separated: rma,oxc,pmd,oxlint,rustsec,gosec,osv)
        /// Default: rma (built-in rules only)
        /// oxc: Rust-native JS/TS linting (no external binary needed)
        /// osv: Multi-language dependency vulnerability scanning via OSV.dev
        /// Example: --providers rma,oxc,osv (enables native Oxc + OSV scanning)
        #[arg(long, value_delimiter = ',', default_value = "rma")]
        providers: Vec<String>,

        /// Scan mode preset (local, ci, pr)
        /// pr mode sets: changed_only=true, baseline_mode=true, format=sarif, severity=warning
        #[arg(long, value_enum)]
        mode: Option<ScanMode>,

        /// OSV: Use cache only, no network requests (emit warning if cache miss)
        #[arg(long)]
        osv_offline: bool,

        /// OSV: Cache time-to-live (e.g., 1h, 24h, 7d). Default: 24h
        #[arg(long, default_value = "24h")]
        osv_cache_ttl: String,

        /// Enable cross-file analysis (import resolution, call graph)
        /// This enables detection of taint flows across function and file boundaries
        #[arg(long)]
        cross_file: bool,

        /// Only report findings on lines changed in the diff (for PR workflows)
        /// Uses git diff against --diff-base to determine changed lines
        #[arg(long)]
        diff: bool,

        /// Base git ref to compare against when using --diff (default: origin/main)
        #[arg(long, default_value = "origin/main", requires = "diff")]
        diff_base: String,

        /// Read unified diff from stdin instead of running git diff
        /// Useful for piping diff output: git diff origin/main | rma scan --diff --diff-stdin
        #[arg(long, requires = "diff")]
        diff_stdin: bool,

        /// Include test files in analysis (tests are excluded by default)
        /// Use this flag to scan test files: *_test.go, *.test.ts, test_*.py, src/test/**, etc.
        #[arg(long)]
        include_tests: bool,

        /// Skip ALL findings in test files including security rules
        /// By default, tests are excluded but security rules still apply if tests are included
        #[arg(long)]
        skip_tests_all: bool,

        /// [DEPRECATED] Tests are now excluded by default. Use --include-tests to scan them.
        #[arg(long, hide = true)]
        skip_tests: bool,

        /// Maximum findings to display (default: 20, use --all for unlimited)
        #[arg(long, default_value = "20")]
        limit: usize,

        /// Show all findings without limit
        #[arg(long, conflicts_with = "limit")]
        all: bool,

        /// Group findings by file/rule/severity/none
        #[arg(long, value_enum, default_value = "file")]
        group_by: GroupBy,

        /// Collapse repeated findings (show count instead)
        #[arg(long)]
        collapse: bool,

        /// Expand collapsed findings (show all locations)
        #[arg(long, conflicts_with = "collapse")]
        expand: bool,

        // =====================================================================
        // Filtering options
        // =====================================================================
        /// Filter by specific rule IDs (comma-separated, supports glob patterns like "security/*")
        #[arg(long, value_delimiter = ',')]
        rules: Vec<String>,

        /// Exclude specific rule IDs (comma-separated, supports glob patterns)
        #[arg(long, value_delimiter = ',')]
        exclude_rules: Vec<String>,

        /// Filter to specific files (glob patterns, comma-separated)
        #[arg(long, value_delimiter = ',')]
        files: Vec<String>,

        /// Exclude files matching patterns (glob patterns, comma-separated)
        #[arg(long, value_delimiter = ',')]
        exclude_files: Vec<String>,

        /// Filter by category (security, quality, performance, style)
        #[arg(long, value_enum)]
        category: Option<filter::CategoryFilter>,

        /// Only show findings with fixes available
        #[arg(long)]
        fixable: bool,

        /// Only show high-confidence findings
        #[arg(long)]
        high_confidence: bool,

        /// Search findings by message content (case-insensitive)
        #[arg(long)]
        search: Option<String>,

        /// Search with regex pattern
        #[arg(long, conflicts_with = "search")]
        search_regex: Option<String>,

        // =====================================================================
        // Smart presets
        // =====================================================================
        /// Use security-focused preset (security rules, high confidence, warning+)
        #[arg(long, conflicts_with_all = ["preset_ci", "preset_review"])]
        preset_security: bool,

        /// Use CI preset (errors only, compact output)
        #[arg(long, conflicts_with_all = ["preset_security", "preset_review"])]
        preset_ci: bool,

        /// Use review preset (warnings+, grouped by file)
        #[arg(long, conflicts_with_all = ["preset_security", "preset_ci"])]
        preset_review: bool,

        /// Load filter profile from config file
        #[arg(long)]
        filter_profile: Option<String>,

        /// Show why findings were filtered (detailed breakdown)
        #[arg(long)]
        explain: bool,

        /// Stream findings as they're discovered (real-time output)
        #[arg(long)]
        stream: bool,

        /// Hide progress bar (for CI/scripts, auto-disabled for non-TTY)
        #[arg(long)]
        no_progress: bool,

        /// Launch interactive TUI viewer for browsing findings
        #[arg(short = 'I', long)]
        interactive: bool,

        /// Disable analysis cache (force fresh analysis)
        #[arg(long)]
        no_cache: bool,
    },

    /// Watch for file changes and re-analyze in real-time
    #[command(visible_alias = "w")]
    Watch {
        /// Path to watch
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Debounce interval for file changes (e.g., 500ms, 1s)
        #[arg(short, long, default_value = "300ms")]
        interval: String,

        /// Enable AI analysis on changes
        #[arg(long)]
        ai: bool,

        /// Only watch specific file patterns
        #[arg(short, long)]
        pattern: Option<String>,

        /// Clear screen before each analysis
        #[arg(long)]
        clear: bool,

        /// Suppress output (only show errors)
        #[arg(short, long)]
        quiet: bool,

        /// Show only errors (hide warnings and info)
        #[arg(long)]
        errors_only: bool,

        /// Skip initial scan (only show changes)
        #[arg(long)]
        no_initial_scan: bool,

        /// Disable interactive mode (no keyboard shortcuts)
        #[arg(long)]
        no_interactive: bool,
    },

    /// Search indexed findings and code
    #[command(visible_alias = "q")]
    Search {
        /// Search query (supports regex)
        query: String,

        /// Repository path to search
        #[arg(short, long, default_value = ".")]
        repo: PathBuf,

        /// Maximum results to return
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Filter by severity
        #[arg(short, long)]
        severity: Option<SeverityArg>,

        /// Filter by rule ID
        #[arg(short = 'r', long)]
        rule: Option<String>,

        /// Output format
        #[arg(short, long, default_value = "text", value_enum)]
        format: OutputFormat,
    },

    /// Show repository statistics and metrics
    Stats {
        /// Path to analyze
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Show detailed breakdown by language
        #[arg(short, long)]
        detailed: bool,

        /// Output format
        #[arg(short, long, default_value = "text", value_enum)]
        format: OutputFormat,
    },

    /// Start the RMA HTTP daemon server
    Daemon {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Host to bind to
        #[arg(short = 'H', long, default_value = "127.0.0.1")]
        host: String,

        /// Run in background (daemonize)
        #[arg(short, long)]
        background: bool,
    },

    /// Manage WASM plugins
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },

    /// Manage RMA configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Initialize RMA in a repository
    Init {
        /// Path to initialize
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Force overwrite existing configuration
        #[arg(short, long)]
        force: bool,

        /// Initialize with AI features enabled
        #[arg(long)]
        with_ai: bool,

        /// Initial profile (fast, balanced, strict)
        #[arg(long, default_value = "balanced")]
        profile: String,
    },

    /// Generate baseline from current findings (for legacy code)
    Baseline {
        /// Path to scan for baseline
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output baseline file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Update existing baseline instead of replacing
        #[arg(short, long)]
        update: bool,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Check RMA installation health and diagnostics
    Doctor {
        /// Show detailed output with more information
        #[arg(short, long)]
        detailed: bool,
    },

    /// Run benchmarks on a codebase
    #[command(visible_alias = "benchmark")]
    Bench {
        /// Path to benchmark (can also use --repo)
        #[arg(default_value = ".", value_name = "PATH")]
        path: PathBuf,

        /// Alias for path (for consistency with other tools)
        #[arg(long, hide = true)]
        repo: Option<PathBuf>,

        /// Number of iterations
        #[arg(short, long, default_value = "3")]
        iterations: usize,

        /// Exclude patterns (glob)
        #[arg(short = 'x', long, value_delimiter = ',')]
        exclude: Option<Vec<String>>,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text", value_enum)]
        format: BenchFormat,
    },

    /// Manage RMA cache (OSV vulnerability data, etc.)
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Manage finding suppressions
    Suppress {
        #[command(subcommand)]
        action: SuppressAction,

        /// Project path
        #[arg(default_value = ".", global = true)]
        path: PathBuf,
    },

    /// Run comprehensive security audit (dependencies, Docker, code)
    #[command(visible_alias = "audit")]
    Security {
        /// Path to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format (pretty, json, sarif, markdown)
        #[arg(short, long, default_value = "pretty")]
        format: String,

        /// Minimum severity to report (critical, high, medium, low)
        #[arg(short, long, default_value = "medium")]
        severity: String,

        /// Show detailed CVE information and references
        #[arg(short, long)]
        details: bool,

        /// Show recommended fix commands
        #[arg(long)]
        fix: bool,

        /// Use cached data only (no network requests)
        #[arg(long)]
        offline: bool,

        /// Skip Docker/container scanning
        #[arg(long)]
        skip_docker: bool,

        /// Skip dependency vulnerability scanning
        #[arg(long)]
        skip_deps: bool,

        /// Skip code security analysis
        #[arg(long)]
        skip_code: bool,

        /// Fail (exit 1) if vulnerabilities at or above this severity are found
        /// Possible values: critical, high, medium, low, none
        #[arg(long, default_value = "high", value_name = "SEVERITY")]
        fail_on: String,

        /// Don't fail even if vulnerabilities are found (alias for --fail-on none)
        #[arg(long, conflicts_with = "fail_on")]
        no_fail: bool,

        /// Include test files in code security scanning (normally excluded)
        #[arg(long)]
        include_tests: bool,
    },

    /// Fix vulnerable dependencies automatically
    #[command(visible_alias = "autofix")]
    Fix {
        /// Path to scan and fix
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Fix strategy (minimal, best, latest)
        /// minimal: smallest version bump that fixes the issue
        /// best: optimal balance of safety and minimal breaking changes (default)
        /// latest: always upgrade to latest safe version
        #[arg(long, default_value = "best")]
        strategy: String,

        /// Maximum version bump allowed (patch, minor, major, any)
        #[arg(long, default_value = "any")]
        max_bump: String,

        /// Allow prerelease versions as fix targets
        #[arg(long)]
        allow_prerelease: bool,

        /// Allow yanked/deprecated versions
        #[arg(long)]
        allow_yanked: bool,

        /// Use cached data only (no network requests)
        #[arg(long)]
        offline: bool,

        /// Show detailed candidate analysis (skipped versions and reasons)
        #[arg(long)]
        explain: bool,

        /// Dry run - show plan without applying changes (default)
        #[arg(long)]
        dry_run: bool,

        /// Apply fixes to files
        #[arg(long)]
        apply: bool,

        /// Git branch name to create (e.g., rma/fix-deps)
        #[arg(long)]
        branch_name: Option<String>,

        /// Create git commit after applying fixes
        #[arg(long)]
        commit: bool,

        /// Commit message prefix
        #[arg(long, default_value = "rma:")]
        commit_prefix: String,

        /// Force operations even if working tree is dirty
        #[arg(long)]
        force: bool,

        /// Skip all git operations
        #[arg(long)]
        no_git: bool,

        /// Maximum number of packages to fix
        #[arg(long)]
        limit: Option<usize>,

        /// Force specific package versions (pkg@ver, repeatable)
        #[arg(long = "target", value_name = "PKG@VER")]
        targets: Vec<String>,

        /// Allow vulnerable target versions (requires explicit opt-in)
        #[arg(long)]
        allow_vulnerable_target: bool,

        /// Output format (pretty, json)
        #[arg(short, long, default_value = "pretty")]
        format: String,
    },

    /// Analyze and visualize cross-file data flows
    ///
    /// Shows source-to-sink taint paths with evidence and confidence scores.
    /// Use this to understand how data flows across file boundaries and
    /// identify potential security vulnerabilities.
    ///
    /// Examples:
    ///   rma flows .                           # Analyze current directory
    ///   rma flows --sort-by confidence        # Sort by confidence score
    ///   rma flows --sink-type sql             # Filter SQL injection flows
    ///   rma flows --evidence                  # Show full flow paths
    ///   rma flows --group-by sink-type        # Group by vulnerability type
    ///   rma flows --dedupe --stats            # Dedupe and show statistics
    #[command(visible_alias = "flow")]
    Flows {
        /// Path to analyze
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format (text, json, compact)
        #[arg(short, long, default_value = "text", value_enum)]
        format: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        /// Sort flows by (severity, confidence, sink-type, source-type, file, path-length)
        #[arg(long, default_value = "severity")]
        sort_by: String,

        /// Reverse sort order
        #[arg(short, long)]
        reverse: bool,

        /// Group flows by (sink-type, source-type, file, none)
        #[arg(long, default_value = "sink-type")]
        group_by: String,

        /// Minimum confidence threshold (0.0 - 1.0)
        #[arg(long, default_value = "0.0")]
        min_confidence: f32,

        /// Filter by sink type (sql, command, path, xss, ldap, etc.)
        #[arg(long)]
        sink_type: Option<String>,

        /// Filter by source type (http, file, env, message, etc.)
        #[arg(long)]
        source_type: Option<String>,

        /// Show detailed evidence (full flow paths)
        #[arg(short, long)]
        evidence: bool,

        /// Only show flows passing through specific file
        #[arg(long)]
        through_file: Option<PathBuf>,

        /// Maximum flows to display
        #[arg(long, default_value = "20")]
        limit: usize,

        /// Show all flows without limit
        #[arg(long, conflicts_with = "limit")]
        all: bool,

        /// Suppress non-essential output
        #[arg(short, long)]
        quiet: bool,

        /// Deduplicate flows (group by source+sink)
        #[arg(long)]
        dedupe: bool,

        /// Show statistics summary
        #[arg(long)]
        stats: bool,

        /// Include test files (by default, test sources are excluded)
        #[arg(long)]
        include_tests: bool,

        /// Disable analysis cache (force fresh analysis)
        #[arg(long)]
        no_cache: bool,

        /// Launch interactive TUI viewer for browsing flows
        #[arg(short, long)]
        interactive: bool,
    },
}

/// Suppress subcommands
#[derive(Subcommand)]
pub enum SuppressAction {
    /// Add a new suppression
    Add {
        /// Fingerprint of the finding to suppress
        #[arg(short, long)]
        fingerprint: Option<String>,

        /// Interactive mode - select from scan results
        #[arg(short, long, conflicts_with = "fingerprint")]
        interactive: bool,

        /// Reason for suppression
        #[arg(short, long)]
        reason: Option<String>,

        /// Ticket reference (e.g., JIRA-123)
        #[arg(short, long)]
        ticket: Option<String>,

        /// Expiration period (e.g., "90d", "30d", "7d")
        #[arg(short, long)]
        expires: Option<String>,

        /// Filter by rule ID (for interactive mode)
        #[arg(long)]
        rule: Option<String>,

        /// Filter by file path (for interactive mode)
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// List suppressions
    List {
        /// Filter by rule ID
        #[arg(short, long)]
        rule: Option<String>,

        /// Filter by file path
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Include all statuses (not just active)
        #[arg(short, long)]
        all: bool,

        /// Limit number of results
        #[arg(short, long)]
        limit: Option<usize>,
    },

    /// Remove a suppression by ID
    Remove {
        /// Suppression ID to remove
        id: String,
    },

    /// Show suppression details
    Show {
        /// Suppression ID to show
        id: String,

        /// Include audit history
        #[arg(long)]
        history: bool,
    },

    /// Export suppressions to JSON
    Export {
        /// Output file path
        #[arg(short, long, default_value = ".rma/suppressions.json")]
        output: PathBuf,
    },

    /// Import suppressions from JSON
    Import {
        /// Input file path
        input: PathBuf,
    },

    /// Check for stale/expired suppressions
    Check {
        /// Prune stale suppressions
        #[arg(long)]
        prune: bool,
    },

    /// Show audit log
    Log {
        /// Limit number of entries
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
}

/// Cache management subcommands
#[derive(Subcommand)]
pub enum CacheAction {
    /// Show cache status (path, size, TTL, entries)
    Status,
    /// Download/update OSV vulnerability databases for offline scanning
    Update {
        /// Specific ecosystems to update (default: all enabled)
        #[arg(short, long, value_delimiter = ',')]
        ecosystems: Option<Vec<String>>,
        /// Force update even if cache is fresh
        #[arg(short, long)]
        force: bool,
    },
    /// Clear all cache files
    Clear {
        /// Don't ask for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum PluginAction {
    /// List installed plugins
    List,
    /// Install a plugin from path or URL
    Install {
        /// Plugin path or URL
        source: String,
    },
    /// Remove a plugin
    Remove {
        /// Plugin name
        name: String,
    },
    /// Test a plugin
    Test {
        /// Plugin name or path
        plugin: String,
        /// Test file path
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Show plugin info
    Info {
        /// Plugin name
        name: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Get a configuration value
    Get {
        /// Configuration key (e.g., "profiles.default")
        key: String,
    },
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Value to set
        value: String,
    },
    /// List all configuration values
    List,
    /// Edit configuration in $EDITOR
    Edit,
    /// Show configuration file path
    Path,
    /// Validate configuration file
    Validate,
    /// Print the effective (resolved) configuration
    PrintEffective {
        /// Output format (text, json)
        #[arg(short, long, default_value = "text", value_enum)]
        format: EffectiveConfigFormat,
    },
    /// Reset to defaults
    Reset {
        /// Don't ask for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
pub enum EffectiveConfigFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
pub enum OutputFormat {
    /// Human-readable text with colors
    Text,
    /// JSON format
    Json,
    /// SARIF format (for CI/CD integration)
    Sarif,
    /// Compact single-line format
    Compact,
    /// Markdown table format
    Markdown,
    /// GitHub Actions workflow commands
    Github,
    /// Self-contained HTML report
    Html,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityArg {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
pub enum BenchFormat {
    /// Human-readable text
    Text,
    /// JSON format (for comparison/CI)
    Json,
}

/// Scan mode presets for common workflows
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Default)]
pub enum ScanMode {
    /// Local development (default settings)
    #[default]
    Local,
    /// CI pipeline (optimized for automated builds)
    Ci,
    /// Pull request review (changed files only, SARIF output, baseline mode)
    Pr,
}

/// How to group findings in output
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Default)]
pub enum GroupBy {
    /// Group findings by file (default)
    #[default]
    File,
    /// Group findings by rule ID
    Rule,
    /// Group findings by severity level
    Severity,
    /// No grouping, flat list
    None,
}

impl From<SeverityArg> for rma_common::Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => rma_common::Severity::Info,
            SeverityArg::Warning => rma_common::Severity::Warning,
            SeverityArg::Error => rma_common::Severity::Error,
            SeverityArg::Critical => rma_common::Severity::Critical,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle color settings
    if cli.no_color {
        colored::control::set_override(false);
    }

    // Setup logging based on verbosity
    if !cli.quiet {
        let log_level = match cli.verbose {
            0 => Level::WARN,
            1 => Level::INFO,
            2 => Level::DEBUG,
            _ => Level::TRACE,
        };

        let subscriber = FmtSubscriber::builder()
            .with_max_level(log_level)
            .with_target(cli.verbose >= 2)
            .with_thread_ids(cli.verbose >= 3)
            .with_file(cli.verbose >= 3)
            .with_line_number(cli.verbose >= 3)
            .finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    // Load config if specified
    let config_path = cli.config.clone();

    // Execute command
    let result = match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            severity,
            profile,
            ruleset,
            incremental,
            jobs,
            languages,
            ai_analysis,
            ai_provider,
            timing,
            exclude,
            baseline_mode,
            include_suppressed,
            changed_only,
            base,
            providers,
            mode,
            osv_offline,
            osv_cache_ttl,
            cross_file,
            diff,
            diff_base,
            diff_stdin,
            include_tests,
            skip_tests,
            skip_tests_all,
            limit,
            all,
            group_by,
            collapse,
            expand,
            rules,
            exclude_rules,
            files,
            exclude_files,
            category,
            fixable,
            high_confidence,
            search,
            search_regex,
            preset_security,
            preset_ci,
            preset_review,
            filter_profile,
            explain,
            stream,
            no_progress,
            interactive,
            no_cache,
        } => commands::scan::run(commands::scan::ScanArgs {
            path,
            format,
            output,
            severity: severity.into(),
            profile,
            ruleset,
            incremental,
            jobs,
            languages,
            ai_analysis,
            ai_provider,
            timing,
            exclude,
            config_path,
            quiet: cli.quiet,
            baseline_mode,
            include_suppressed,
            changed_only,
            base,
            providers,
            mode,
            osv_offline,
            osv_cache_ttl,
            cross_file,
            diff,
            diff_base,
            diff_stdin,
            include_tests,
            skip_tests,
            skip_tests_all,
            limit,
            show_all: all,
            group_by,
            collapse,
            expand,
            rules,
            exclude_rules,
            files,
            exclude_files,
            category,
            fixable,
            high_confidence,
            search,
            search_regex,
            preset_security,
            preset_ci,
            preset_review,
            filter_profile,
            explain,
            stream,
            no_progress,
            interactive,
            no_cache,
        }),

        Commands::Watch {
            path,
            interval,
            ai,
            pattern,
            clear,
            quiet,
            errors_only,
            no_initial_scan,
            no_interactive,
        } => commands::watch::run(commands::watch::WatchArgs {
            path,
            interval,
            ai,
            pattern,
            clear,
            quiet: quiet || cli.quiet,
            errors_only,
            initial_scan: !no_initial_scan,
            interactive: !no_interactive,
        }),

        Commands::Search {
            query,
            repo,
            limit,
            severity,
            rule,
            format,
        } => commands::search::run(commands::search::SearchArgs {
            query,
            repo,
            limit,
            severity: severity.map(Into::into),
            rule,
            format,
        }),

        Commands::Stats {
            path,
            detailed,
            format,
        } => commands::stats::run(commands::stats::StatsArgs {
            path,
            detailed,
            format,
        }),

        Commands::Daemon {
            port,
            host,
            background,
        } => commands::daemon::run(commands::daemon::DaemonArgs {
            port,
            host,
            background,
        }),

        Commands::Plugin { action } => commands::plugin::run(action),

        Commands::Config { action } => commands::config::run(action),

        Commands::Init {
            path,
            force,
            with_ai,
            profile,
        } => commands::init::run(commands::init::InitArgs {
            path,
            force,
            with_ai,
            profile: profile.parse().ok(),
        }),

        Commands::Baseline {
            path,
            output,
            update,
        } => commands::baseline::run(commands::baseline::BaselineArgs {
            path,
            output,
            update,
            quiet: cli.quiet,
        }),

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, name, &mut io::stdout());
            Ok(())
        }

        Commands::Doctor { detailed } => {
            commands::doctor::run(commands::doctor::DoctorArgs { verbose: detailed })
        }

        Commands::Bench {
            path,
            repo,
            iterations,
            exclude,
            format,
        } => commands::bench::run(commands::bench::BenchArgs {
            path: repo.unwrap_or(path),
            iterations,
            exclude,
            format,
        }),

        Commands::Cache { action } => commands::cache::run(action),

        Commands::Suppress { action, path } => {
            let suppress_action = match action {
                SuppressAction::Add {
                    fingerprint,
                    interactive,
                    reason,
                    ticket,
                    expires,
                    rule,
                    file,
                } => commands::suppress::SuppressAction::Add {
                    fingerprint,
                    interactive,
                    reason,
                    ticket,
                    expires,
                    rule,
                    file,
                },
                SuppressAction::List {
                    rule,
                    file,
                    all,
                    limit,
                } => commands::suppress::SuppressAction::List {
                    rule,
                    file,
                    all,
                    limit,
                },
                SuppressAction::Remove { id } => commands::suppress::SuppressAction::Remove { id },
                SuppressAction::Show { id, history } => {
                    commands::suppress::SuppressAction::Show { id, history }
                }
                SuppressAction::Export { output } => {
                    commands::suppress::SuppressAction::Export { output }
                }
                SuppressAction::Import { input } => {
                    commands::suppress::SuppressAction::Import { input }
                }
                SuppressAction::Check { prune } => {
                    commands::suppress::SuppressAction::Check { prune }
                }
                SuppressAction::Log { limit } => commands::suppress::SuppressAction::Log { limit },
            };
            commands::suppress::run(commands::suppress::SuppressArgs {
                action: suppress_action,
                path,
                quiet: cli.quiet,
            })
        }

        Commands::Security {
            path,
            format,
            severity,
            details,
            fix,
            offline,
            skip_docker,
            skip_deps,
            skip_code,
            fail_on,
            no_fail,
            include_tests,
        } => {
            let severity = match severity.to_lowercase().as_str() {
                "critical" => rma_common::Severity::Critical,
                "high" => rma_common::Severity::Error,
                "medium" => rma_common::Severity::Warning,
                "low" => rma_common::Severity::Info,
                _ => rma_common::Severity::Info,
            };
            let format = format.parse().unwrap_or_default();

            // Parse fail_on severity, or use None if --no-fail is set
            let fail_on = if no_fail {
                commands::security::FailSeverity::None
            } else {
                fail_on
                    .parse()
                    .unwrap_or(commands::security::FailSeverity::High)
            };

            commands::security::run(commands::security::SecurityArgs {
                path,
                format,
                severity,
                details,
                fix,
                offline,
                skip_docker,
                skip_deps,
                skip_code,
                fail_on,
                include_tests,
            })
        }

        Commands::Fix {
            path,
            strategy,
            max_bump,
            allow_prerelease,
            allow_yanked,
            offline,
            explain,
            dry_run,
            apply,
            branch_name,
            commit,
            commit_prefix,
            force,
            no_git,
            limit,
            targets,
            allow_vulnerable_target,
            format,
        } => {
            let strategy = strategy.parse().unwrap_or_default();
            let max_bump = max_bump.parse().unwrap_or_default();
            let format = format.parse().unwrap_or_default();

            commands::fix::run(commands::fix::FixArgs {
                path,
                strategy,
                max_bump,
                allow_prerelease,
                allow_yanked,
                offline,
                explain,
                dry_run: dry_run || !apply, // dry_run is true unless --apply
                apply,
                branch_name,
                commit,
                commit_prefix,
                force,
                no_git,
                limit,
                targets,
                allow_vulnerable_target,
                format,
            })
        }

        Commands::Flows {
            path,
            format,
            output,
            sort_by,
            reverse,
            group_by,
            min_confidence,
            sink_type,
            source_type,
            evidence,
            through_file,
            limit,
            all,
            quiet,
            dedupe,
            stats,
            include_tests,
            no_cache,
            interactive,
        } => {
            let sort_by = sort_by.parse().unwrap_or_default();
            let group_by = group_by.parse().unwrap_or_default();

            commands::flows::run(commands::flows::FlowsArgs {
                path,
                format,
                output,
                sort_by,
                reverse,
                group_by,
                min_confidence,
                sink_type,
                source_type,
                evidence,
                through_file,
                limit,
                all,
                quiet: quiet || cli.quiet,
                dedupe,
                stats,
                include_tests,
                no_cache,
                interactive,
            })
        }
    };

    // Handle errors with helpful suggestions
    if let Err(e) = result {
        ui::errors::print_error(&e, cli.verbose > 0);
        std::process::exit(1);
    }

    Ok(())
}
