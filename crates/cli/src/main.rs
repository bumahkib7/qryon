//! RMA CLI - Rust Monorepo Analyzer Command Line Interface
//!
//! A sophisticated, intelligent, color-coded CLI for code analysis and security scanning.

mod commands;
mod output;
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
pub enum Commands {
    /// Scan a repository for security issues and code metrics
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
                SuppressAction::List { rule, file, all, limit } => {
                    commands::suppress::SuppressAction::List { rule, file, all, limit }
                }
                SuppressAction::Remove { id } => {
                    commands::suppress::SuppressAction::Remove { id }
                }
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
                SuppressAction::Log { limit } => {
                    commands::suppress::SuppressAction::Log { limit }
                }
            };
            commands::suppress::run(commands::suppress::SuppressArgs {
                action: suppress_action,
                path,
                quiet: cli.quiet,
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
