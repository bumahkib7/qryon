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
    },

    /// Watch for file changes and re-analyze in real-time
    #[command(visible_alias = "w")]
    Watch {
        /// Path to watch
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Debounce interval for file changes
        #[arg(short, long, default_value = "500ms")]
        interval: String,

        /// Enable AI analysis on changes
        #[arg(long)]
        ai: bool,

        /// Only watch specific file patterns
        #[arg(short, long)]
        pattern: Option<String>,
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

    /// Run benchmarks
    #[command(hide = true)]
    Bench {
        /// Path to benchmark
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Number of iterations
        #[arg(short, long, default_value = "3")]
        iterations: usize,
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
        }),

        Commands::Watch {
            path,
            interval,
            ai,
            pattern,
        } => commands::watch::run(commands::watch::WatchArgs {
            path,
            interval,
            ai,
            pattern,
            quiet: cli.quiet,
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

        Commands::Bench { path, iterations } => {
            commands::bench::run(commands::bench::BenchArgs { path, iterations })
        }
    };

    // Handle errors with helpful suggestions
    if let Err(e) = result {
        ui::errors::print_error(&e, cli.verbose > 0);
        std::process::exit(1);
    }

    Ok(())
}
