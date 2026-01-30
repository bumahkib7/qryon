//! RMA CLI - Rust Monorepo Analyzer Command Line Interface

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rma_analyzer::{AnalyzerEngine, AnalysisSummary, FileAnalysis};
use rma_common::{RmaConfig, Severity};
use rma_indexer::{IndexConfig, IndexerEngine};
use rma_parser::ParserEngine;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "rma")]
#[command(author = "RMA Team")]
#[command(version = "0.1.0")]
#[command(about = "Ultra-fast Rust-native code intelligence and security analyzer", long_about = None)]
struct Cli {
    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a repository for security issues and code metrics
    Scan {
        /// Path to the repository to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "text")]
        output: OutputFormat,

        /// Output file (stdout if not specified)
        #[arg(short = 'f', long)]
        output_file: Option<PathBuf>,

        /// Minimum severity to report
        #[arg(short, long, default_value = "warning")]
        severity: SeverityArg,

        /// Enable incremental mode
        #[arg(short, long)]
        incremental: bool,

        /// Number of parallel workers (0 = auto)
        #[arg(short = 'j', long, default_value = "0")]
        parallelism: usize,

        /// Languages to scan (comma-separated, empty = all)
        #[arg(short, long)]
        languages: Option<String>,
    },

    /// Search the index for files or findings
    Search {
        /// Search query
        query: String,

        /// Maximum results
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Show index statistics
    Stats,

    /// Initialize RMA configuration
    Init {
        /// Path to initialize
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Watch for file changes and re-analyze
    Watch {
        /// Path to watch
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Info,
    Warning,
    Error,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Warning => Severity::Warning,
            SeverityArg::Error => Severity::Error,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = match cli.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Scan {
            path,
            output,
            output_file,
            severity,
            incremental,
            parallelism,
            languages,
        } => {
            run_scan(
                &path,
                output,
                output_file,
                severity.into(),
                incremental,
                parallelism,
                languages,
            )?;
        }
        Commands::Search { query, limit } => {
            run_search(&query, limit)?;
        }
        Commands::Stats => {
            run_stats()?;
        }
        Commands::Init { path } => {
            run_init(&path)?;
        }
        Commands::Watch { path } => {
            run_watch(&path)?;
        }
    }

    Ok(())
}

fn run_scan(
    path: &PathBuf,
    output: OutputFormat,
    output_file: Option<PathBuf>,
    min_severity: Severity,
    incremental: bool,
    parallelism: usize,
    languages: Option<String>,
) -> Result<()> {
    let start = Instant::now();

    println!("{}", "🔍 RMA - Rust Monorepo Analyzer".cyan().bold());
    println!("Scanning: {}\n", path.display());

    // Build config
    let mut config = RmaConfig::default();
    config.min_severity = min_severity;
    config.incremental = incremental;
    config.parallelism = parallelism;

    if let Some(langs) = languages {
        config.languages = langs
            .split(',')
            .filter_map(|l| match l.trim().to_lowercase().as_str() {
                "rust" | "rs" => Some(rma_common::Language::Rust),
                "javascript" | "js" => Some(rma_common::Language::JavaScript),
                "typescript" | "ts" => Some(rma_common::Language::TypeScript),
                "python" | "py" => Some(rma_common::Language::Python),
                "go" => Some(rma_common::Language::Go),
                "java" => Some(rma_common::Language::Java),
                _ => None,
            })
            .collect();
    }

    // Parse
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")?,
    );
    pb.set_message("Parsing files...");

    let parser = ParserEngine::new(config.clone());
    let (parsed_files, parse_stats) = parser.parse_directory(path)?;

    pb.finish_with_message(format!(
        "✓ Parsed {} files ({} skipped)",
        parse_stats.files_parsed, parse_stats.files_skipped
    ));

    // Analyze
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")?,
    );
    pb.set_message("Analyzing...");

    let analyzer = AnalyzerEngine::new(config.clone());
    let (results, summary) = analyzer.analyze_files(&parsed_files)?;

    pb.finish_with_message(format!(
        "✓ Analyzed {} files, found {} findings",
        summary.files_analyzed, summary.total_findings
    ));

    // Index results
    let index_config = IndexConfig {
        index_path: path.join(".rma/index"),
        ..Default::default()
    };

    if let Ok(indexer) = IndexerEngine::new(index_config) {
        let _ = indexer.index_results(&results);
    }

    let duration = start.elapsed();

    // Output results
    match output {
        OutputFormat::Text => output_text(&results, &summary, duration),
        OutputFormat::Json => output_json(&results, &summary, duration, output_file)?,
        OutputFormat::Sarif => output_sarif(&results, output_file)?,
    }

    Ok(())
}

fn output_text(results: &[FileAnalysis], summary: &AnalysisSummary, duration: std::time::Duration) {
    println!("\n{}", "═".repeat(60).dimmed());
    println!("{}", "SCAN SUMMARY".cyan().bold());
    println!("{}", "═".repeat(60).dimmed());

    println!("Files analyzed:    {}", summary.files_analyzed);
    println!("Total lines:       {}", summary.total_loc);
    println!("Total complexity:  {}", summary.total_complexity);
    println!("Duration:          {:.2}s", duration.as_secs_f64());

    println!("\n{}", "FINDINGS".yellow().bold());
    println!("{}", "─".repeat(40).dimmed());

    if summary.critical_count > 0 {
        println!(
            "  {} Critical:  {}",
            "●".red(),
            summary.critical_count.to_string().red().bold()
        );
    }
    if summary.error_count > 0 {
        println!(
            "  {} Error:     {}",
            "●".bright_red(),
            summary.error_count.to_string().bright_red()
        );
    }
    if summary.warning_count > 0 {
        println!(
            "  {} Warning:   {}",
            "●".yellow(),
            summary.warning_count.to_string().yellow()
        );
    }
    if summary.info_count > 0 {
        println!(
            "  {} Info:      {}",
            "●".blue(),
            summary.info_count.to_string().blue()
        );
    }

    println!("\n{}", "DETAILS".cyan().bold());
    println!("{}", "─".repeat(40).dimmed());

    for result in results {
        if result.findings.is_empty() {
            continue;
        }

        println!("\n{}", result.path.bright_white());

        for finding in &result.findings {
            let severity_color = match finding.severity {
                Severity::Critical => "CRIT".red().bold(),
                Severity::Error => "ERR ".bright_red(),
                Severity::Warning => "WARN".yellow(),
                Severity::Info => "INFO".blue(),
            };

            println!(
                "  {} [{}] {}:{}  {}",
                severity_color,
                finding.rule_id.dimmed(),
                finding.location.start_line,
                finding.location.start_column,
                finding.message
            );

            if let Some(snippet) = &finding.snippet {
                let truncated = if snippet.len() > 80 {
                    format!("{}...", &snippet[..77])
                } else {
                    snippet.clone()
                };
                println!("      {}", truncated.dimmed());
            }
        }
    }

    println!("\n{}", "═".repeat(60).dimmed());
}

fn output_json(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: std::time::Duration,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let output = serde_json::json!({
        "summary": summary,
        "duration_ms": duration.as_millis(),
        "results": results,
    });

    let json = serde_json::to_string_pretty(&output)?;

    if let Some(path) = output_file {
        std::fs::write(path, &json)?;
    } else {
        println!("{}", json);
    }

    Ok(())
}

fn output_sarif(results: &[FileAnalysis], output_file: Option<PathBuf>) -> Result<()> {
    // Build SARIF report
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RMA",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/bumahkib7/rust-monorepo-analyzer"
                }
            },
            "results": results.iter().flat_map(|r| {
                r.findings.iter().map(|f| {
                    serde_json::json!({
                        "ruleId": f.rule_id,
                        "level": match f.severity {
                            Severity::Critical | Severity::Error => "error",
                            Severity::Warning => "warning",
                            Severity::Info => "note",
                        },
                        "message": {
                            "text": f.message
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.location.file.display().to_string()
                                },
                                "region": {
                                    "startLine": f.location.start_line,
                                    "startColumn": f.location.start_column,
                                    "endLine": f.location.end_line,
                                    "endColumn": f.location.end_column
                                }
                            }
                        }]
                    })
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>()
        }]
    });

    let json = serde_json::to_string_pretty(&sarif)?;

    if let Some(path) = output_file {
        std::fs::write(path, &json)?;
    } else {
        println!("{}", json);
    }

    Ok(())
}

fn run_search(query: &str, limit: usize) -> Result<()> {
    let index_config = IndexConfig {
        index_path: PathBuf::from(".rma/index"),
        ..Default::default()
    };

    let indexer = IndexerEngine::new(index_config)?;
    let results = indexer.search(query, limit)?;

    println!("{}", "Search Results".cyan().bold());
    println!("{}", "─".repeat(40).dimmed());

    for result in results {
        println!(
            "{} ({}) - {} findings, score: {:.2}",
            result.path.bright_white(),
            result.language.dimmed(),
            result.findings_count,
            result.score
        );
    }

    Ok(())
}

fn run_stats() -> Result<()> {
    let index_config = IndexConfig {
        index_path: PathBuf::from(".rma/index"),
        ..Default::default()
    };

    let indexer = IndexerEngine::new(index_config)?;
    let stats = indexer.stats()?;

    println!("{}", "Index Statistics".cyan().bold());
    println!("{}", "─".repeat(40).dimmed());
    println!("Index path:     {:?}", stats.index_path);
    println!("Documents:      {}", stats.num_docs);

    Ok(())
}

fn run_init(path: &PathBuf) -> Result<()> {
    let config_dir = path.join(".rma");
    std::fs::create_dir_all(&config_dir)?;

    let config = RmaConfig::default();
    let config_json = serde_json::to_string_pretty(&config)?;
    std::fs::write(config_dir.join("config.json"), config_json)?;

    println!("{} Initialized RMA in {:?}", "✓".green(), path);
    println!("  Created .rma/config.json");

    Ok(())
}

fn run_watch(path: &PathBuf) -> Result<()> {
    use rma_indexer::watcher;

    println!(
        "{} Watching {} for changes...",
        "👁".cyan(),
        path.display()
    );
    println!("Press Ctrl+C to stop\n");

    let (_watcher, rx) = watcher::watch_directory(path)?;

    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = AnalyzerEngine::new(config);

    loop {
        match rx.recv() {
            Ok(event) => {
                let events = watcher::filter_source_events(vec![event]);
                for ev in events {
                    println!(
                        "{} {:?}: {}",
                        "→".yellow(),
                        ev.kind,
                        ev.path.display()
                    );

                    // Re-analyze the changed file
                    if let Ok(content) = std::fs::read_to_string(&ev.path) {
                        if let Ok(parsed) = parser.parse_file(&ev.path, &content) {
                            if let Ok(analysis) = analyzer.analyze_file(&parsed) {
                                if !analysis.findings.is_empty() {
                                    println!(
                                        "  {} {} findings",
                                        "⚠".yellow(),
                                        analysis.findings.len()
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    Ok(())
}
