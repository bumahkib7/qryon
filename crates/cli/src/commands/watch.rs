//! Watch command implementation

use crate::ui::theme::Theme;
use anyhow::{Context, Result};
use colored::Colorize;
use rma_analyzer::AnalyzerEngine;
use rma_common::RmaConfig;
use rma_indexer::watcher;
use rma_parser::ParserEngine;
use std::path::PathBuf;

pub struct WatchArgs {
    pub path: PathBuf,
    pub interval: String,
    pub ai: bool,
    pub pattern: Option<String>,
    pub quiet: bool,
}

pub fn run(args: WatchArgs) -> Result<()> {
    if !args.quiet {
        print_watch_header(&args);
    }

    let (_watcher, rx) =
        watcher::watch_directory(&args.path).context("Failed to start file watcher")?;

    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = AnalyzerEngine::new(config);

    if !args.quiet {
        println!("{} Watching for changes...\n", Theme::info_mark());
    }

    while let Ok(event) = rx.recv() {
        let events = watcher::filter_source_events(vec![event]);

        for ev in events {
            // Apply pattern filter if specified
            if let Some(ref pattern) = args.pattern {
                let path_str = ev.path.to_string_lossy();
                if !path_str.contains(pattern) {
                    continue;
                }
            }

            if !args.quiet {
                println!(
                    "{} {} {}",
                    Theme::arrow(),
                    format!("{:?}", ev.kind).dimmed(),
                    Theme::path(&ev.path)
                );
            }

            // Re-analyze the changed file
            if let Ok(content) = std::fs::read_to_string(&ev.path)
                && let Ok(parsed) = parser.parse_file(&ev.path, &content)
            {
                match analyzer.analyze_file(&parsed) {
                    Ok(analysis) => {
                        if !args.quiet {
                            if analysis.findings.is_empty() {
                                println!("    {} No issues", Theme::success_mark());
                            } else {
                                println!(
                                    "    {} {} findings",
                                    Theme::warning_mark(),
                                    analysis.findings.len().to_string().yellow()
                                );

                                for finding in &analysis.findings {
                                    println!(
                                        "      {} [{}] {}:{} {}",
                                        Theme::severity(finding.severity),
                                        finding.rule_id.dimmed(),
                                        finding.location.start_line,
                                        finding.location.start_column,
                                        finding.message.dimmed()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if !args.quiet {
                            println!("    {} Analysis failed: {}", Theme::error_mark(), e);
                        }
                    }
                }
            }

            if !args.quiet {
                println!();
            }
        }
    }

    Ok(())
}

fn print_watch_header(args: &WatchArgs) {
    println!();
    println!("{}", "👁  RMA Watch Mode".cyan().bold());
    println!("{}", Theme::separator(50));
    println!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    );
    println!(
        "  {} {}",
        "Interval:".dimmed(),
        args.interval.bright_white()
    );

    if let Some(ref pattern) = args.pattern {
        println!("  {} {}", "Pattern:".dimmed(), pattern.bright_white());
    }

    if args.ai {
        println!("  {} {}", "AI:".dimmed(), "enabled".green());
    }

    println!("\n  Press {} to stop", "Ctrl+C".yellow());
    println!();
}
