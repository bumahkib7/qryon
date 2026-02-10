//! Search command implementation

use crate::OutputFormat;
use crate::ui::theme::Theme;
use anyhow::{Context, Result};
use colored::Colorize;
use rma_common::Severity;
use rma_indexer::{IndexConfig, IndexerEngine};
use std::path::PathBuf;

#[allow(dead_code)]
pub struct SearchArgs {
    pub query: String,
    pub repo: PathBuf,
    pub limit: usize,
    pub severity: Option<Severity>,
    pub rule: Option<String>,
    pub format: OutputFormat,
}

pub fn run(args: SearchArgs) -> Result<()> {
    let index_path = args.repo.join(".qryon/index");
    let index_config = IndexConfig {
        index_path: index_path.clone(),
        ..Default::default()
    };

    let indexer = IndexerEngine::new(index_config)
        .context("Failed to open index. Run 'qryon scan' first to build the index.")?;

    let results = indexer
        .search(&args.query, args.limit)
        .context("Search failed")?;

    match args.format {
        OutputFormat::Text => output_text(&args, &results),
        OutputFormat::Json => output_json(&results)?,
        _ => output_text(&args, &results),
    }

    Ok(())
}

fn output_text(args: &SearchArgs, results: &[rma_indexer::SearchResult]) {
    println!();
    println!("{}", Theme::header("Search Results"));
    println!("{}", Theme::separator(60));
    println!(
        "  Query: {}  |  Found: {} results",
        args.query.bright_white(),
        results.len().to_string().cyan()
    );
    println!();

    if results.is_empty() {
        println!("  {} No results found", Theme::info_mark());
        println!();
        println!(
            "  {} Try a different search term or run 'qryon scan' to update the index",
            "hint:".dimmed()
        );
    } else {
        for (i, result) in results.iter().enumerate() {
            println!(
                "  {}. {} {}",
                (i + 1).to_string().dimmed(),
                result.path.bright_white(),
                format!("({})", result.language).dimmed()
            );
            println!(
                "     {} {} findings  {} score: {:.2}",
                Theme::bullet(),
                result.findings_count.to_string().yellow(),
                Theme::bullet(),
                result.score
            );
        }
    }

    println!();
}

fn output_json(results: &[rma_indexer::SearchResult]) -> Result<()> {
    let json = serde_json::to_string_pretty(&results)?;
    println!("{}", json);
    Ok(())
}
