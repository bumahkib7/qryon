//! Stats command implementation

use crate::OutputFormat;
use crate::output::tables;
use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use comfy_table::{Cell, Color};
use rma_common::RmaConfig;
use rma_indexer::{IndexConfig, IndexerEngine};
use rma_parser::ParserEngine;
use std::collections::HashMap;
use std::path::PathBuf;

pub struct StatsArgs {
    pub path: PathBuf,
    pub detailed: bool,
    pub format: OutputFormat,
}

pub fn run(args: StatsArgs) -> Result<()> {
    // Try to get stats from index first
    let index_path = args.path.join(".qryon/index");
    let index_config = IndexConfig {
        index_path: index_path.clone(),
        ..Default::default()
    };

    let index_stats = IndexerEngine::new(index_config)
        .ok()
        .and_then(|i| i.stats().ok());

    // Get fresh stats by parsing
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config);
    let (parsed_files, parse_stats) = parser.parse_directory(&args.path)?;

    // Compute language breakdown
    let mut lang_stats: HashMap<String, LangStats> = HashMap::new();

    for file in &parsed_files {
        let lang = format!("{:?}", file.language);
        let entry = lang_stats.entry(lang).or_default();
        entry.files += 1;
        entry.lines += file.content.lines().count();
    }

    match args.format {
        OutputFormat::Text => output_text(&args, &parse_stats, &lang_stats, index_stats.as_ref()),
        OutputFormat::Json => output_json(&args, &parse_stats, &lang_stats, index_stats.as_ref())?,
        _ => output_text(&args, &parse_stats, &lang_stats, index_stats.as_ref()),
    }

    Ok(())
}

#[derive(Default)]
struct LangStats {
    files: usize,
    lines: usize,
}

fn output_text(
    args: &StatsArgs,
    parse_stats: &rma_parser::ParseStats,
    lang_stats: &HashMap<String, LangStats>,
    index_stats: Option<&rma_indexer::IndexStats>,
) {
    println!();
    println!("{}", Theme::header("Repository Statistics"));
    println!("{}", Theme::double_separator(60));
    println!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    );
    println!();

    // Overview
    println!("{}", Theme::subheader("Overview"));
    println!("{}", Theme::separator(40));

    let total_files: usize = lang_stats.values().map(|s| s.files).sum();
    let total_lines: usize = lang_stats.values().map(|s| s.lines).sum();

    println!(
        "  {:<20} {}",
        "Total files:",
        total_files.to_string().bright_white()
    );
    println!(
        "  {:<20} {}",
        "Total lines:",
        format_number(total_lines).bright_white()
    );
    println!(
        "  {:<20} {}",
        "Files parsed:",
        parse_stats.files_parsed.to_string().green()
    );
    println!(
        "  {:<20} {}",
        "Files skipped:",
        parse_stats.files_skipped.to_string().dimmed()
    );

    if let Some(idx) = index_stats {
        println!(
            "  {:<20} {}",
            "Indexed docs:",
            idx.num_docs.to_string().cyan()
        );
    }

    println!();

    // Language breakdown
    if args.detailed || lang_stats.len() > 1 {
        println!("{}", Theme::subheader("By Language"));
        println!("{}", Theme::separator(40));

        let mut table = tables::create_table();
        table.set_header(vec!["Language", "Files", "Lines", "%"]);

        let mut sorted: Vec<_> = lang_stats.iter().collect();
        sorted.sort_by(|a, b| b.1.lines.cmp(&a.1.lines));

        for (lang, stats) in sorted {
            let pct = if total_lines > 0 {
                (stats.lines as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };

            table.add_row(vec![
                Cell::new(lang).fg(Color::Cyan),
                Cell::new(stats.files),
                Cell::new(format_number(stats.lines)),
                Cell::new(format!("{:.1}%", pct)),
            ]);
        }

        println!("{}", table);
    }

    println!();
}

fn output_json(
    args: &StatsArgs,
    parse_stats: &rma_parser::ParseStats,
    lang_stats: &HashMap<String, LangStats>,
    index_stats: Option<&rma_indexer::IndexStats>,
) -> Result<()> {
    let total_files: usize = lang_stats.values().map(|s| s.files).sum();
    let total_lines: usize = lang_stats.values().map(|s| s.lines).sum();

    let output = serde_json::json!({
        "path": args.path.display().to_string(),
        "overview": {
            "total_files": total_files,
            "total_lines": total_lines,
            "files_parsed": parse_stats.files_parsed,
            "files_skipped": parse_stats.files_skipped,
        },
        "by_language": lang_stats.iter().map(|(lang, stats)| {
            (lang.clone(), serde_json::json!({
                "files": stats.files,
                "lines": stats.lines,
            }))
        }).collect::<HashMap<_, _>>(),
        "index": index_stats.map(|s| serde_json::json!({
            "num_docs": s.num_docs,
            "path": s.index_path.display().to_string(),
        })),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

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
