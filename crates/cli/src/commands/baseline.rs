//! Baseline command implementation
//!
//! Creates and manages baseline files for legacy code debt management.

use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::AnalyzerEngine;
use rma_common::{Baseline, RmaConfig, RmaTomlConfig};
use rma_parser::ParserEngine;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub struct BaselineArgs {
    pub path: PathBuf,
    pub output: Option<PathBuf>,
    pub update: bool,
    pub quiet: bool,
}

pub fn run(args: BaselineArgs) -> Result<()> {
    let start = std::time::Instant::now();

    // Discover configuration
    let (config_path, toml_config) = RmaTomlConfig::discover(&args.path)
        .unwrap_or_else(|| (PathBuf::from("rma.toml"), RmaTomlConfig::default()));

    let output_path = args
        .output
        .unwrap_or_else(|| toml_config.baseline.file.clone());

    if !args.quiet {
        println!();
        println!("{}", Theme::header("Generating Baseline"));
        println!("{}", Theme::separator(60));

        if config_path.exists() {
            println!(
                "  {} Using config: {}",
                Theme::info_mark(),
                config_path.display().to_string().cyan()
            );
        }
        println!(
            "  {} Output: {}",
            Theme::info_mark(),
            output_path.display().to_string().cyan()
        );
        println!();
    }

    // Load existing baseline if updating
    let mut baseline = if args.update && output_path.exists() {
        Baseline::load(&output_path).unwrap_or_else(|_| Baseline::new())
    } else {
        Baseline::new()
    };

    // Scan the codebase
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = AnalyzerEngine::new(config);

    let (parsed_files, _stats) = parser.parse_directory(&args.path)?;

    if !args.quiet {
        println!(
            "  {} Scanning {} files...",
            Theme::info_mark(),
            parsed_files.len()
        );
    }

    let (results, _summary) = analyzer.analyze_files(&parsed_files)?;

    // Generate fingerprints and add to baseline
    let mut new_count = 0;
    let mut existing_count = 0;

    for result in &results {
        for finding in &result.findings {
            let fingerprint = generate_fingerprint(
                &finding.rule_id,
                &result.path,
                finding.snippet.as_deref().unwrap_or(""),
            );

            let file_path = PathBuf::from(&result.path);

            if baseline.contains(&finding.rule_id, &file_path, &fingerprint) {
                existing_count += 1;
            } else {
                baseline.add(
                    finding.rule_id.clone(),
                    file_path,
                    finding.location.start_line,
                    fingerprint,
                );
                new_count += 1;
            }
        }
    }

    // Save baseline
    baseline.save(&output_path).map_err(|e| anyhow::anyhow!(e))?;

    let duration = start.elapsed();

    if !args.quiet {
        println!();
        println!("{}", Theme::double_separator(60));
        println!("{} Baseline generated!", Theme::success_mark());
        println!();
        println!(
            "  {} Total entries: {}",
            Theme::bullet(),
            baseline.entries.len().to_string().cyan()
        );
        if args.update {
            println!(
                "  {} New entries: {}",
                Theme::bullet(),
                new_count.to_string().green()
            );
            println!(
                "  {} Existing: {}",
                Theme::bullet(),
                existing_count.to_string().dimmed()
            );
        }
        println!(
            "  {} Saved to: {}",
            Theme::bullet(),
            output_path.display().to_string().yellow()
        );
        println!(
            "  {} Duration: {:.2}s",
            Theme::bullet(),
            duration.as_secs_f64()
        );
        println!();
        println!("  {}", "Next steps:".cyan().bold());
        println!(
            "  {} Set {} in rma.toml to only report new issues",
            Theme::bullet(),
            "baseline.mode = \"new-only\"".yellow()
        );
        println!(
            "  {} Commit {} to track legacy debt",
            Theme::bullet(),
            output_path.display().to_string().yellow()
        );
        println!();
    }

    Ok(())
}

/// Generate a stable fingerprint for a finding
fn generate_fingerprint(rule_id: &str, file: &str, snippet: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(file.as_bytes());
    // Normalize whitespace in snippet for stability
    let normalized: String = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    hasher.update(normalized.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)[..16].to_string()
}

/// Show baseline statistics
#[allow(dead_code)]
pub fn show_stats(path: &std::path::Path) -> Result<()> {
    let baseline = Baseline::load(path).map_err(|e| anyhow::anyhow!(e))?;

    println!();
    println!("{}", Theme::header("Baseline Statistics"));
    println!("{}", Theme::separator(60));
    println!();

    println!(
        "  {} Version: {}",
        Theme::bullet(),
        baseline.version.cyan()
    );
    println!(
        "  {} Created: {}",
        Theme::bullet(),
        baseline.created.dimmed()
    );
    println!(
        "  {} Total entries: {}",
        Theme::bullet(),
        baseline.entries.len().to_string().yellow()
    );

    // Group by rule
    let mut by_rule: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut suppressed = 0;

    for entry in &baseline.entries {
        *by_rule.entry(&entry.rule_id).or_insert(0) += 1;
        if entry.suppressed {
            suppressed += 1;
        }
    }

    println!(
        "  {} Suppressed: {}",
        Theme::bullet(),
        suppressed.to_string().dimmed()
    );
    println!();
    println!("  {} By rule:", Theme::bullet());

    let mut sorted_rules: Vec<_> = by_rule.iter().collect();
    sorted_rules.sort_by(|a, b| b.1.cmp(a.1));

    for (rule, count) in sorted_rules.iter().take(10) {
        println!(
            "    {} {}: {}",
            Theme::bullet(),
            rule.bright_white(),
            count.to_string().cyan()
        );
    }

    if sorted_rules.len() > 10 {
        println!(
            "    {} ... and {} more rules",
            Theme::bullet(),
            (sorted_rules.len() - 10).to_string().dimmed()
        );
    }

    println!();

    Ok(())
}
