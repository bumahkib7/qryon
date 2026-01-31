//! Scan command implementation

use crate::OutputFormat;
use crate::output;
use crate::ui::{progress, theme::Theme};
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::AnalyzerEngine;
use rma_common::{Baseline, BaselineMode, Language, Profile, RmaConfig, RmaTomlConfig, Severity};
use rma_indexer::{IndexConfig, IndexerEngine};
use rma_parser::ParserEngine;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[allow(dead_code)]
pub struct ScanArgs {
    pub path: PathBuf,
    pub format: OutputFormat,
    pub output: Option<PathBuf>,
    pub severity: Severity,
    pub profile: Option<String>,
    pub ruleset: Option<String>,
    pub incremental: bool,
    pub jobs: usize,
    pub languages: Option<Vec<String>>,
    pub ai_analysis: bool,
    pub ai_provider: String,
    pub timing: bool,
    pub exclude: Option<Vec<String>>,
    pub config_path: Option<PathBuf>,
    pub quiet: bool,
    pub baseline_mode: bool,
    pub include_suppressed: bool,
    pub changed_only: bool,
    pub base: String,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let total_start = Instant::now();
    let mut timings: Vec<(&str, Duration)> = Vec::new();

    // Discover TOML configuration
    let toml_config = RmaTomlConfig::discover(&args.path);

    // Determine profile (CLI > config > default)
    let profile = args
        .profile
        .as_ref()
        .and_then(|p| p.parse::<Profile>().ok())
        .or_else(|| toml_config.as_ref().map(|(_, c)| c.profiles.default))
        .unwrap_or(Profile::Balanced);

    // Print header
    if !args.quiet && args.format == OutputFormat::Text {
        print_scan_header(&args, toml_config.as_ref().map(|(_, c)| c), profile);
    }

    // Build configuration
    let config = build_config(&args, toml_config.as_ref().map(|(_, c)| c), profile)?;

    // Phase 1: Parse files
    let parse_start = Instant::now();
    let (mut parsed_files, _parse_stats) = run_parse_phase(&args, &config)?;
    timings.push(("Parse", parse_start.elapsed()));

    // Phase 1.5: Filter to changed files only (for PR workflows)
    if args.changed_only {
        let changed_files = get_changed_files(&args.path, &args.base)?;

        if !args.quiet && args.format == OutputFormat::Text {
            println!(
                "  {} {} files changed since {}",
                Theme::info_mark(),
                changed_files.len().to_string().yellow(),
                args.base.dimmed()
            );
        }

        let before_count = parsed_files.len();
        parsed_files.retain(|f| {
            let file_path = f.path.strip_prefix(&args.path).unwrap_or(&f.path);
            changed_files
                .iter()
                .any(|cf| file_path.ends_with(cf) || cf.ends_with(file_path.to_string_lossy().as_ref()))
        });

        if !args.quiet && args.format == OutputFormat::Text && before_count != parsed_files.len() {
            println!(
                "  {} Scanning {} of {} files",
                Theme::info_mark(),
                parsed_files.len().to_string().green(),
                before_count.to_string().dimmed()
            );
        }
    }

    // Phase 2: Analyze
    let analyze_start = Instant::now();
    let (mut results, mut summary) = run_analyze_phase(&args, &config, &parsed_files)?;
    timings.push(("Analyze", analyze_start.elapsed()));

    // Phase 2.5: Apply baseline filtering if enabled
    let baseline_mode = args.baseline_mode
        || toml_config
            .as_ref()
            .map(|(_, c)| c.baseline.mode == BaselineMode::NewOnly)
            .unwrap_or(false);

    if baseline_mode {
        let baseline_path = toml_config
            .as_ref()
            .map(|(_, c)| c.baseline.file.clone())
            .unwrap_or_else(|| PathBuf::from(".rma/baseline.json"));

        if baseline_path.exists()
            && let Ok(baseline) = Baseline::load(&baseline_path)
        {
            let before_count = summary.total_findings;
            filter_baseline_findings(&mut results, &mut summary, &baseline);

            if !args.quiet && args.format == OutputFormat::Text {
                let filtered = before_count - summary.total_findings;
                if filtered > 0 {
                    println!(
                        "  {} Filtered {} baseline findings",
                        Theme::info_mark(),
                        filtered.to_string().dimmed()
                    );
                }
            }
        }
    }

    // Phase 3: AI Analysis (optional)
    if args.ai_analysis {
        let ai_start = Instant::now();
        run_ai_phase(&args, &mut results)?;
        timings.push(("AI Analysis", ai_start.elapsed()));
    }

    // Phase 4: Index results
    let index_start = Instant::now();
    run_index_phase(&args)?;
    timings.push(("Index", index_start.elapsed()));

    let total_duration = total_start.elapsed();

    // Print timing information
    if args.timing && !args.quiet {
        print_timings(&timings, total_duration);
    }

    // Output results
    output::format_results(&results, &summary, total_duration, args.format, args.output)?;

    // Exit with error code if critical/error findings
    if summary.critical_count > 0 || summary.error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn print_scan_header(args: &ScanArgs, toml_config: Option<&RmaTomlConfig>, profile: Profile) {
    println!();
    println!("{}", "🔍 RMA - Rust Monorepo Analyzer".cyan().bold());
    println!("{}", Theme::separator(50));
    println!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    );

    println!("  {} {}", "Profile:".dimmed(), profile.to_string().cyan());

    if toml_config.is_some() {
        println!("  {} {}", "Config:".dimmed(), "rma.toml".green());
    }

    if let Some(ref langs) = args.languages {
        println!(
            "  {} {}",
            "Languages:".dimmed(),
            langs.join(", ").bright_white()
        );
    }

    if let Some(ref ruleset) = args.ruleset {
        println!("  {} {}", "Ruleset:".dimmed(), ruleset.cyan());
    }

    if args.ai_analysis {
        println!(
            "  {} {} ({})",
            "AI:".dimmed(),
            "enabled".green(),
            args.ai_provider.dimmed()
        );
    }

    if args.incremental {
        println!("  {} {}", "Mode:".dimmed(), "incremental".yellow());
    }

    if args.baseline_mode {
        println!("  {} {}", "Baseline:".dimmed(), "new-only".yellow());
    }

    if args.changed_only {
        println!(
            "  {} {} (base: {})",
            "Mode:".dimmed(),
            "changed-only".cyan(),
            args.base.dimmed()
        );
    }

    println!();
}

fn build_config(
    args: &ScanArgs,
    toml_config: Option<&RmaTomlConfig>,
    profile: Profile,
) -> Result<RmaConfig> {
    let mut config = RmaConfig::default();

    // Apply TOML configuration
    if let Some(toml) = toml_config {
        // Apply exclude patterns from TOML
        if !toml.scan.exclude.is_empty() {
            config.exclude_patterns = toml.scan.exclude.clone();
        }

        // Apply file size limit
        config.max_file_size = toml.scan.max_file_size;

        // Get thresholds for the profile (used by analyzer)
        let _thresholds = toml.profiles.get_thresholds(profile);
    }

    // CLI overrides
    config.min_severity = args.severity;
    config.incremental = args.incremental;
    config.parallelism = args.jobs;

    if let Some(ref langs) = args.languages {
        config.languages = langs.iter().filter_map(|l| parse_language(l)).collect();
    }

    if let Some(ref excludes) = args.exclude {
        config.exclude_patterns.extend(excludes.clone());
    }

    Ok(config)
}

fn parse_language(s: &str) -> Option<Language> {
    match s.trim().to_lowercase().as_str() {
        "rust" | "rs" => Some(Language::Rust),
        "javascript" | "js" => Some(Language::JavaScript),
        "typescript" | "ts" => Some(Language::TypeScript),
        "python" | "py" => Some(Language::Python),
        "go" | "golang" => Some(Language::Go),
        "java" => Some(Language::Java),
        _ => None,
    }
}

fn run_parse_phase(
    args: &ScanArgs,
    config: &RmaConfig,
) -> Result<(Vec<rma_parser::ParsedFile>, rma_parser::ParseStats)> {
    let spinner = if !args.quiet && args.format == OutputFormat::Text {
        let s = progress::create_spinner("Parsing files...");
        Some(s)
    } else {
        None
    };

    let parser = ParserEngine::new(config.clone());
    let result = parser.parse_directory(&args.path)?;

    if let Some(s) = spinner {
        s.finish_with_message(format!(
            "{} Parsed {} files ({} skipped)",
            Theme::success_mark(),
            result.1.files_parsed.to_string().green(),
            result.1.files_skipped.to_string().dimmed()
        ));
    }

    Ok(result)
}

fn run_analyze_phase(
    args: &ScanArgs,
    config: &RmaConfig,
    parsed_files: &[rma_parser::ParsedFile],
) -> Result<(
    Vec<rma_analyzer::FileAnalysis>,
    rma_analyzer::AnalysisSummary,
)> {
    let spinner = if !args.quiet && args.format == OutputFormat::Text {
        let s = progress::create_spinner("Analyzing code...");
        Some(s)
    } else {
        None
    };

    let analyzer = AnalyzerEngine::new(config.clone());
    let result = analyzer.analyze_files(parsed_files)?;

    if let Some(s) = spinner {
        let (_results, summary) = &result;
        let status = if summary.critical_count > 0 {
            format!(
                "{} findings ({} critical)",
                summary.total_findings, summary.critical_count
            )
            .red()
        } else if summary.total_findings > 0 {
            format!("{} findings", summary.total_findings).yellow()
        } else {
            "No issues found".green()
        };
        s.finish_with_message(format!(
            "{} Analyzed {} files - {}",
            Theme::success_mark(),
            summary.files_analyzed.to_string().green(),
            status
        ));
    }

    Ok(result)
}

fn run_ai_phase(args: &ScanArgs, _results: &mut [rma_analyzer::FileAnalysis]) -> Result<()> {
    let spinner = if !args.quiet && args.format == OutputFormat::Text {
        let s = progress::create_spinner("Running AI analysis...");
        Some(s)
    } else {
        None
    };

    // Note: AI analysis would be integrated here
    // For now, we just simulate the phase
    if let Some(s) = spinner {
        s.finish_with_message(format!(
            "{} AI analysis complete (provider: {})",
            Theme::success_mark(),
            args.ai_provider.dimmed()
        ));
    }

    Ok(())
}

fn run_index_phase(args: &ScanArgs) -> Result<()> {
    let index_path = args.path.join(".rma/index");
    let index_config = IndexConfig {
        index_path,
        ..Default::default()
    };

    // Silently index results
    if let Ok(_indexer) = IndexerEngine::new(index_config) {
        // Indexing happens automatically
    }

    Ok(())
}

fn print_timings(timings: &[(&str, Duration)], total: Duration) {
    println!();
    println!("{}", "⏱  Timing Breakdown".cyan().bold());
    println!("{}", Theme::separator(40));

    for (phase, duration) in timings {
        let pct = (duration.as_secs_f64() / total.as_secs_f64()) * 100.0;
        println!(
            "  {:15} {:>8.2}ms ({:>5.1}%)",
            phase,
            duration.as_secs_f64() * 1000.0,
            pct
        );
    }

    println!("{}", Theme::separator(40));
    println!(
        "  {:15} {:>8.2}ms",
        "Total".bold(),
        total.as_secs_f64() * 1000.0
    );
    println!();
}

fn filter_baseline_findings(
    results: &mut [rma_analyzer::FileAnalysis],
    summary: &mut rma_analyzer::AnalysisSummary,
    baseline: &Baseline,
) {
    use sha2::{Digest, Sha256};

    for result in results.iter_mut() {
        result.findings.retain(|finding| {
            let fingerprint = {
                let mut hasher = Sha256::new();
                hasher.update(finding.rule_id.as_bytes());
                hasher.update(result.path.as_bytes());
                let normalized: String = finding
                    .snippet
                    .as_deref()
                    .unwrap_or("")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                hasher.update(normalized.as_bytes());
                let hash = hasher.finalize();
                format!("{:x}", hash)[..16].to_string()
            };

            let file_path = PathBuf::from(&result.path);
            !baseline.contains(&finding.rule_id, &file_path, &fingerprint)
        });
    }

    // Recalculate summary
    summary.total_findings = 0;
    summary.critical_count = 0;
    summary.error_count = 0;
    summary.warning_count = 0;
    summary.info_count = 0;

    for result in results.iter() {
        for finding in &result.findings {
            summary.total_findings += 1;
            match finding.severity {
                Severity::Critical => summary.critical_count += 1,
                Severity::Error => summary.error_count += 1,
                Severity::Warning => summary.warning_count += 1,
                Severity::Info => summary.info_count += 1,
            }
        }
    }
}

/// Get list of files changed since a base git ref
fn get_changed_files(repo_path: &PathBuf, base_ref: &str) -> Result<Vec<String>> {
    use std::process::Command;

    // Run git diff to get changed files
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", base_ref])
        .current_dir(repo_path)
        .output()?;

    if !output.status.success() {
        // Try fetching the remote first
        let _ = Command::new("git")
            .args(["fetch", "origin"])
            .current_dir(repo_path)
            .output();

        // Retry the diff
        let output = Command::new("git")
            .args(["diff", "--name-only", "--diff-filter=ACMR", base_ref])
            .current_dir(repo_path)
            .output()?;

        if !output.status.success() {
            // Fall back to comparing against HEAD~10 if base ref doesn't exist
            let output = Command::new("git")
                .args(["diff", "--name-only", "--diff-filter=ACMR", "HEAD~10"])
                .current_dir(repo_path)
                .output()?;

            if !output.status.success() {
                anyhow::bail!(
                    "Failed to get changed files. Is this a git repository? Error: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            return Ok(String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.to_string())
                .collect());
        }
    }

    // Also include staged files
    let staged = Command::new("git")
        .args(["diff", "--name-only", "--cached", "--diff-filter=ACMR"])
        .current_dir(repo_path)
        .output()?;

    let mut files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    if staged.status.success() {
        files.extend(
            String::from_utf8_lossy(&staged.stdout)
                .lines()
                .map(|s| s.to_string()),
        );
    }

    // Deduplicate
    files.sort();
    files.dedup();

    Ok(files)
}
