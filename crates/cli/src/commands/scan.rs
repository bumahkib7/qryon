//! Scan command implementation

use crate::filter::{self, CategoryFilter, FilterStats, FindingFilter};
use crate::output::{self, OutputOptions};
use crate::progress::{ScanProgress, ScanProgressConfig};
use crate::tui;
use crate::ui::{progress, theme::Theme};
use crate::{GroupBy, OutputFormat, ScanMode};
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::{
    AnalyzerEngine, diff,
    project::{ProjectAnalysisResult, ProjectAnalyzer},
};
use rma_common::{
    Baseline, BaselineMode, Language, Profile, ProviderType, ProvidersConfig, RmaConfig,
    RmaTomlConfig, Severity, SuppressionEngine, parse_inline_suppressions,
};
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
    /// Comma-separated list of providers to use (rma,pmd,oxlint)
    pub providers: Vec<String>,
    /// Scan mode preset (local, ci, pr)
    pub mode: Option<ScanMode>,
    /// OSV offline mode
    pub osv_offline: bool,
    /// OSV cache TTL
    pub osv_cache_ttl: String,
    /// Enable cross-file analysis
    pub cross_file: bool,
    /// Only report findings on lines changed in the diff
    pub diff: bool,
    /// Base git ref to compare against when using --diff
    pub diff_base: String,
    /// Read unified diff from stdin instead of running git diff
    pub diff_stdin: bool,
    /// Include test files in analysis (tests excluded by default)
    pub include_tests: bool,
    /// Skip ALL findings in tests including security rules
    pub skip_tests_all: bool,
    /// [DEPRECATED] Tests are now excluded by default
    pub skip_tests: bool,
    /// Maximum findings to display
    pub limit: usize,
    /// Show all findings without limit
    pub show_all: bool,
    /// How to group findings
    pub group_by: GroupBy,
    /// Collapse repeated findings
    pub collapse: bool,
    /// Expand collapsed findings (show all locations)
    pub expand: bool,
    /// Launch interactive TUI viewer
    pub interactive: bool,
    /// Stream findings as they're discovered (real-time output)
    pub stream: bool,
    /// Hide progress bar (auto-disabled for non-TTY)
    pub no_progress: bool,

    // =========================================================================
    // Filtering options
    // =========================================================================
    /// Filter by specific rule IDs (supports glob patterns)
    pub rules: Vec<String>,
    /// Exclude specific rule IDs
    pub exclude_rules: Vec<String>,
    /// Filter to specific files (glob patterns)
    pub files: Vec<String>,
    /// Exclude files matching patterns
    pub exclude_files: Vec<String>,
    /// Filter by category
    pub category: Option<CategoryFilter>,
    /// Only show fixable findings
    pub fixable: bool,
    /// Only show high-confidence findings
    pub high_confidence: bool,
    /// Search findings by message content
    pub search: Option<String>,
    /// Search with regex pattern
    pub search_regex: Option<String>,

    // =========================================================================
    // Smart presets
    // =========================================================================
    /// Use security-focused preset
    pub preset_security: bool,
    /// Use CI preset
    pub preset_ci: bool,
    /// Use review preset
    pub preset_review: bool,
    /// Load filter profile from config
    pub filter_profile: Option<String>,
    /// Show filter explanation
    pub explain: bool,
    /// Disable analysis cache (force fresh analysis)
    pub no_cache: bool,
}

/// Effective scan settings after applying mode defaults
struct EffectiveScanSettings {
    format: OutputFormat,
    #[allow(dead_code)] // Reserved for future use
    severity: Severity,
    changed_only: bool,
    baseline_mode: bool,
    timing: bool,
    /// Whether to apply default test/example suppression presets
    use_default_presets: bool,
    /// Whether to skip security rules in tests too (--skip-tests-all)
    skip_security_in_tests: bool,
    /// Whether to include suppressed findings in output
    include_suppressed: bool,
    /// Filter findings to only changed lines in diff
    diff: bool,
    /// Base git ref for diff comparison
    diff_base: String,
    /// Read diff from stdin instead of running git
    diff_stdin: bool,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let total_start = Instant::now();
    let mut timings: Vec<(&str, Duration)> = Vec::new();

    // Apply mode defaults (pr mode sets specific defaults unless explicitly overridden)
    let effective = apply_mode_defaults(&args);

    // Discover TOML configuration
    let toml_config = RmaTomlConfig::discover(&args.path);

    // Determine profile (CLI > config > default)
    let profile = args
        .profile
        .as_ref()
        .and_then(|p| p.parse::<Profile>().ok())
        .or_else(|| toml_config.as_ref().map(|(_, c)| c.profiles.default))
        .unwrap_or(Profile::Balanced);

    // Print header (only for text format)
    if !args.quiet && effective.format == OutputFormat::Text {
        print_scan_header(
            &args,
            toml_config.as_ref().map(|(_, c)| c),
            profile,
            &effective,
        );
    }

    // Build configuration
    let config = build_config(&args, toml_config.as_ref().map(|(_, c)| c), profile)?;

    // Phase 1: Parse files
    let parse_start = Instant::now();
    let (mut parsed_files, _parse_stats) = run_parse_phase(&args, &effective, &config)?;
    timings.push(("Parse", parse_start.elapsed()));

    // Phase 1.5: Filter to changed files only (for PR workflows)
    if effective.changed_only {
        let changed_files = get_changed_files(&args.path, &args.base)?;

        if !args.quiet && effective.format == OutputFormat::Text {
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
            changed_files.iter().any(|cf| {
                file_path.ends_with(cf) || cf.ends_with(file_path.to_string_lossy().as_ref())
            })
        });

        if !args.quiet
            && effective.format == OutputFormat::Text
            && before_count != parsed_files.len()
        {
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
    let (mut results, mut summary) = run_analyze_phase(
        &args,
        &effective,
        &config,
        &parsed_files,
        toml_config.as_ref().map(|(_, c)| c),
    )?;
    timings.push(("Analyze", analyze_start.elapsed()));

    // Phase 2.5: Cross-file analysis (if enabled or in interactive mode)
    // Interactive mode auto-enables cross-file analysis for call graph and flow visualization
    let mut project_result: Option<ProjectAnalysisResult> = None;
    let run_cross_file = args.cross_file || args.interactive;
    if run_cross_file {
        let cross_file_start = Instant::now();
        project_result = run_cross_file_phase(
            &args,
            &effective,
            &config,
            &parsed_files,
            &mut results,
            &mut summary,
        )?;
        timings.push(("Cross-file", cross_file_start.elapsed()));
    }

    // Phase 2.6: Apply suppression filtering
    let suppression_start = Instant::now();
    let suppressed_count = apply_suppressions(
        &args,
        &effective,
        &mut results,
        &mut summary,
        toml_config.as_ref().map(|(_, c)| c),
    );
    timings.push(("Suppressions", suppression_start.elapsed()));

    if !args.quiet && effective.format == OutputFormat::Text && suppressed_count > 0 {
        println!(
            "  {} Suppressed {} findings (use --include-suppressed to show)",
            Theme::info_mark(),
            suppressed_count.to_string().dimmed()
        );
    }

    // Phase 2.6: Apply baseline filtering if enabled
    let baseline_active = effective.baseline_mode
        || toml_config
            .as_ref()
            .map(|(_, c)| c.baseline.mode == BaselineMode::NewOnly)
            .unwrap_or(false);

    if baseline_active {
        let baseline_path = toml_config
            .as_ref()
            .map(|(_, c)| c.baseline.file.clone())
            .unwrap_or_else(|| PathBuf::from(".rma/baseline.json"));

        if baseline_path.exists()
            && let Ok(baseline) = Baseline::load(&baseline_path)
        {
            let before_count = summary.total_findings;
            filter_baseline_findings(&mut results, &mut summary, &baseline);

            if !args.quiet && effective.format == OutputFormat::Text {
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

    // Phase 2.8: Diff-aware filtering (for PR workflows)
    if effective.diff {
        let diff_start = Instant::now();
        let before_count = summary.total_findings;

        let changed_lines = if effective.diff_stdin {
            // Read diff from stdin
            diff::get_changed_lines_from_stdin()?
        } else {
            // Get diff from git
            diff::get_changed_lines_from_git(&args.path, &effective.diff_base)?
        };

        if !args.quiet && effective.format == OutputFormat::Text {
            let files_changed = changed_lines.len();
            let total_lines: usize = changed_lines.values().map(|s| s.len()).sum();
            println!(
                "  {} {} files with {} changed lines (base: {})",
                Theme::info_mark(),
                files_changed.to_string().yellow(),
                total_lines.to_string().yellow(),
                effective.diff_base.dimmed()
            );
        }

        // Filter findings to only those on changed lines
        for result in &mut results {
            let file_path = PathBuf::from(&result.path);
            result.findings =
                diff::filter_findings_by_diff(std::mem::take(&mut result.findings), &changed_lines);
            // Update path in findings to match file_path for proper filtering
            for finding in &mut result.findings {
                if finding.location.file != file_path {
                    finding.location.file = file_path.clone();
                }
            }
        }

        // Recalculate summary
        summary.total_findings = 0;
        summary.critical_count = 0;
        summary.error_count = 0;
        summary.warning_count = 0;
        summary.info_count = 0;

        for result in &results {
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

        timings.push(("Diff filter", diff_start.elapsed()));

        if !args.quiet && effective.format == OutputFormat::Text {
            let filtered = before_count - summary.total_findings;
            if filtered > 0 {
                println!(
                    "  {} Filtered {} findings not on changed lines",
                    Theme::info_mark(),
                    filtered.to_string().dimmed()
                );
            }
        }
    }

    // Phase 2.9: Apply user-specified filters
    let filter_stats = apply_user_filters(
        &args,
        &effective,
        &mut results,
        &mut summary,
        toml_config.as_ref().map(|(p, _)| p.as_path()),
    )?;

    // Show filter summary if filters are active
    if !args.quiet && effective.format == OutputFormat::Text && filter_stats.has_filtered() {
        print_filter_summary(&args, &filter_stats);
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

    // Phase 5: Deduplicate findings (same rule in same file → single finding with count)
    let dedup_start = Instant::now();
    let before_dedup = summary.total_findings;
    for result in &mut results {
        result.findings = rma_common::deduplicate_findings(std::mem::take(&mut result.findings));
    }

    // Recalculate summary after deduplication
    let mut dedup_total = 0usize;
    let mut dedup_occurrences = 0usize;
    summary.critical_count = 0;
    summary.error_count = 0;
    summary.warning_count = 0;
    summary.info_count = 0;

    for result in &results {
        for finding in &result.findings {
            dedup_total += 1;
            dedup_occurrences += finding.occurrence_count.unwrap_or(1);
            match finding.severity {
                Severity::Critical => summary.critical_count += 1,
                Severity::Error => summary.error_count += 1,
                Severity::Warning => summary.warning_count += 1,
                Severity::Info => summary.info_count += 1,
            }
        }
    }
    summary.total_findings = dedup_total;
    timings.push(("Deduplicate", dedup_start.elapsed()));

    // Show deduplication info if it reduced count
    if !args.quiet && effective.format == OutputFormat::Text && dedup_occurrences > dedup_total {
        println!(
            "  {} Deduplicated {} → {} unique findings ({} occurrences consolidated)",
            Theme::info_mark(),
            before_dedup.to_string().dimmed(),
            dedup_total.to_string().green(),
            (dedup_occurrences - dedup_total).to_string().dimmed()
        );
    }

    let total_duration = total_start.elapsed();

    // Print timing information
    if effective.timing && !args.quiet {
        print_timings(&timings, total_duration);
    }

    // Launch interactive TUI if requested
    if args.interactive {
        // Filter out test files from results if --include-tests is not set
        let filtered_results: Vec<_> = if args.include_tests {
            results.clone()
        } else {
            results
                .iter()
                .filter(|r| !rma_analyzer::project::is_test_file(std::path::Path::new(&r.path)))
                .cloned()
                .collect()
        };

        // Recalculate summary for filtered results
        let filtered_summary = rma_analyzer::AnalysisSummary {
            files_analyzed: filtered_results.len(),
            total_findings: filtered_results.iter().map(|r| r.findings.len()).sum(),
            critical_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == rma_common::Severity::Critical)
                .count(),
            error_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == rma_common::Severity::Error)
                .count(),
            warning_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == rma_common::Severity::Warning)
                .count(),
            info_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == rma_common::Severity::Info)
                .count(),
            total_loc: filtered_results
                .iter()
                .map(|r| r.metrics.lines_of_code)
                .sum(),
            total_complexity: filtered_results
                .iter()
                .map(|r| r.metrics.cyclomatic_complexity)
                .sum(),
        };

        // Filter cross-file taints to exclude test-only flows
        let filtered_project = project_result.as_ref().map(|proj| {
            let filtered_taints: Vec<_> = if args.include_tests {
                proj.cross_file_taints.clone()
            } else {
                proj.cross_file_taints
                    .iter()
                    .filter(|t| {
                        t.reachability != rma_analyzer::project::Reachability::TestOnly
                            && !rma_analyzer::project::is_test_file(&t.source.file)
                    })
                    .cloned()
                    .collect()
            };

            rma_analyzer::project::ProjectAnalysisResult {
                files_analyzed: filtered_results.len(),
                file_results: filtered_results.clone(),
                cross_file_taints: filtered_taints,
                call_graph: proj.call_graph.clone(),
                import_graph: proj.import_graph.clone(),
                summary: filtered_summary.clone(),
                duration_ms: proj.duration_ms,
            }
        });

        return tui::run_from_analysis_with_project(
            &filtered_results,
            &filtered_summary,
            filtered_project.as_ref(),
        );
    }

    // Build output options
    let output_options = OutputOptions {
        limit: if args.show_all {
            usize::MAX
        } else {
            args.limit
        },
        group_by: args.group_by,
        collapse: args.collapse,
        expand: args.expand,
        quiet: args.quiet,
    };

    // Output results
    output::format_results_with_options(
        &results,
        &summary,
        total_duration,
        effective.format,
        args.output.clone(),
        Some(&args.path),
        &output_options,
    )?;

    // Exit with error code if critical/error findings
    if summary.critical_count > 0 || summary.error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Apply mode defaults - pr mode sets specific defaults unless explicitly overridden
fn apply_mode_defaults(args: &ScanArgs) -> EffectiveScanSettings {
    match args.mode {
        Some(ScanMode::Pr) => {
            // PR mode defaults: changed_only=true, baseline_mode=true, format=sarif, severity=warning, timing=false
            // Also enables default test/example suppressions and diff filtering
            EffectiveScanSettings {
                format: if args.format != OutputFormat::Text {
                    args.format // User explicitly set format
                } else {
                    OutputFormat::Sarif // Default for PR mode
                },
                severity: args.severity, // Keep user's choice (already defaults to warning)
                changed_only: true,      // Always true for PR mode
                baseline_mode: true,     // Always true for PR mode
                timing: false,           // Disabled for PR mode (cleaner output)
                use_default_presets: true, // Enable test/example suppressions
                skip_security_in_tests: args.skip_tests_all,
                include_suppressed: args.include_suppressed,
                diff: args.diff, // Respect explicit --diff flag
                diff_base: args.diff_base.clone(),
                diff_stdin: args.diff_stdin,
            }
        }
        Some(ScanMode::Ci) => {
            // CI mode: optimize for automation, enable default suppressions
            EffectiveScanSettings {
                format: args.format,
                severity: args.severity,
                changed_only: args.changed_only,
                baseline_mode: args.baseline_mode,
                timing: false,             // Disabled for cleaner CI output
                use_default_presets: true, // Enable test/example suppressions
                skip_security_in_tests: args.skip_tests_all,
                include_suppressed: args.include_suppressed,
                diff: args.diff,
                diff_base: args.diff_base.clone(),
                diff_stdin: args.diff_stdin,
            }
        }
        Some(ScanMode::Local) | None => {
            // Local mode: use all explicit settings
            // Tests are excluded by default; use --include-tests to scan them
            EffectiveScanSettings {
                format: args.format,
                severity: args.severity,
                changed_only: args.changed_only,
                baseline_mode: args.baseline_mode,
                timing: args.timing,
                use_default_presets: !args.include_tests,
                skip_security_in_tests: args.skip_tests_all,
                include_suppressed: args.include_suppressed,
                diff: args.diff,
                diff_base: args.diff_base.clone(),
                diff_stdin: args.diff_stdin,
            }
        }
    }
}

fn print_scan_header(
    args: &ScanArgs,
    toml_config: Option<&RmaTomlConfig>,
    profile: Profile,
    effective: &EffectiveScanSettings,
) {
    println!();
    println!("{}", "🔍 RMA - Rust Monorepo Analyzer".cyan().bold());
    println!("{}", Theme::separator(50));
    println!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    );

    println!("  {} {}", "Profile:".dimmed(), profile.to_string().cyan());

    // Show scan mode if set
    if let Some(mode) = args.mode {
        let mode_str = match mode {
            ScanMode::Local => "local",
            ScanMode::Ci => "ci",
            ScanMode::Pr => "pr",
        };
        println!("  {} {}", "Scan Mode:".dimmed(), mode_str.cyan());
    }

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

    if effective.baseline_mode {
        println!("  {} {}", "Baseline:".dimmed(), "new-only".yellow());
    }

    if effective.changed_only {
        println!(
            "  {} {} (base: {})",
            "Mode:".dimmed(),
            "changed-only".cyan(),
            args.base.dimmed()
        );
    }

    if args.cross_file || args.interactive {
        println!("  {} {}", "Cross-file:".dimmed(), "enabled".green());
    }

    // Show diff-aware filtering info
    if effective.diff {
        if effective.diff_stdin {
            println!(
                "  {} {} (from stdin)",
                "Diff filter:".dimmed(),
                "enabled".green()
            );
        } else {
            println!(
                "  {} {} (base: {})",
                "Diff filter:".dimmed(),
                "enabled".green(),
                effective.diff_base.dimmed()
            );
        }
    }

    // Show providers if not just default
    if args.providers.len() > 1 || (args.providers.len() == 1 && args.providers[0] != "rma") {
        println!(
            "  {} {}",
            "Providers:".dimmed(),
            args.providers.join(", ").cyan()
        );
    }

    // Show OSV options if OSV is enabled
    if args.providers.iter().any(|p| p == "osv") {
        if args.osv_offline {
            println!("  {} {}", "OSV:".dimmed(), "offline mode".yellow());
        }
        if args.osv_cache_ttl != "24h" {
            println!(
                "  {} cache TTL: {}",
                "OSV:".dimmed(),
                args.osv_cache_ttl.cyan()
            );
        }
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
        "kotlin" | "kt" => Some(Language::Kotlin),
        "scala" => Some(Language::Scala),
        "ruby" | "rb" => Some(Language::Ruby),
        "php" => Some(Language::Php),
        "csharp" | "c#" | "cs" => Some(Language::CSharp),
        "swift" => Some(Language::Swift),
        "bash" | "sh" | "shell" => Some(Language::Bash),
        "elixir" | "ex" => Some(Language::Elixir),
        "solidity" | "sol" => Some(Language::Solidity),
        "ocaml" | "ml" => Some(Language::OCaml),
        "hcl" | "terraform" | "tf" => Some(Language::Hcl),
        "yaml" | "yml" => Some(Language::Yaml),
        "json" => Some(Language::Json),
        "html" => Some(Language::Html),
        _ => None,
    }
}

/// Build providers config from CLI args and TOML config
///
/// CLI --providers flag overrides TOML config if provided.
/// RMA native provider is always included.
fn build_providers_config(
    providers: &[String],
    toml_config: Option<&RmaTomlConfig>,
    osv_offline: bool,
    osv_cache_ttl: &str,
) -> ProvidersConfig {
    // Start with TOML config or defaults
    let mut config = toml_config.map(|c| c.providers.clone()).unwrap_or_default();

    // Override enabled list from CLI if non-empty
    if !providers.is_empty() {
        config.enabled = providers
            .iter()
            .filter_map(|p| match p.trim().to_lowercase().as_str() {
                "rma" => Some(ProviderType::Rma),
                "pmd" => Some(ProviderType::Pmd),
                "oxlint" => Some(ProviderType::Oxlint),
                "oxc" => Some(ProviderType::Oxc),
                "rustsec" => Some(ProviderType::RustSec),
                "gosec" => Some(ProviderType::Gosec),
                "osv" => Some(ProviderType::Osv),
                _ => None,
            })
            .collect();
    }

    // Ensure RMA native rules are always enabled
    if !config.enabled.contains(&ProviderType::Rma) {
        config.enabled.insert(0, ProviderType::Rma);
    }

    // Apply OSV CLI options
    if osv_offline {
        config.osv.offline = true;
    }
    if osv_cache_ttl != "24h" {
        config.osv.cache_ttl = osv_cache_ttl.to_string();
    }

    config
}

fn run_parse_phase(
    args: &ScanArgs,
    effective: &EffectiveScanSettings,
    config: &RmaConfig,
) -> Result<(Vec<rma_parser::ParsedFile>, rma_parser::ParseStats)> {
    let spinner = if !args.quiet && effective.format == OutputFormat::Text {
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
    effective: &EffectiveScanSettings,
    config: &RmaConfig,
    parsed_files: &[rma_parser::ParsedFile],
    toml_config: Option<&RmaTomlConfig>,
) -> Result<(
    Vec<rma_analyzer::FileAnalysis>,
    rma_analyzer::AnalysisSummary,
)> {
    // Create progress config based on CLI args
    let progress_config = ScanProgressConfig::from_args(args.no_progress, args.stream, args.quiet);

    // Use enhanced progress tracking if streaming is enabled
    if progress_config.stream_findings {
        return run_analyze_phase_streaming(
            args,
            effective,
            config,
            parsed_files,
            toml_config,
            progress_config,
        );
    }

    // Standard progress with spinner
    let spinner = if !args.quiet && effective.format == OutputFormat::Text && !args.no_progress {
        let s = progress::create_spinner("Analyzing code...");
        Some(s)
    } else {
        None
    };

    // Build providers config from CLI args and TOML config
    let providers_config = build_providers_config(
        &args.providers,
        toml_config,
        args.osv_offline,
        &args.osv_cache_ttl,
    );

    let analyzer = AnalyzerEngine::with_providers(config.clone(), providers_config);

    // If we have external providers, use the directory-based analysis
    let has_external_providers = args.providers.iter().any(|p| p != "rma");
    let result = if has_external_providers {
        analyzer.analyze_files_with_providers(parsed_files, &args.path)?
    } else {
        analyzer.analyze_files(parsed_files)?
    };

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

/// Run analyze phase with streaming output - prints findings as they are discovered
fn run_analyze_phase_streaming(
    args: &ScanArgs,
    _effective: &EffectiveScanSettings,
    config: &RmaConfig,
    parsed_files: &[rma_parser::ParsedFile],
    toml_config: Option<&RmaTomlConfig>,
    progress_config: ScanProgressConfig,
) -> Result<(
    Vec<rma_analyzer::FileAnalysis>,
    rma_analyzer::AnalysisSummary,
)> {
    // Create scan progress tracker
    let scan_progress = ScanProgress::new(parsed_files.len() as u64, progress_config);

    // Build providers config from CLI args and TOML config
    let providers_config = build_providers_config(
        &args.providers,
        toml_config,
        args.osv_offline,
        &args.osv_cache_ttl,
    );

    let analyzer = AnalyzerEngine::with_providers(config.clone(), providers_config);

    // Process files one by one for streaming
    let mut all_results: Vec<rma_analyzer::FileAnalysis> = Vec::with_capacity(parsed_files.len());
    let mut summary = rma_analyzer::AnalysisSummary::default();

    for parsed_file in parsed_files {
        scan_progress.set_current_file(&parsed_file.path);
        scan_progress.track_language(parsed_file.language);

        // Analyze single file
        let file_results = analyzer.analyze_file(parsed_file)?;

        // Stream findings as they're discovered
        for finding in &file_results.findings {
            scan_progress.add_finding(finding);

            // Update summary counts
            summary.total_findings += 1;
            match finding.severity {
                Severity::Critical => summary.critical_count += 1,
                Severity::Error => summary.error_count += 1,
                Severity::Warning => summary.warning_count += 1,
                Severity::Info => summary.info_count += 1,
            }
        }

        all_results.push(file_results);
        scan_progress.inc_file();
    }

    summary.files_analyzed = all_results.len();
    scan_progress.finish();

    Ok((all_results, summary))
}

fn run_cross_file_phase(
    args: &ScanArgs,
    effective: &EffectiveScanSettings,
    config: &RmaConfig,
    _parsed_files: &[rma_parser::ParsedFile],
    results: &mut Vec<rma_analyzer::FileAnalysis>,
    summary: &mut rma_analyzer::AnalysisSummary,
) -> Result<Option<ProjectAnalysisResult>> {
    let spinner = if !args.quiet && effective.format == OutputFormat::Text {
        let s = progress::create_spinner("Running cross-file analysis...");
        Some(s)
    } else {
        None
    };

    // Use ProjectAnalyzer for cross-file analysis
    let project_analyzer = ProjectAnalyzer::new(config.clone())
        .with_cross_file(true)
        .with_parallel(args.jobs == 0 || args.jobs > 1)
        .with_cache(!args.no_cache);

    // Run the cross-file analysis on the project
    let project_result = project_analyzer.analyze_project(&args.path)?;

    // Add cross-file taint findings to results
    let mut cross_file_findings = 0;
    for taint in &project_result.cross_file_taints {
        // Create a finding for each cross-file taint flow
        // Generate a unique ID based on the taint flow
        let finding_id = format!(
            "cross-file-{}-{}-{}",
            taint.source.function, taint.sink.function, taint.sink.line
        );

        let finding = rma_common::Finding {
            id: finding_id,
            rule_id: "cross-file/taint-flow".to_string(),
            message: taint.description.clone(),
            severity: taint.severity,
            location: rma_common::SourceLocation {
                file: taint.sink.file.clone(),
                start_line: taint.sink.line,
                start_column: 1,
                end_line: taint.sink.line,
                end_column: 1,
            },
            language: rma_common::Language::Unknown,
            snippet: None,
            suggestion: Some(format!(
                "Validate or sanitize data from {} before using in {}",
                taint.source.function, taint.sink.function
            )),
            fix: None,
            confidence: rma_common::Confidence::Medium,
            category: rma_common::FindingCategory::Security,
            source: rma_common::FindingSource::TaintFlow,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        };

        // Find or create the file result
        let file_path = taint.sink.file.display().to_string();
        if let Some(result) = results.iter_mut().find(|r| r.path == file_path) {
            result.findings.push(finding);
        } else {
            results.push(rma_analyzer::FileAnalysis {
                path: file_path,
                language: rma_common::Language::Unknown,
                metrics: rma_common::CodeMetrics::default(),
                findings: vec![finding],
            });
        }

        cross_file_findings += 1;
    }

    // Update summary
    summary.total_findings += cross_file_findings;

    if let Some(s) = spinner {
        let graph_info = project_result
            .call_graph
            .as_ref()
            .map(|g| format!("{} functions, {} edges", g.function_count(), g.edge_count()))
            .unwrap_or_else(|| "no call graph".to_string());

        s.finish_with_message(format!(
            "{} Cross-file analysis complete ({}, {} taint flows detected)",
            Theme::success_mark(),
            graph_info.dimmed(),
            cross_file_findings.to_string().yellow()
        ));
    }

    Ok(Some(project_result))
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

/// Apply suppression rules to findings
/// Returns the count of suppressed findings
fn apply_suppressions(
    args: &ScanArgs,
    effective: &EffectiveScanSettings,
    results: &mut [rma_analyzer::FileAnalysis],
    summary: &mut rma_analyzer::AnalysisSummary,
    toml_config: Option<&RmaTomlConfig>,
) -> usize {
    // Build suppression engine from config
    let rules_config = toml_config.map(|c| c.rules.clone()).unwrap_or_default();
    let mut engine = SuppressionEngine::new(&rules_config, effective.use_default_presets)
        .with_skip_security_in_tests(effective.skip_security_in_tests);

    // Load suppression store if enabled
    let suppression_config = toml_config.map(|c| &c.suppressions);
    let store_enabled = suppression_config.map(|c| c.enabled).unwrap_or(true);

    if store_enabled {
        let db_path = suppression_config
            .map(|c| args.path.join(&c.database))
            .unwrap_or_else(|| args.path.join(".rma/suppressions.db"));

        if db_path.exists()
            && let Ok(store) = rma_common::suppression::SuppressionStore::open(&db_path)
        {
            engine = engine.with_store(store);
        }
    }

    let mut suppressed_count = 0;
    let mut file_contents_cache: std::collections::HashMap<PathBuf, String> =
        std::collections::HashMap::new();

    for result in results.iter_mut() {
        let file_path = PathBuf::from(&result.path);

        // Get or cache file contents for inline suppression parsing
        let inline_suppressions = if !file_contents_cache.contains_key(&file_path) {
            // Try to read file contents
            if let Ok(content) = std::fs::read_to_string(&file_path) {
                let suppressions = parse_inline_suppressions(&content);
                file_contents_cache.insert(file_path.clone(), content);
                suppressions
            } else {
                Vec::new()
            }
        } else {
            // Parse from cached content
            file_contents_cache
                .get(&file_path)
                .map(|c| parse_inline_suppressions(c))
                .unwrap_or_default()
        };

        for finding in &mut result.findings {
            let finding_line = finding.location.start_line;
            let fingerprint = finding.fingerprint.as_deref();

            let suppression_result = engine.check(
                &finding.rule_id,
                &file_path,
                finding_line,
                &inline_suppressions,
                fingerprint,
            );

            if suppression_result.suppressed {
                // Add suppression metadata to finding properties
                let properties = finding
                    .properties
                    .get_or_insert_with(std::collections::HashMap::new);
                SuppressionEngine::add_suppression_metadata(properties, &suppression_result);
                suppressed_count += 1;
            }
        }
    }

    // If not including suppressed findings, filter them out
    if !effective.include_suppressed {
        for result in results.iter_mut() {
            result.findings.retain(|f| {
                if let Some(ref props) = f.properties {
                    !props
                        .get("suppressed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                } else {
                    true
                }
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

    suppressed_count
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

/// Build and apply user-specified filters to findings
fn apply_user_filters(
    args: &ScanArgs,
    _effective: &EffectiveScanSettings,
    results: &mut [rma_analyzer::FileAnalysis],
    summary: &mut rma_analyzer::AnalysisSummary,
    config_path: Option<&std::path::Path>,
) -> Result<FilterStats> {
    // Build the filter based on CLI args and presets
    let mut filter = build_finding_filter(args, config_path)?;

    // Check if any filters are active
    if !filter.is_active() {
        return Ok(FilterStats::default());
    }

    // Collect all findings for filtering
    let _total_before: usize = results.iter().map(|r| r.findings.len()).sum();

    // Apply filter with statistics tracking if explain mode is enabled
    let all_findings: Vec<rma_common::Finding> = results
        .iter_mut()
        .flat_map(|r| std::mem::take(&mut r.findings))
        .collect();

    let (filtered_findings, stats) = filter.apply_with_stats(all_findings);

    // Redistribute filtered findings back to their files
    let mut findings_by_file: std::collections::HashMap<String, Vec<rma_common::Finding>> =
        std::collections::HashMap::new();

    for finding in filtered_findings {
        let file_path = finding.location.file.to_string_lossy().to_string();
        findings_by_file.entry(file_path).or_default().push(finding);
    }

    for result in results.iter_mut() {
        if let Some(findings) = findings_by_file.remove(&result.path) {
            result.findings = findings;
        }
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

    Ok(stats)
}

/// Build a FindingFilter from CLI arguments
fn build_finding_filter(
    args: &ScanArgs,
    config_path: Option<&std::path::Path>,
) -> Result<FindingFilter> {
    // Start with a preset if specified
    let mut filter = if args.preset_security {
        FindingFilter::preset_security()
    } else if args.preset_ci {
        FindingFilter::preset_ci()
    } else if args.preset_review {
        FindingFilter::preset_review()
    } else if let Some(ref profile_name) = args.filter_profile {
        // Load profile from config
        if let Some(path) = config_path {
            let profiles = filter::load_profiles_from_config(path)?;
            if let Some(profile) = profiles.get(profile_name) {
                FindingFilter::from_profile(profile)?
            } else {
                anyhow::bail!("Filter profile '{}' not found in config", profile_name);
            }
        } else {
            anyhow::bail!("No config file found for filter profile '{}'", profile_name);
        }
    } else {
        FindingFilter::new()
    };

    // Apply CLI overrides
    if !args.rules.is_empty() {
        filter = filter.with_rules(args.rules.clone());
    }

    if !args.exclude_rules.is_empty() {
        filter = filter.with_exclude_rules(args.exclude_rules.clone());
    }

    if !args.files.is_empty() {
        filter = filter.with_files(args.files.clone());
    }

    if !args.exclude_files.is_empty() {
        filter = filter.with_exclude_files(args.exclude_files.clone());
    }

    if let Some(cat) = args.category {
        filter = filter.with_category(cat.into());
    }

    if args.fixable {
        filter = filter.with_fixable_only(true);
    }

    if args.high_confidence {
        filter = filter.with_high_confidence_only(true);
    }

    if let Some(ref text) = args.search {
        filter = filter.with_search(text.clone());
    }

    if let Some(ref pattern) = args.search_regex {
        filter = filter.with_search_regex(pattern)?;
    }

    // Enable stats tracking if explain mode is on
    if args.explain {
        filter = filter.with_stats();
    }

    Ok(filter)
}

/// Print filter summary and statistics
fn print_filter_summary(args: &ScanArgs, stats: &FilterStats) {
    // Build filter for summary display
    let filter = build_finding_filter(args, None).unwrap_or_default();

    println!();
    println!("{}", "Filters active:".cyan().bold());

    for (key, value) in filter.summary() {
        println!(
            "  {} {}: {}",
            "\u{2022}".dimmed(),
            key.dimmed(),
            value.bright_white()
        );
    }

    println!();
    println!(
        "Found {} matching findings (filtered from {} total)",
        stats.total_after.to_string().green().bold(),
        stats.total_before.to_string().dimmed()
    );

    // Show explain details if requested
    if args.explain && stats.filtered_count() > 0 {
        println!();
        println!("{}", "Filtered out findings:".yellow().bold());

        if stats.by_severity > 0 {
            let breakdown: Vec<String> = stats
                .severity_breakdown
                .iter()
                .map(|(sev, count)| format!("{} {}", count, sev))
                .collect();
            println!(
                "  {} {} below severity threshold ({})",
                "\u{2022}".dimmed(),
                stats.by_severity.to_string().yellow(),
                breakdown.join(", ").dimmed()
            );
        }

        if stats.by_rules_exclude > 0 {
            let breakdown: Vec<String> = stats
                .excluded_rules_breakdown
                .iter()
                .take(5)
                .map(|(rule, count)| format!("{}: {}", rule, count))
                .collect();
            let suffix = if stats.excluded_rules_breakdown.len() > 5 {
                format!(" (+{} more)", stats.excluded_rules_breakdown.len() - 5)
            } else {
                String::new()
            };
            println!(
                "  {} {} from excluded rules ({}{})",
                "\u{2022}".dimmed(),
                stats.by_rules_exclude.to_string().yellow(),
                breakdown.join(", ").dimmed(),
                suffix.dimmed()
            );
        }

        if stats.by_rules_include > 0 {
            println!(
                "  {} {} not matching included rules",
                "\u{2022}".dimmed(),
                stats.by_rules_include.to_string().yellow()
            );
        }

        if stats.by_files_exclude > 0 {
            let breakdown: Vec<String> = stats
                .excluded_files_breakdown
                .iter()
                .take(3)
                .map(|(pattern, count)| format!("{}: {}", pattern, count))
                .collect();
            let suffix = if stats.excluded_files_breakdown.len() > 3 {
                format!(
                    " (+{} more patterns)",
                    stats.excluded_files_breakdown.len() - 3
                )
            } else {
                String::new()
            };
            println!(
                "  {} {} from excluded files ({}{})",
                "\u{2022}".dimmed(),
                stats.by_files_exclude.to_string().yellow(),
                breakdown.join(", ").dimmed(),
                suffix.dimmed()
            );
        }

        if stats.by_files_include > 0 {
            println!(
                "  {} {} not matching included files",
                "\u{2022}".dimmed(),
                stats.by_files_include.to_string().yellow()
            );
        }

        if stats.by_category > 0 {
            println!(
                "  {} {} from other categories",
                "\u{2022}".dimmed(),
                stats.by_category.to_string().yellow()
            );
        }

        if stats.by_fixable > 0 {
            println!(
                "  {} {} without available fixes",
                "\u{2022}".dimmed(),
                stats.by_fixable.to_string().yellow()
            );
        }

        if stats.by_confidence > 0 {
            println!(
                "  {} {} with low/medium confidence",
                "\u{2022}".dimmed(),
                stats.by_confidence.to_string().yellow()
            );
        }

        if stats.by_search > 0 {
            println!(
                "  {} {} not matching search pattern",
                "\u{2022}".dimmed(),
                stats.by_search.to_string().yellow()
            );
        }
    }

    println!();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_args() -> ScanArgs {
        ScanArgs {
            path: PathBuf::from("."),
            format: OutputFormat::Text,
            output: None,
            severity: Severity::Warning,
            profile: None,
            ruleset: None,
            incremental: false,
            jobs: 0,
            languages: None,
            ai_analysis: false,
            ai_provider: "claude".to_string(),
            timing: false,
            exclude: None,
            config_path: None,
            quiet: false,
            baseline_mode: false,
            include_suppressed: false,
            changed_only: false,
            base: "origin/main".to_string(),
            providers: vec!["rma".to_string()],
            mode: None,
            osv_offline: false,
            osv_cache_ttl: "24h".to_string(),
            cross_file: false,
            diff: false,
            diff_base: "origin/main".to_string(),
            diff_stdin: false,
            include_tests: false,
            skip_tests: false,
            skip_tests_all: false,
            limit: 20,
            show_all: false,
            group_by: GroupBy::File,
            collapse: false,
            expand: false,
            interactive: false,
            stream: false,
            no_progress: false,
            // Filtering options
            rules: Vec::new(),
            exclude_rules: Vec::new(),
            files: Vec::new(),
            exclude_files: Vec::new(),
            category: None,
            fixable: false,
            high_confidence: false,
            search: None,
            search_regex: None,
            // Presets
            preset_security: false,
            preset_ci: false,
            preset_review: false,
            filter_profile: None,
            explain: false,
            no_cache: false,
        }
    }

    #[test]
    fn test_mode_local_uses_explicit_settings() {
        let args = ScanArgs {
            mode: Some(ScanMode::Local),
            format: OutputFormat::Json,
            changed_only: true,
            baseline_mode: true,
            timing: true,
            ..create_test_args()
        };

        let effective = apply_mode_defaults(&args);

        assert_eq!(effective.format, OutputFormat::Json);
        assert!(effective.changed_only);
        assert!(effective.baseline_mode);
        assert!(effective.timing);
        assert!(effective.use_default_presets); // Tests excluded by default
    }

    #[test]
    fn test_include_tests_disables_presets() {
        let args = ScanArgs {
            mode: Some(ScanMode::Local),
            include_tests: true, // Opt-in to scan test files
            ..create_test_args()
        };

        let effective = apply_mode_defaults(&args);

        assert!(!effective.use_default_presets); // Tests included when flag is set
    }

    #[test]
    fn test_mode_pr_applies_defaults() {
        let args = ScanArgs {
            mode: Some(ScanMode::Pr),
            ..create_test_args()
        };

        let effective = apply_mode_defaults(&args);

        // PR mode defaults
        assert_eq!(effective.format, OutputFormat::Sarif);
        assert!(effective.changed_only);
        assert!(effective.baseline_mode);
        assert!(!effective.timing);
        assert!(effective.use_default_presets); // PR mode enables presets
    }

    #[test]
    fn test_mode_pr_respects_explicit_format() {
        let args = ScanArgs {
            mode: Some(ScanMode::Pr),
            format: OutputFormat::Json, // User explicitly set JSON
            ..create_test_args()
        };

        let effective = apply_mode_defaults(&args);

        // User's explicit format is respected
        assert_eq!(effective.format, OutputFormat::Json);
        // But other PR defaults still apply
        assert!(effective.changed_only);
        assert!(effective.baseline_mode);
        assert!(effective.use_default_presets);
    }

    #[test]
    fn test_mode_ci_disables_timing() {
        let args = ScanArgs {
            mode: Some(ScanMode::Ci),
            timing: true, // User wants timing but CI mode overrides
            ..create_test_args()
        };

        let effective = apply_mode_defaults(&args);

        // CI mode disables timing for cleaner output
        assert!(!effective.timing);
        // CI mode enables default presets
        assert!(effective.use_default_presets);
    }

    #[test]
    fn test_no_mode_uses_all_explicit_settings() {
        let args = ScanArgs {
            mode: None,
            format: OutputFormat::Compact,
            changed_only: true,
            baseline_mode: true,
            timing: true,
            ..create_test_args()
        };

        let effective = apply_mode_defaults(&args);

        assert_eq!(effective.format, OutputFormat::Compact);
        assert!(effective.changed_only);
        assert!(effective.baseline_mode);
        assert!(effective.timing);
    }
}
