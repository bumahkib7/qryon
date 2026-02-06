//! Cross-file taint flow visualization command
//!
//! This command provides enhanced visualization and analysis of cross-file
//! data flows, showing source-to-sink paths with evidence and confidence scores.

use crate::OutputFormat;
use crate::tui;
use crate::ui::{progress, theme::Theme};
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::callgraph::{CallGraph, SinkClassification, SinkEvidenceKind, TaintFlow};
use rma_analyzer::flow::{
    ArgSinkVerdict, analyze_rust_command, evaluate_command_sink, fix_recommendation,
};
use rma_analyzer::knowledge::SinkContext;
use rma_analyzer::project::{CrossFileTaint, ProjectAnalyzer};
use rma_common::{RmaConfig, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Arguments for the flows command
pub struct FlowsArgs {
    /// Path to analyze
    pub path: PathBuf,
    /// Output format
    pub format: OutputFormat,
    /// Output file
    pub output: Option<PathBuf>,
    /// Sort flows by: severity, confidence, sink-type, source-type, file
    pub sort_by: FlowSortBy,
    /// Reverse sort order
    pub reverse: bool,
    /// Group flows by: sink-type, source-type, file, none
    pub group_by: FlowGroupBy,
    /// Minimum confidence threshold (0.0 - 1.0)
    pub min_confidence: f32,
    /// Filter by sink type (sql, command, path, xss, etc.)
    pub sink_type: Option<String>,
    /// Filter by source type (http, file, env, etc.)
    pub source_type: Option<String>,
    /// Show detailed evidence (full paths)
    pub evidence: bool,
    /// Show only flows crossing specific file
    pub through_file: Option<PathBuf>,
    /// Maximum flows to display
    pub limit: usize,
    /// Show all flows without limit
    pub all: bool,
    /// Quiet mode
    pub quiet: bool,
    /// Deduplicate flows (group by source+sink)
    pub dedupe: bool,
    /// Show statistics summary
    pub stats: bool,
    /// Include test files (by default, test sources are excluded)
    pub include_tests: bool,
    /// Disable analysis cache (force fresh analysis)
    pub no_cache: bool,
    /// Launch interactive TUI viewer
    pub interactive: bool,
}

/// How to sort flows
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FlowSortBy {
    /// Sort by severity (critical first)
    #[default]
    Severity,
    /// Sort by confidence score (highest first)
    Confidence,
    /// Sort by sink vulnerability type
    SinkType,
    /// Sort by source type
    SourceType,
    /// Sort by file path
    File,
    /// Sort by flow path length (shortest first)
    PathLength,
}

/// How to group flows
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FlowGroupBy {
    /// Group by sink vulnerability type
    #[default]
    SinkType,
    /// Group by source type
    SourceType,
    /// Group by sink file
    File,
    /// No grouping
    None,
}

impl std::str::FromStr for FlowSortBy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "severity" | "sev" => Ok(FlowSortBy::Severity),
            "confidence" | "conf" => Ok(FlowSortBy::Confidence),
            "sink" | "sink-type" => Ok(FlowSortBy::SinkType),
            "source" | "source-type" => Ok(FlowSortBy::SourceType),
            "file" | "path" => Ok(FlowSortBy::File),
            "length" | "path-length" => Ok(FlowSortBy::PathLength),
            _ => Err(format!("Unknown sort type: {}", s)),
        }
    }
}

impl std::str::FromStr for FlowGroupBy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sink" | "sink-type" => Ok(FlowGroupBy::SinkType),
            "source" | "source-type" => Ok(FlowGroupBy::SourceType),
            "file" | "path" => Ok(FlowGroupBy::File),
            "none" | "flat" => Ok(FlowGroupBy::None),
            _ => Err(format!("Unknown group type: {}", s)),
        }
    }
}

/// Run the flows command
pub fn run(args: FlowsArgs) -> Result<()> {
    let start = Instant::now();

    // Print header
    if !args.quiet && args.format == OutputFormat::Text {
        print_header(&args);
    }

    // Run cross-file analysis
    let spinner = if !args.quiet && args.format == OutputFormat::Text {
        Some(progress::create_spinner(
            "Analyzing cross-file data flows...",
        ))
    } else {
        None
    };

    let config = RmaConfig::default();
    let project_analyzer = ProjectAnalyzer::new(config)
        .with_cross_file(true)
        .with_parallel(true)
        .with_cache(!args.no_cache);

    let result = project_analyzer.analyze_project(&args.path)?;

    if let Some(s) = spinner {
        s.finish_with_message(format!("{} Analysis complete", Theme::success_mark()));
    }

    // Get flows from call graph
    let all_flows: Vec<TaintFlow> = if let Some(ref call_graph) = result.call_graph {
        call_graph.find_taint_flows()
    } else {
        Vec::new()
    };

    // Filter out test-only sources from TaintFlow list
    let flows: Vec<TaintFlow> = if args.include_tests {
        all_flows
    } else {
        all_flows
            .into_iter()
            .filter(|f| !rma_analyzer::project::is_test_file(&f.source.file))
            .collect()
    };

    // Also include CrossFileTaint results, filtering out test-only sources by default
    let cross_file_taints: Vec<_> = if args.include_tests {
        result.cross_file_taints.clone()
    } else {
        result
            .cross_file_taints
            .iter()
            .filter(|t| {
                // Check both the reachability field AND the source file path
                if t.reachability == rma_analyzer::project::Reachability::TestOnly {
                    return false;
                }
                // Additional CLI-level test file detection
                !rma_analyzer::project::is_test_file(&t.source.file)
            })
            .cloned()
            .collect()
    };

    // Report test exclusions (from both flow sources)
    let excluded_taint_flows = if let Some(ref cg) = result.call_graph {
        cg.find_taint_flows().len() - flows.len()
    } else {
        0
    };
    let excluded_cross_file = result.cross_file_taints.len() - cross_file_taints.len();
    let total_excluded = excluded_taint_flows + excluded_cross_file;
    if total_excluded > 0 && !args.quiet {
        eprintln!(
            "[rma] Excluded {} test-only flows (use --include-tests to show)",
            total_excluded
        );
    }

    // Filter out safe-by-construction command sinks (same validation as project-level analysis)
    let flows = filter_safe_command_sinks(flows, &result.file_results);

    // Apply filters
    let mut filtered_flows = filter_flows(&flows, &args);

    // Apply deduplication if requested
    if args.dedupe {
        filtered_flows = dedupe_flows(filtered_flows);
    }

    // Sort flows
    sort_flows(&mut filtered_flows, args.sort_by, args.reverse);

    // Apply limit
    let limit = if args.all { usize::MAX } else { args.limit };
    let total_flows = filtered_flows.len();
    let displayed_flows: Vec<_> = filtered_flows.into_iter().take(limit).collect();

    // Launch interactive TUI if requested
    if args.interactive {
        // Filter out test files from results if --include-tests is not set
        let filtered_results: Vec<_> = if args.include_tests {
            result.file_results.clone()
        } else {
            result
                .file_results
                .iter()
                .filter(|r| !rma_analyzer::project::is_test_file(std::path::Path::new(&r.path)))
                .cloned()
                .collect()
        };

        // Create summary for filtered results
        let summary = rma_analyzer::AnalysisSummary {
            files_analyzed: filtered_results.len(),
            total_findings: filtered_results.iter().map(|r| r.findings.len()).sum(),
            critical_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            error_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Error)
                .count(),
            warning_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Warning)
                .count(),
            info_count: filtered_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Info)
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

        // Create filtered project result with already-filtered cross_file_taints
        let filtered_project = rma_analyzer::project::ProjectAnalysisResult {
            files_analyzed: filtered_results.len(),
            file_results: filtered_results.clone(),
            cross_file_taints: cross_file_taints.clone(), // Already filtered earlier
            call_graph: result.call_graph.clone(),
            import_graph: result.import_graph.clone(),
            summary: summary.clone(),
            duration_ms: result.duration_ms,
        };

        return tui::run_from_analysis_with_project(
            &filtered_results,
            &summary,
            Some(&filtered_project),
        );
    }

    // Output based on format
    match args.format {
        OutputFormat::Text => {
            output_text(
                &displayed_flows,
                &cross_file_taints,
                &args,
                total_flows,
                start.elapsed(),
            )?;
        }
        OutputFormat::Json => {
            output_json(
                &displayed_flows,
                &cross_file_taints,
                &args,
                args.output.clone(),
            )?;
        }
        OutputFormat::Compact => {
            output_compact(&displayed_flows, &cross_file_taints)?;
        }
        _ => {
            output_text(
                &displayed_flows,
                &cross_file_taints,
                &args,
                total_flows,
                start.elapsed(),
            )?;
        }
    }

    // Show statistics if requested
    if args.stats && !args.quiet {
        print_statistics(&result.call_graph, &flows, &cross_file_taints);
    }

    Ok(())
}

fn print_header(args: &FlowsArgs) {
    println!();
    println!("{}", "🔀 Cross-File Data Flow Analysis".cyan().bold());
    println!("{}", Theme::separator(50));
    println!(
        "  {} {}",
        "Path:".dimmed(),
        args.path.display().to_string().bright_white()
    );
    println!(
        "  {} {}",
        "Sort by:".dimmed(),
        format!("{:?}", args.sort_by).to_lowercase().cyan()
    );
    if args.min_confidence > 0.0 {
        println!(
            "  {} {:.0}%",
            "Min confidence:".dimmed(),
            args.min_confidence * 100.0
        );
    }
    if args.dedupe {
        println!("  {} {}", "Deduplication:".dimmed(), "enabled".green());
    }
    println!();
}

/// Filter out command injection flows that are safe by construction
/// (constant binary + constant args = no real vulnerability)
fn filter_safe_command_sinks(
    flows: Vec<TaintFlow>,
    file_results: &[rma_analyzer::FileAnalysis],
) -> Vec<TaintFlow> {
    flows
        .into_iter()
        .filter(|flow| {
            // Only filter command injection sinks
            let is_command_sink = flow
                .sink_type()
                .is_some_and(|st| matches!(st, SinkClassification::CommandInjection));

            if !is_command_sink {
                return true; // Keep non-command flows
            }

            // Only validate Rust files for now
            let is_rust = flow
                .sink
                .file
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "rs")
                .unwrap_or(false);

            if !is_rust {
                return true; // Can't validate, keep the flow
            }

            // Find file content from analysis results
            let content = file_results
                .iter()
                .find(|fr| {
                    let fr_path = Path::new(&fr.path);
                    let sink_path = &flow.sink.file;
                    fr_path.ends_with(sink_path)
                        || sink_path.ends_with(fr_path)
                        || fr_path.file_name() == sink_path.file_name()
                })
                .and_then(|fr| {
                    // Try to read the file content
                    std::fs::read_to_string(&fr.path).ok()
                });

            let content = match content {
                Some(c) => c,
                None => return true, // Can't validate, keep the flow
            };

            // Analyze the command site
            if let Some(site) = analyze_rust_command(&content, flow.sink.line, "") {
                match evaluate_command_sink(&site) {
                    ArgSinkVerdict::SafeByConstruction => {
                        // This is a false positive - filter it out
                        false
                    }
                    ArgSinkVerdict::Dangerous { .. } => true,
                    ArgSinkVerdict::NotASink => true,
                }
            } else {
                true // Couldn't analyze, keep the flow
            }
        })
        .collect()
}

fn filter_flows(flows: &[TaintFlow], args: &FlowsArgs) -> Vec<TaintFlow> {
    flows
        .iter()
        .filter(|flow| {
            // Filter by confidence
            if flow.confidence < args.min_confidence {
                return false;
            }

            // Filter by sink type
            if let Some(ref sink_filter) = args.sink_type {
                let sink_match = flow.sink_type().is_some_and(|st| {
                    format!("{:?}", st)
                        .to_lowercase()
                        .contains(&sink_filter.to_lowercase())
                });
                if !sink_match {
                    return false;
                }
            }

            // Filter by source type
            if let Some(ref source_filter) = args.source_type {
                let source_match = flow.source_type().is_some_and(|st| {
                    format!("{:?}", st)
                        .to_lowercase()
                        .contains(&source_filter.to_lowercase())
                });
                if !source_match {
                    return false;
                }
            }

            // Filter by file
            if let Some(ref through_file) = args.through_file {
                let file_in_path = flow.source.file == *through_file
                    || flow.sink.file == *through_file
                    || flow.path.iter().any(|f| f.file == *through_file);
                if !file_in_path {
                    return false;
                }
            }

            true
        })
        .cloned()
        .collect()
}

fn dedupe_flows(flows: Vec<TaintFlow>) -> Vec<TaintFlow> {
    // Group by (source_function, sink_function, sink_type)
    let mut seen: HashMap<(String, String, String), TaintFlow> = HashMap::new();

    for flow in flows {
        let key = (
            flow.source.name.clone(),
            flow.sink.name.clone(),
            flow.sink_type()
                .map_or("unknown".to_string(), |s| format!("{:?}", s)),
        );

        // Keep the flow with highest confidence
        if let Some(existing) = seen.get(&key) {
            if flow.confidence > existing.confidence {
                seen.insert(key, flow);
            }
        } else {
            seen.insert(key, flow);
        }
    }

    seen.into_values().collect()
}

fn sort_flows(flows: &mut [TaintFlow], sort_by: FlowSortBy, reverse: bool) {
    flows.sort_by(|a, b| {
        let cmp = match sort_by {
            FlowSortBy::Severity => {
                // Higher severity first (Critical > Error > Warning > Info)
                let severity_a = sink_to_severity(a.sink_type());
                let severity_b = sink_to_severity(b.sink_type());
                severity_b.cmp(&severity_a)
            }
            FlowSortBy::Confidence => {
                // Higher confidence first
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }
            FlowSortBy::SinkType => {
                let type_a = a
                    .sink_type()
                    .map_or("zzz".to_string(), |s| format!("{:?}", s));
                let type_b = b
                    .sink_type()
                    .map_or("zzz".to_string(), |s| format!("{:?}", s));
                type_a.cmp(&type_b)
            }
            FlowSortBy::SourceType => {
                let type_a = a
                    .source_type()
                    .map_or("zzz".to_string(), |s| format!("{:?}", s));
                let type_b = b
                    .source_type()
                    .map_or("zzz".to_string(), |s| format!("{:?}", s));
                type_a.cmp(&type_b)
            }
            FlowSortBy::File => a.sink.file.cmp(&b.sink.file),
            FlowSortBy::PathLength => a.path.len().cmp(&b.path.len()),
        };

        if reverse { cmp.reverse() } else { cmp }
    });
}

fn sink_to_severity(sink_type: Option<&SinkClassification>) -> u8 {
    match sink_type {
        Some(SinkClassification::SqlInjection) => 4,
        Some(SinkClassification::CommandInjection) => 4,
        Some(SinkClassification::Deserialization) => 4,
        Some(SinkClassification::PathTraversal) => 3,
        Some(SinkClassification::CrossSiteScripting) => 3,
        Some(SinkClassification::LdapInjection) => 3,
        Some(SinkClassification::TemplateInjection) => 3,
        Some(SinkClassification::XmlInjection) => 2,
        Some(SinkClassification::LogInjection) => 2,
        Some(SinkClassification::OpenRedirect) => 2,
        // GenericInjection is downgraded due to weak evidence
        Some(SinkClassification::GenericInjection) => 1,
        Some(SinkClassification::Other(_)) => 1,
        None => 0,
    }
}

fn output_text(
    flows: &[TaintFlow],
    cross_file_taints: &[CrossFileTaint],
    args: &FlowsArgs,
    total: usize,
    duration: std::time::Duration,
) -> Result<()> {
    if flows.is_empty() && cross_file_taints.is_empty() {
        println!();
        println!(
            "  {} No cross-file taint flows detected",
            Theme::info_mark()
        );
        println!();
        return Ok(());
    }

    println!();

    // Only show TaintFlow summary if we don't have CrossFileTaints
    // CrossFileTaints are validated and more accurate - avoid showing both
    if cross_file_taints.is_empty() {
        // Group flows if requested
        match args.group_by {
            FlowGroupBy::SinkType => output_grouped_by_sink_type(flows, args),
            FlowGroupBy::SourceType => output_grouped_by_source_type(flows, args),
            FlowGroupBy::File => output_grouped_by_file(flows, args),
            FlowGroupBy::None => output_flat(flows, args),
        }
    }

    // Show cross-file taints if any (with separate limit) - these are validated
    if !cross_file_taints.is_empty() {
        println!();
        println!("{}", "Cross-File Taint Findings:".yellow().bold());
        println!("{}", Theme::separator(50));

        // Give taints their own limit (same as the main limit)
        let taint_limit = args.limit;
        let taints_to_show: Vec<_> = if args.all {
            cross_file_taints.iter().collect()
        } else {
            cross_file_taints.iter().take(taint_limit).collect()
        };

        for (i, taint) in taints_to_show.iter().enumerate() {
            println!();
            print_cross_file_taint(i + 1, taint, args.evidence);
        }

        if !args.all && taint_limit < cross_file_taints.len() {
            println!();
            println!(
                "  {} (showing {} of {} taints)",
                "...".dimmed(),
                taint_limit.to_string().yellow(),
                cross_file_taints.len().to_string().yellow()
            );
        }
    }

    // Summary
    println!();
    println!("{}", Theme::separator(50));

    let displayed = flows.len() + cross_file_taints.len();
    if displayed < total {
        println!(
            "Showing {} of {} flows (use --all for complete list)",
            displayed.to_string().green(),
            total.to_string().yellow()
        );
    } else {
        println!(
            "Found {} cross-file flows in {:?}",
            displayed.to_string().green().bold(),
            duration
        );
    }
    println!();

    Ok(())
}

fn output_grouped_by_sink_type(flows: &[TaintFlow], args: &FlowsArgs) {
    let mut groups: HashMap<String, Vec<&TaintFlow>> = HashMap::new();

    for flow in flows {
        let key = flow
            .sink_type()
            .map_or("Unknown".to_string(), |s| format!("{}", s));
        groups.entry(key).or_default().push(flow);
    }

    let mut keys: Vec<_> = groups.keys().cloned().collect();
    keys.sort();

    for key in keys {
        let group_flows = &groups[&key];
        let severity = get_sink_severity(&key);

        println!(
            "{} {} ({} flows)",
            severity_icon(severity),
            key.bold(),
            group_flows.len().to_string().yellow()
        );
        println!("{}", Theme::separator(40));

        for flow in group_flows.iter() {
            print_flow(flow, args.evidence);
        }
        println!();
    }
}

fn output_grouped_by_source_type(flows: &[TaintFlow], args: &FlowsArgs) {
    let mut groups: HashMap<String, Vec<&TaintFlow>> = HashMap::new();

    for flow in flows {
        let key = flow
            .source_type()
            .map_or("Unknown".to_string(), |s| format!("{}", s));
        groups.entry(key).or_default().push(flow);
    }

    let mut keys: Vec<_> = groups.keys().cloned().collect();
    keys.sort();

    for key in keys {
        let group_flows = &groups[&key];

        println!(
            "{} {} ({} flows)",
            "📥".cyan(),
            key.bold(),
            group_flows.len().to_string().yellow()
        );
        println!("{}", Theme::separator(40));

        for flow in group_flows.iter() {
            print_flow(flow, args.evidence);
        }
        println!();
    }
}

fn output_grouped_by_file(flows: &[TaintFlow], args: &FlowsArgs) {
    let mut groups: HashMap<PathBuf, Vec<&TaintFlow>> = HashMap::new();

    for flow in flows {
        groups.entry(flow.sink.file.clone()).or_default().push(flow);
    }

    let mut keys: Vec<_> = groups.keys().cloned().collect();
    keys.sort();

    for key in keys {
        let group_flows = &groups[&key];
        let filename = key
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown");

        println!(
            "{} {} ({} flows)",
            "📄".dimmed(),
            filename.bold(),
            group_flows.len().to_string().yellow()
        );
        println!("  {}", key.display().to_string().dimmed());
        println!("{}", Theme::separator(40));

        for flow in group_flows.iter() {
            print_flow(flow, args.evidence);
        }
        println!();
    }
}

fn output_flat(flows: &[TaintFlow], args: &FlowsArgs) {
    for (i, flow) in flows.iter().enumerate() {
        println!(
            "{}. {}",
            (i + 1).to_string().dimmed(),
            format_flow_summary(flow)
        );
        print_flow(flow, args.evidence);
        println!();
    }
}

fn print_flow(flow: &TaintFlow, show_evidence: bool) {
    let confidence_pct = (flow.confidence * 100.0) as u32;
    let confidence_str = format!("{}%", confidence_pct);
    let confidence_colored = if confidence_pct >= 80 {
        confidence_str.green()
    } else if confidence_pct >= 50 {
        confidence_str.yellow()
    } else {
        confidence_str.red()
    };

    // Source info
    let source_file = flow
        .source
        .file
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("?");
    let source_type = flow
        .source_type()
        .map_or("input".to_string(), |s| format!("{}", s));

    println!(
        "  {} {} {}:{} ({})",
        "SOURCE".green().bold(),
        flow.source.name.cyan(),
        source_file.dimmed(),
        flow.source.line.to_string().dimmed(),
        source_type.dimmed()
    );

    // Show flow path if evidence mode
    if show_evidence && !flow.path.is_empty() {
        println!("  {}", "│".dimmed());
        for func in &flow.path {
            let file = func
                .file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("?");
            let cross_file = if func.file != flow.source.file {
                format!(" [{}]", file).yellow()
            } else {
                "".normal()
            };
            println!(
                "  {} {} {}:{}{}",
                "├─▶".dimmed(),
                func.name.white(),
                file.dimmed(),
                func.line.to_string().dimmed(),
                cross_file
            );
        }
        println!("  {}", "│".dimmed());
    } else if !flow.path.is_empty() {
        println!(
            "  {} ({} hops)",
            "↓".dimmed(),
            flow.path.len().to_string().dimmed()
        );
    } else {
        println!("  {}", "↓".dimmed());
    }

    // Sink info
    let sink_file = flow
        .sink
        .file
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("?");
    let sink_type = flow
        .sink_type()
        .map_or("sink".to_string(), |s| format!("{}", s));
    let cross_file_marker = if flow.source.file != flow.sink.file {
        " ⚠️ CROSS-FILE".yellow().bold()
    } else {
        "".normal()
    };

    println!(
        "  {} {} {}:{} ({}){}",
        "SINK".red().bold(),
        flow.sink.name.cyan(),
        sink_file.dimmed(),
        flow.sink.line.to_string().dimmed(),
        sink_type.red(),
        cross_file_marker
    );

    println!(
        "  {} confidence: {} | {} → {}",
        "└".dimmed(),
        confidence_colored,
        source_type.dimmed(),
        sink_type.dimmed()
    );
}

fn print_cross_file_taint(index: usize, taint: &CrossFileTaint, show_evidence: bool) {
    let severity_icon = match taint.severity {
        Severity::Critical => "🔴".to_string(),
        Severity::Error => "🟠".to_string(),
        Severity::Warning => "🟡".to_string(),
        Severity::Info => "🔵".to_string(),
    };

    println!(
        "{}. {} {}",
        index.to_string().dimmed(),
        severity_icon,
        taint.description.bold()
    );

    // Source
    let source_file = taint
        .source
        .file
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("?");
    println!(
        "   {} {} ({}:{})",
        "Source:".green(),
        taint.source.function.cyan(),
        source_file.dimmed(),
        taint.source.line.to_string().dimmed()
    );

    // Flow path
    if show_evidence && !taint.path.is_empty() {
        println!("   {}", "Flow:".yellow());
        for step in &taint.path {
            let step_file = step
                .file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("?");
            println!(
                "     {} {} ({}:{})",
                "→".dimmed(),
                step.function.white(),
                step_file.dimmed(),
                step.line.to_string().dimmed()
            );
        }
    } else if !taint.path.is_empty() {
        println!(
            "   {} {} steps",
            "Flow:".yellow(),
            taint.path.len().to_string().dimmed()
        );
    }

    // Sink
    let sink_file = taint
        .sink
        .file
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("?");
    println!(
        "   {} {} ({}:{})",
        "Sink:".red(),
        taint.sink.function.cyan(),
        sink_file.dimmed(),
        taint.sink.line.to_string().dimmed()
    );

    // Context (helps understand if sanitization is possible)
    let context_desc = taint.sink_context.description();
    let context_colored = match taint.sink_context {
        SinkContext::HtmlRaw | SinkContext::JavaScript => context_desc.bright_red(),
        SinkContext::CommandShell | SinkContext::CommandBinaryTaint => context_desc.bright_red(),
        SinkContext::Sql | SinkContext::Command | SinkContext::CommandExecArgs => {
            context_desc.red()
        }
        SinkContext::HtmlText | SinkContext::HtmlAttribute => context_desc.yellow(),
        SinkContext::Url | SinkContext::Template => context_desc.magenta(),
        SinkContext::FilePath => context_desc.yellow(), // Path traversal - medium severity
        SinkContext::Unknown => context_desc.dimmed(),
    };
    println!(
        "   {} {} ({})",
        "Context:".blue(),
        context_colored,
        taint.sink_context.primary_cwe().dimmed()
    );

    // Fix recommendation (actionable guidance)
    if taint.sink_context != SinkContext::Unknown {
        // Infer language from file extension
        let language = taint
            .sink
            .file
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| match ext {
                "js" | "jsx" | "mjs" => rma_common::Language::JavaScript,
                "ts" | "tsx" => rma_common::Language::TypeScript,
                "py" => rma_common::Language::Python,
                "java" => rma_common::Language::Java,
                "go" => rma_common::Language::Go,
                "rs" => rma_common::Language::Rust,
                "rb" => rma_common::Language::Ruby,
                _ => rma_common::Language::Unknown,
            })
            .unwrap_or(rma_common::Language::Unknown);

        let fix = fix_recommendation(taint.sink_context, language);
        println!("   {} {}", "Fix:".green(), fix.dimmed());

        // Show why this was classified as a sink (helps validate findings)
        // Include role and arg info if available for better precision
        let why = if let (Some(role), Some(arg_idx)) = (&taint.sink_role, taint.sink_arg_index) {
            let callsite_info = if let Some(line) = taint.sink_callsite_line {
                format!(" callsite=line:{}", line)
            } else {
                String::new()
            };
            format!(
                "matched {} sink in {} role={} arg={}{}",
                taint.sink_type, taint.sink.function, role, arg_idx, callsite_info
            )
        } else {
            format!(
                "matched {} sink in {}",
                taint.sink_type, taint.sink.function
            )
        };
        println!("   {} {}", "Why:".blue().dimmed(), why.dimmed());
    }

    // Show evidence for classification (helps validate/triage findings)
    let evidence_display = match &taint.sink_evidence.kind {
        SinkEvidenceKind::CalleeEvidence { qualified_name } => format!(
            "✓ callee: {} (confidence: {:.0}%)",
            qualified_name,
            taint.sink_evidence.confidence * 100.0
        )
        .green(),
        SinkEvidenceKind::ImportEvidence { import_path } => format!(
            "✓ import: {} (confidence: {:.0}%)",
            import_path,
            taint.sink_evidence.confidence * 100.0
        )
        .green(),
        SinkEvidenceKind::TypeEvidence { type_name } => format!(
            "✓ type: {} (confidence: {:.0}%)",
            type_name,
            taint.sink_evidence.confidence * 100.0
        )
        .cyan(),
        SinkEvidenceKind::PatternOnly { pattern } => format!(
            "⚠ pattern-only: {} (confidence: {:.0}%)",
            pattern,
            taint.sink_evidence.confidence * 100.0
        )
        .yellow(),
        SinkEvidenceKind::None => "✗ no evidence".to_string().red(),
    };
    println!("   {} {}", "Evidence:".dimmed(), evidence_display);

    // Show reachability status (helps triage findings)
    let reachability_display = match taint.reachability {
        rma_analyzer::project::Reachability::ProdReachable => "✅ prod".green(),
        rma_analyzer::project::Reachability::TestOnly => "🧪 test-only".yellow(),
        rma_analyzer::project::Reachability::Unknown => "⚠️ unknown".dimmed(),
    };
    println!("   {} {}", "Reachability:".dimmed(), reachability_display);
}

fn format_flow_summary(flow: &TaintFlow) -> String {
    let sink_type = flow
        .sink_type()
        .map_or("Unknown".to_string(), |s| format!("{}", s));
    let source_type = flow
        .source_type()
        .map_or("Input".to_string(), |s| format!("{}", s));

    format!("{} → {} ({})", source_type, sink_type, flow.source.name)
}

fn get_sink_severity(sink_type: &str) -> Severity {
    let lower = sink_type.to_lowercase();
    if lower.contains("sql") || lower.contains("command") || lower.contains("deserial") {
        Severity::Critical
    } else if lower.contains("path")
        || lower.contains("xss")
        || lower.contains("ldap")
        || lower.contains("template")
    {
        Severity::Error
    } else if lower.contains("xml") || lower.contains("log") || lower.contains("redirect") {
        Severity::Warning
    } else {
        Severity::Info
    }
}

fn severity_icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "🔴",
        Severity::Error => "🟠",
        Severity::Warning => "🟡",
        Severity::Info => "🔵",
    }
}

fn output_json(
    flows: &[TaintFlow],
    cross_file_taints: &[CrossFileTaint],
    _args: &FlowsArgs,
    output: Option<PathBuf>,
) -> Result<()> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct FlowOutput {
        flows: Vec<FlowEntry>,
        cross_file_taints: Vec<TaintEntry>,
        total_flows: usize,
    }

    #[derive(Serialize)]
    struct FlowEntry {
        source_function: String,
        source_file: String,
        source_line: usize,
        source_type: Option<String>,
        sink_function: String,
        sink_file: String,
        sink_line: usize,
        sink_type: Option<String>,
        confidence: f32,
        path_length: usize,
        is_cross_file: bool,
    }

    #[derive(Serialize)]
    struct TaintEntry {
        source_function: String,
        source_file: String,
        source_line: usize,
        sink_function: String,
        sink_file: String,
        sink_line: usize,
        severity: String,
        sink_context: String,
        sink_context_cwe: String,
        description: String,
        path: Vec<PathStep>,
    }

    #[derive(Serialize)]
    struct PathStep {
        function: String,
        file: String,
        line: usize,
    }

    let flow_entries: Vec<FlowEntry> = flows
        .iter()
        .map(|f| FlowEntry {
            source_function: f.source.name.clone(),
            source_file: f.source.file.display().to_string(),
            source_line: f.source.line,
            source_type: f.source_type().map(|s| format!("{:?}", s)),
            sink_function: f.sink.name.clone(),
            sink_file: f.sink.file.display().to_string(),
            sink_line: f.sink.line,
            sink_type: f.sink_type().map(|s| format!("{:?}", s)),
            confidence: f.confidence,
            path_length: f.path.len(),
            is_cross_file: f.source.file != f.sink.file,
        })
        .collect();

    let taint_entries: Vec<TaintEntry> = cross_file_taints
        .iter()
        .map(|t| TaintEntry {
            source_function: t.source.function.clone(),
            source_file: t.source.file.display().to_string(),
            source_line: t.source.line,
            sink_function: t.sink.function.clone(),
            sink_file: t.sink.file.display().to_string(),
            sink_line: t.sink.line,
            severity: format!("{:?}", t.severity),
            sink_context: t.sink_context.description().to_string(),
            sink_context_cwe: t.sink_context.primary_cwe().to_string(),
            description: t.description.clone(),
            path: t
                .path
                .iter()
                .map(|step| PathStep {
                    function: step.function.clone(),
                    file: step.file.display().to_string(),
                    line: step.line,
                })
                .collect(),
        })
        .collect();

    let output_data = FlowOutput {
        flows: flow_entries,
        cross_file_taints: taint_entries,
        total_flows: flows.len() + cross_file_taints.len(),
    };

    let json = serde_json::to_string_pretty(&output_data)?;

    if let Some(path) = output {
        std::fs::write(&path, &json)?;
        eprintln!("Output written to: {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(())
}

fn output_compact(flows: &[TaintFlow], cross_file_taints: &[CrossFileTaint]) -> Result<()> {
    for flow in flows {
        let sink_type = flow
            .sink_type()
            .map_or("unknown".to_string(), |s| format!("{:?}", s).to_lowercase());
        let source_type = flow
            .source_type()
            .map_or("input".to_string(), |s| format!("{:?}", s).to_lowercase());

        let source_file = flow
            .source
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");
        let sink_file = flow
            .sink
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");

        println!(
            "{}:{}:{} [{}] {} → {}:{}:{} [{}] (conf: {:.0}%)",
            source_file,
            flow.source.line,
            flow.source.name,
            source_type,
            if flow.source.file != flow.sink.file {
                "⚠️"
            } else {
                "→"
            },
            sink_file,
            flow.sink.line,
            flow.sink.name,
            sink_type,
            flow.confidence * 100.0
        );
    }

    for taint in cross_file_taints {
        let source_file = taint
            .source
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");
        let sink_file = taint
            .sink
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");

        let severity_char = match taint.severity {
            Severity::Critical => "C",
            Severity::Error => "E",
            Severity::Warning => "W",
            Severity::Info => "I",
        };

        println!(
            "{}:{}:{} ⚠️ {}:{}:{} [{}] {}",
            source_file,
            taint.source.line,
            taint.source.function,
            sink_file,
            taint.sink.line,
            taint.sink.function,
            severity_char,
            taint.description
        );
    }

    Ok(())
}

fn print_statistics(
    call_graph: &Option<CallGraph>,
    flows: &[TaintFlow],
    cross_file_taints: &[CrossFileTaint],
) {
    println!();
    println!("{}", "📊 Flow Statistics".cyan().bold());
    println!("{}", Theme::separator(50));

    if let Some(cg) = call_graph {
        println!(
            "  {} {} functions, {} call edges",
            "Call Graph:".dimmed(),
            cg.function_count().to_string().bright_white(),
            cg.edge_count().to_string().bright_white()
        );

        let cross_file_edges = cg.cross_file_edges().len();
        if cross_file_edges > 0 {
            println!(
                "  {} {} cross-file calls",
                "            ".dimmed(),
                cross_file_edges.to_string().yellow()
            );
        }

        let sources = cg.source_functions().len();
        let sinks = cg.sink_functions().len();
        let sanitizers = cg.sanitizer_functions().len();

        println!(
            "  {} {} sources, {} sinks, {} sanitizers",
            "Security:".dimmed(),
            sources.to_string().green(),
            sinks.to_string().red(),
            sanitizers.to_string().blue()
        );
    }

    println!(
        "  {} {} taint flows detected",
        "Flows:".dimmed(),
        flows.len().to_string().yellow().bold()
    );

    // Breakdown by sink type
    let mut by_sink: HashMap<String, usize> = HashMap::new();
    for flow in flows {
        let key = flow
            .sink_type()
            .map_or("Unknown".to_string(), |s| format!("{}", s));
        *by_sink.entry(key).or_default() += 1;
    }

    if !by_sink.is_empty() {
        let mut entries: Vec<_> = by_sink.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1));

        for (sink_type, count) in entries.iter().take(5) {
            println!(
                "    {} {}: {}",
                "•".dimmed(),
                sink_type,
                count.to_string().yellow()
            );
        }
    }

    // Cross-file taints
    if !cross_file_taints.is_empty() {
        println!(
            "  {} {} cross-file taint issues",
            "Issues:".dimmed(),
            cross_file_taints.len().to_string().red().bold()
        );
    }

    // Confidence distribution
    if !flows.is_empty() {
        let high_conf = flows.iter().filter(|f| f.confidence >= 0.8).count();
        let med_conf = flows
            .iter()
            .filter(|f| f.confidence >= 0.5 && f.confidence < 0.8)
            .count();
        let low_conf = flows.iter().filter(|f| f.confidence < 0.5).count();

        println!(
            "  {} high: {}, medium: {}, low: {}",
            "Confidence:".dimmed(),
            high_conf.to_string().green(),
            med_conf.to_string().yellow(),
            low_conf.to_string().red()
        );
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_by_parsing() {
        assert_eq!(
            "severity".parse::<FlowSortBy>().unwrap(),
            FlowSortBy::Severity
        );
        assert_eq!(
            "conf".parse::<FlowSortBy>().unwrap(),
            FlowSortBy::Confidence
        );
        assert_eq!(
            "sink-type".parse::<FlowSortBy>().unwrap(),
            FlowSortBy::SinkType
        );
    }

    #[test]
    fn test_group_by_parsing() {
        assert_eq!(
            "sink".parse::<FlowGroupBy>().unwrap(),
            FlowGroupBy::SinkType
        );
        assert_eq!("file".parse::<FlowGroupBy>().unwrap(), FlowGroupBy::File);
        assert_eq!("none".parse::<FlowGroupBy>().unwrap(), FlowGroupBy::None);
    }
}
