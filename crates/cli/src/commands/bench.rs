//! Benchmark command implementation

use crate::BenchFormat;
use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::AnalyzerEngine;
use rma_common::RmaConfig;
use rma_parser::ParserEngine;
use serde::Serialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct BenchArgs {
    pub path: PathBuf,
    pub iterations: usize,
    pub exclude: Option<Vec<String>>,
    pub format: BenchFormat,
}

/// JSON output structure for benchmarks
#[derive(Serialize)]
struct BenchmarkResults {
    version: String,
    path: String,
    iterations: usize,
    exclude_patterns: Vec<String>,
    files_count: usize,
    total_lines: usize,
    parse: PhaseStats,
    analyze: PhaseStats,
    full_pipeline: PhaseStats,
    throughput: Throughput,
    wall_clock_seconds: f64,
}

#[derive(Serialize)]
struct PhaseStats {
    min_ms: f64,
    max_ms: f64,
    avg_ms: f64,
    stddev_ms: f64,
}

#[derive(Serialize)]
struct Throughput {
    files_per_second: f64,
    lines_per_second: f64,
}

pub fn run(args: BenchArgs) -> Result<()> {
    let command_start = Instant::now();

    // Build config with exclude patterns
    let mut config = RmaConfig::default();
    let exclude_patterns = args.exclude.clone().unwrap_or_default();
    if !exclude_patterns.is_empty() {
        config.exclude_patterns = exclude_patterns.clone();
    }

    // Add common default excludes if none specified
    if config.exclude_patterns.is_empty() {
        config.exclude_patterns = vec![
            "**/node_modules/**".to_string(),
            "**/target/**".to_string(),
            "**/.git/**".to_string(),
        ];
    }

    if args.format == BenchFormat::Text {
        println!();
        println!("{}", "⏱  Qryon Benchmark".cyan().bold());
        println!("{}", Theme::separator(60));
        println!(
            "  {} {}",
            "Path:".dimmed(),
            args.path.display().to_string().bright_white()
        );
        println!(
            "  {} {}",
            "Iterations:".dimmed(),
            args.iterations.to_string().bright_white()
        );
        if !config.exclude_patterns.is_empty() {
            println!(
                "  {} {}",
                "Excludes:".dimmed(),
                config.exclude_patterns.len().to_string().yellow()
            );
            for pattern in &config.exclude_patterns {
                println!("    {}", pattern.dimmed());
            }
        }
        println!();
    }

    // Warm up
    if args.format == BenchFormat::Text {
        println!("{} Warming up...", Theme::info_mark());
    }
    let parser = ParserEngine::new(config.clone());
    let _analyzer = AnalyzerEngine::new(config.clone());
    let _ = parser.parse_directory(&args.path)?;

    // Benchmark parsing
    if args.format == BenchFormat::Text {
        println!("{} Benchmarking parse phase...", Theme::info_mark());
    }
    let parse_times = benchmark_phase(args.iterations, || {
        let parser = ParserEngine::new(config.clone());
        parser.parse_directory(&args.path).map(|_| ())
    })?;

    // Benchmark analysis
    if args.format == BenchFormat::Text {
        println!("{} Benchmarking analyze phase...", Theme::info_mark());
    }
    let (parsed_files, _) = parser.parse_directory(&args.path)?;
    let analyze_times = benchmark_phase(args.iterations, || {
        let analyzer = AnalyzerEngine::new(config.clone());
        analyzer.analyze_files(&parsed_files).map(|_| ())
    })?;

    // Full pipeline
    if args.format == BenchFormat::Text {
        println!("{} Benchmarking full pipeline...", Theme::info_mark());
    }
    let full_times = benchmark_phase(args.iterations, || {
        let parser = ParserEngine::new(config.clone());
        let analyzer = AnalyzerEngine::new(config.clone());
        let (files, _) = parser.parse_directory(&args.path)?;
        analyzer.analyze_files(&files).map(|_| ())
    })?;

    // Get final metrics
    let (files, _) = parser.parse_directory(&args.path)?;
    let total_lines: usize = files.iter().map(|f| f.content.lines().count()).sum();
    let avg_full_time = average(&full_times);

    let wall_clock = command_start.elapsed();

    match args.format {
        BenchFormat::Json => {
            let results = BenchmarkResults {
                version: env!("CARGO_PKG_VERSION").to_string(),
                path: args.path.display().to_string(),
                iterations: args.iterations,
                exclude_patterns: config.exclude_patterns.clone(),
                files_count: files.len(),
                total_lines,
                parse: times_to_stats(&parse_times),
                analyze: times_to_stats(&analyze_times),
                full_pipeline: times_to_stats(&full_times),
                throughput: Throughput {
                    files_per_second: files.len() as f64 / avg_full_time.as_secs_f64(),
                    lines_per_second: total_lines as f64 / avg_full_time.as_secs_f64(),
                },
                wall_clock_seconds: wall_clock.as_secs_f64(),
            };
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        BenchFormat::Text => {
            println!();
            println!("{}", Theme::header("Results"));
            println!("{}", Theme::double_separator(60));
            println!();

            print_bench_results("Parse", &parse_times);
            print_bench_results("Analyze", &analyze_times);
            print_bench_results("Full Pipeline", &full_times);

            println!();
            println!("{}", Theme::subheader("Throughput"));
            println!("{}", Theme::separator(40));
            println!(
                "  {} files/s",
                format!("{:.0}", files.len() as f64 / avg_full_time.as_secs_f64())
                    .green()
                    .bold()
            );
            println!(
                "  {} lines/s",
                format!("{:.0}", total_lines as f64 / avg_full_time.as_secs_f64())
                    .green()
                    .bold()
            );
            println!();

            // Show file counts by language
            println!("{}", Theme::subheader("Files by Language"));
            println!("{}", Theme::separator(40));
            let mut lang_counts: std::collections::HashMap<rma_common::Language, usize> =
                std::collections::HashMap::new();
            for f in &files {
                *lang_counts.entry(f.language).or_default() += 1;
            }
            let mut counts: Vec<_> = lang_counts.into_iter().collect();
            counts.sort_by(|a, b| b.1.cmp(&a.1));
            for (lang, count) in counts {
                println!("  {:12} {}", format!("{:?}", lang).cyan(), count);
            }
            println!();

            // Wall-clock time
            println!("{}", Theme::separator(60));
            println!(
                "  {} {}",
                "Total wall-clock time:".bright_white().bold(),
                format_duration(wall_clock).green().bold()
            );
            println!();
        }
    }

    Ok(())
}

fn benchmark_phase<F>(iterations: usize, f: F) -> Result<Vec<Duration>>
where
    F: Fn() -> Result<()>,
{
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        f()?;
        times.push(start.elapsed());
    }

    Ok(times)
}

fn print_bench_results(name: &str, times: &[Duration]) {
    let min = times.iter().min().copied().unwrap_or_default();
    let max = times.iter().max().copied().unwrap_or_default();
    let avg = average(times);
    let stddev = std_dev(times, avg);

    println!("  {}", name.cyan().bold());
    println!(
        "    min: {:>10.2}ms  max: {:>10.2}ms",
        min.as_secs_f64() * 1000.0,
        max.as_secs_f64() * 1000.0
    );
    println!(
        "    avg: {:>10.2}ms  stddev: {:>7.2}ms",
        avg.as_secs_f64() * 1000.0,
        stddev.as_secs_f64() * 1000.0
    );
    println!();
}

fn average(times: &[Duration]) -> Duration {
    if times.is_empty() {
        return Duration::ZERO;
    }
    let sum: Duration = times.iter().sum();
    sum / times.len() as u32
}

fn std_dev(times: &[Duration], avg: Duration) -> Duration {
    if times.len() < 2 {
        return Duration::ZERO;
    }

    let avg_nanos = avg.as_nanos() as f64;
    let variance: f64 = times
        .iter()
        .map(|t| {
            let diff = t.as_nanos() as f64 - avg_nanos;
            diff * diff
        })
        .sum::<f64>()
        / (times.len() - 1) as f64;

    Duration::from_nanos(variance.sqrt() as u64)
}

fn times_to_stats(times: &[Duration]) -> PhaseStats {
    let min = times.iter().min().copied().unwrap_or_default();
    let max = times.iter().max().copied().unwrap_or_default();
    let avg = average(times);
    let stddev = std_dev(times, avg);

    PhaseStats {
        min_ms: min.as_secs_f64() * 1000.0,
        max_ms: max.as_secs_f64() * 1000.0,
        avg_ms: avg.as_secs_f64() * 1000.0,
        stddev_ms: stddev.as_secs_f64() * 1000.0,
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.2}s", secs)
    } else {
        let mins = (secs / 60.0).floor();
        let remaining_secs = secs - (mins * 60.0);
        format!("{}m {:.1}s", mins as u64, remaining_secs)
    }
}
