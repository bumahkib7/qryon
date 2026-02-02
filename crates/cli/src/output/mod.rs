//! Output formatting utilities

pub mod diagnostics;
pub mod github;
pub mod html;
pub mod json;
pub mod sarif;
pub mod tables;
pub mod text;

// Re-export diagnostic types for convenience
#[allow(unused_imports)]
pub use diagnostics::{DiagnosticRenderer, RichDiagnosticRenderer, SourceCache};

use crate::OutputFormat;
use anyhow::Result;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use std::path::PathBuf;
use std::time::Duration;

/// Format analysis results based on output format
#[allow(dead_code)]
pub fn format_results(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    format: OutputFormat,
    output_file: Option<PathBuf>,
) -> Result<()> {
    format_results_with_root(results, summary, duration, format, output_file, None)
}

/// Format analysis results with project root for relative paths
pub fn format_results_with_root(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    format: OutputFormat,
    output_file: Option<PathBuf>,
    project_root: Option<&std::path::Path>,
) -> Result<()> {
    match format {
        OutputFormat::Text => text::output(results, summary, duration),
        OutputFormat::Json => json::output(results, summary, duration, output_file),
        OutputFormat::Sarif => sarif::output(results, output_file),
        OutputFormat::Compact => text::output_compact(results, summary, duration),
        OutputFormat::Markdown => tables::output_markdown(results, summary, duration, output_file),
        OutputFormat::Github => github::output(results, summary, duration),
        OutputFormat::Html => html::output(results, summary, duration, output_file, project_root),
    }
}

/// Write output to file or stdout
#[allow(dead_code)]
pub fn write_output(content: &str, output_file: Option<PathBuf>) -> Result<()> {
    if let Some(path) = output_file {
        std::fs::write(&path, content)?;
        eprintln!("Output written to: {}", path.display());
    } else {
        println!("{}", content);
    }
    Ok(())
}
