//! Output formatting utilities

pub mod diagnostics;
pub mod github;
pub mod html;
pub mod json;
pub mod pretty;
pub mod sarif;
pub mod tables;
pub mod text;

// Re-export pretty output types (allow unused for now until integration)
#[allow(unused_imports)]
pub use pretty::{BoxChars, PrettyConfig, PrettyFormat, PrettyRenderer};

// Re-export diagnostic types for convenience
#[allow(unused_imports)]
pub use diagnostics::{DiagnosticRenderer, RichDiagnosticRenderer, SourceCache};

use crate::{GroupBy, OutputFormat};
use anyhow::Result;
use rma_analyzer::{AnalysisSummary, FileAnalysis};
use std::path::PathBuf;
use std::time::Duration;

/// Output formatting options
#[derive(Debug, Clone)]
pub struct OutputOptions {
    /// Maximum number of findings to display
    pub limit: usize,
    /// How to group findings
    pub group_by: GroupBy,
    /// Collapse repeated findings
    pub collapse: bool,
    /// Expand collapsed findings (show all locations)
    pub expand: bool,
    /// Quiet mode - only show summary
    pub quiet: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            limit: 20,
            group_by: GroupBy::File,
            collapse: false,
            expand: false,
            quiet: false,
        }
    }
}

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
#[allow(dead_code)]
pub fn format_results_with_root(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    format: OutputFormat,
    output_file: Option<PathBuf>,
    project_root: Option<&std::path::Path>,
) -> Result<()> {
    format_results_with_options(
        results,
        summary,
        duration,
        format,
        output_file,
        project_root,
        &OutputOptions::default(),
    )
}

/// Format analysis results with full options
pub fn format_results_with_options(
    results: &[FileAnalysis],
    summary: &AnalysisSummary,
    duration: Duration,
    format: OutputFormat,
    output_file: Option<PathBuf>,
    project_root: Option<&std::path::Path>,
    options: &OutputOptions,
) -> Result<()> {
    match format {
        OutputFormat::Text => text::output_with_options(results, summary, duration, options),
        OutputFormat::Json => json::output(results, summary, duration, output_file),
        OutputFormat::Sarif => sarif::output(results, summary, duration, output_file),
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
