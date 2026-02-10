//! Error handling and display utilities

#![allow(dead_code)]

use anyhow::Error;
use colored::Colorize;

/// Print an error with helpful suggestions
pub fn print_error(error: &Error, verbose: bool) {
    eprintln!("\n{} {}", "error:".red().bold(), error);

    // Print error chain in verbose mode
    if verbose {
        for (i, cause) in error.chain().skip(1).enumerate() {
            eprintln!(
                "  {} {}: {}",
                "│".dimmed(),
                format!("cause {}", i + 1).dimmed(),
                cause
            );
        }
    }

    // Provide helpful suggestions based on error type
    let suggestions = get_suggestions(error);
    if !suggestions.is_empty() {
        eprintln!("\n{}", "suggestions:".yellow().bold());
        for suggestion in suggestions {
            eprintln!("  {} {}", "→".dimmed(), suggestion);
        }
    }

    eprintln!();
}

/// Get context-aware suggestions for common errors
fn get_suggestions(error: &Error) -> Vec<String> {
    let error_str = error.to_string().to_lowercase();
    let mut suggestions = Vec::new();

    // File/path related errors
    if error_str.contains("no such file") || error_str.contains("not found") {
        suggestions.push("Check that the path exists and is accessible".into());
        suggestions.push("Try running 'qryon init' to initialize the project".into());
    }

    // Permission errors
    if error_str.contains("permission denied") {
        suggestions.push("Check file permissions".into());
        suggestions.push("Try running with appropriate permissions".into());
    }

    // Index related errors
    if error_str.contains("index") || error_str.contains("tantivy") {
        suggestions.push("Try running 'qryon scan' first to build the index".into());
        suggestions.push("Delete .qryon/index and re-scan to rebuild".into());
    }

    // Configuration errors
    if error_str.contains("config") || error_str.contains("configuration") {
        suggestions.push("Check your configuration with 'qryon config list'".into());
        suggestions.push("Reset to defaults with 'qryon config reset'".into());
    }

    // API/Network errors
    if error_str.contains("api")
        || error_str.contains("network")
        || error_str.contains("connection")
    {
        suggestions.push("Check your internet connection".into());
        suggestions.push("Verify API credentials are configured correctly".into());
        suggestions.push("Set API keys with 'qryon config set ai.api_key YOUR_KEY'".into());
    }

    // AI-related errors
    if error_str.contains("ai") || error_str.contains("claude") || error_str.contains("openai") {
        suggestions.push("Ensure AI provider API key is set".into());
        suggestions.push("Try a different provider with '--ai-provider local'".into());
    }

    // Parser errors
    if error_str.contains("parse") || error_str.contains("syntax") {
        suggestions.push("The file may contain syntax errors".into());
        suggestions.push("Try running with '--verbose' for more details".into());
    }

    // Generic fallback
    if suggestions.is_empty() {
        suggestions.push("Run with '-v' or '-vv' for more details".into());
        suggestions.push("Check 'qryon --help' for usage information".into());
    }

    suggestions
}

/// Print a warning message
pub fn print_warning(message: &str) {
    eprintln!("{} {}", "warning:".yellow().bold(), message);
}

/// Print an info message
pub fn print_info(message: &str) {
    eprintln!("{} {}", "info:".blue().bold(), message);
}

/// Print a hint message
pub fn print_hint(message: &str) {
    eprintln!("{} {}", "hint:".cyan(), message);
}

/// Format an error for display in tables/compact output
pub fn format_error_compact(error: &Error) -> String {
    error.to_string()
}
