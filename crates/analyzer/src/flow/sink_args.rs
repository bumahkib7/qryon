//! Argument-Level Sink Modeling
//!
//! This module models sinks at the argument level, not just function level.
//! A sink is only dangerous if tainted data reaches the specific argument
//! that represents the exploitable role.
//!
//! Example: `Command::new("git").arg(user_input)`
//! - Program role = "git" (constant, safe)
//! - ArgList role = user_input (tainted, but not shell injection if no shell)
//!
//! Only emit CWE-78 if ShellString role is tainted.

use std::path::PathBuf;

/// The role an argument plays in a sink call
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkArgRole {
    /// Binary/executable path (Command::new arg)
    Program,
    /// Shell command string (sh -c arg, system() arg)
    ShellString,
    /// Individual command arguments (safe if no shell)
    ArgList,
    /// Environment variable value
    EnvValue,
    /// Working directory
    WorkingDir,
    /// SQL query string
    SqlQuery,
    /// Raw HTML content
    HtmlRaw,
    /// URL target for redirects
    UrlTarget,
    /// Template string
    TemplateString,
    /// Not a sink argument
    NotSink,
}

impl SinkArgRole {
    /// Returns the CWE for this role when tainted
    pub fn cwe(&self) -> Option<&'static str> {
        match self {
            SinkArgRole::Program => Some("CWE-78"),
            SinkArgRole::ShellString => Some("CWE-78"),
            SinkArgRole::ArgList => Some("CWE-88"), // Argument injection (different from shell injection)
            SinkArgRole::SqlQuery => Some("CWE-89"),
            SinkArgRole::HtmlRaw => Some("CWE-79"),
            SinkArgRole::UrlTarget => Some("CWE-601"),
            SinkArgRole::TemplateString => Some("CWE-1336"),
            SinkArgRole::EnvValue | SinkArgRole::WorkingDir => None,
            SinkArgRole::NotSink => None,
        }
    }

    /// Returns severity when this role is tainted
    pub fn severity(&self) -> &'static str {
        match self {
            SinkArgRole::ShellString => "critical",
            SinkArgRole::Program => "critical",
            SinkArgRole::SqlQuery => "critical",
            SinkArgRole::HtmlRaw => "high",
            SinkArgRole::UrlTarget => "high",
            SinkArgRole::TemplateString => "high",
            SinkArgRole::ArgList => "medium", // Not shell injection
            SinkArgRole::EnvValue => "low",
            SinkArgRole::WorkingDir => "low",
            SinkArgRole::NotSink => "none",
        }
    }

    /// Description of what this role means
    pub fn description(&self) -> &'static str {
        match self {
            SinkArgRole::Program => "executable/binary path",
            SinkArgRole::ShellString => "shell command string",
            SinkArgRole::ArgList => "command argument",
            SinkArgRole::EnvValue => "environment variable",
            SinkArgRole::WorkingDir => "working directory",
            SinkArgRole::SqlQuery => "SQL query string",
            SinkArgRole::HtmlRaw => "raw HTML content",
            SinkArgRole::UrlTarget => "URL/redirect target",
            SinkArgRole::TemplateString => "template expression",
            SinkArgRole::NotSink => "not a sink",
        }
    }
}

/// A sink site with argument role information
#[derive(Debug, Clone)]
pub struct SinkSite {
    /// File containing the sink
    pub file: PathBuf,
    /// Line number of the actual sink callsite
    pub line: usize,
    /// Function containing the sink
    pub function: String,
    /// The sink API being called (e.g., "Command::new", "query")
    pub sink_api: String,
    /// Argument roles: (arg_index, role, is_constant)
    pub arg_roles: Vec<(usize, SinkArgRole, bool)>,
    /// Whether this is inside a shell invocation chain
    pub is_shell_context: bool,
    /// The variable/parameter name used in the dangerous role (if non-constant)
    pub tainted_param_name: Option<String>,
}

impl SinkSite {
    /// Check if any dangerous role is tainted (non-constant)
    pub fn has_tainted_dangerous_role(&self) -> Option<(usize, SinkArgRole)> {
        for (idx, role, is_constant) in &self.arg_roles {
            if !is_constant && role.cwe().is_some() {
                return Some((*idx, *role));
            }
        }
        None
    }

    /// Check if this is safe by construction (all dangerous roles are constant)
    pub fn is_safe_by_construction(&self) -> bool {
        self.arg_roles.iter().all(|(_, role, is_constant)| {
            // Safe if constant or if not a dangerous role
            *is_constant || role.cwe().is_none()
        })
    }

    /// Get the most dangerous tainted role
    pub fn most_dangerous_tainted_role(&self) -> Option<SinkArgRole> {
        let priorities = [
            SinkArgRole::ShellString,
            SinkArgRole::Program,
            SinkArgRole::SqlQuery,
            SinkArgRole::HtmlRaw,
            SinkArgRole::UrlTarget,
            SinkArgRole::TemplateString,
            SinkArgRole::ArgList,
        ];

        priorities.into_iter().find(|&role| {
            self.arg_roles
                .iter()
                .any(|(_, r, is_const)| *r == role && !is_const)
        })
    }
}

/// Analyze a Rust command chain and extract argument roles
///
/// The `command_line` is typically the function start line. This function
/// scans forward to find the actual Command::new callsite.
pub fn analyze_rust_command(
    content: &str,
    command_line: usize,
    _function_name: &str,
) -> Option<SinkSite> {
    // Find the command construction around this line
    let lines: Vec<&str> = content.lines().collect();
    if command_line == 0 || command_line > lines.len() {
        return None;
    }

    // Look for Command::new pattern - scan forward from function start
    // to find the actual callsite (not just check if it exists)
    let start = command_line.saturating_sub(3);
    let end = (command_line + 30).min(lines.len()); // Scan further forward

    // Find the actual line with Command::new
    let mut actual_callsite_line = command_line;
    for i in start..end {
        if i < lines.len() {
            let line_lower = lines[i].to_lowercase();
            if line_lower.contains("command::new") {
                actual_callsite_line = i + 1; // 1-indexed
                break;
            }
        }
    }

    let context: String = lines[start..end].join("\n");
    let context_lower = context.to_lowercase();

    // Check if this is a Command construction
    if !context_lower.contains("command::new") && !context_lower.contains("command::") {
        return None;
    }

    let mut arg_roles = Vec::new();
    let mut is_shell_context = false;
    let mut tainted_param_name = None;

    // Detect program argument (first arg to Command::new)
    if let Some(program_match) = extract_command_new_arg(&context) {
        let is_constant = is_string_literal(&program_match);
        arg_roles.push((0, SinkArgRole::Program, is_constant));

        // If not constant, capture the variable/parameter name
        if !is_constant {
            // Clean up the parameter name (remove references, method calls, etc.)
            let clean_name = program_match
                .trim()
                .trim_start_matches('&')
                .split('.')
                .next()
                .unwrap_or(&program_match)
                .to_string();
            tainted_param_name = Some(clean_name);
        }

        // Check if it's a shell invocation
        let prog_lower = program_match.to_lowercase();
        if prog_lower.contains("sh")
            || prog_lower.contains("bash")
            || prog_lower.contains("cmd")
            || prog_lower.contains("powershell")
        {
            is_shell_context = true;
        }
    }

    // Detect .arg() and .args() calls
    let arg_calls = extract_arg_calls(&context);
    for (idx, arg_value) in arg_calls.iter().enumerate() {
        let is_constant = is_string_literal(arg_value) || is_array_of_literals(arg_value);

        // Check if this is the shell -c argument
        if is_shell_context && (arg_value.contains("-c") || arg_value.contains("/c")) {
            // The NEXT argument after -c is the shell string
            if let Some(next) = arg_calls.get(idx + 1) {
                let next_is_constant = is_string_literal(next);
                arg_roles.push((idx + 2, SinkArgRole::ShellString, next_is_constant));
            }
        }

        arg_roles.push((idx + 1, SinkArgRole::ArgList, is_constant));
    }

    Some(SinkSite {
        file: PathBuf::new(),       // Will be filled by caller
        line: actual_callsite_line, // The actual Command::new call, not function start
        function: String::new(),    // Will be filled by caller
        sink_api: "std::process::Command".to_string(),
        arg_roles,
        is_shell_context,
        tainted_param_name,
    })
}

/// Extract the argument to Command::new(...)
fn extract_command_new_arg(content: &str) -> Option<String> {
    // Simple pattern: Command::new("something") or Command::new(variable)
    let patterns = ["Command::new(", "command::new("];

    for pattern in patterns {
        if let Some(start) = content.find(pattern) {
            let after_paren = &content[start + pattern.len()..];
            if let Some(end) = find_matching_paren(after_paren) {
                return Some(after_paren[..end].trim().to_string());
            }
        }
    }
    None
}

/// Extract all .arg(...) and .args(...) call arguments
fn extract_arg_calls(content: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut remaining = content;

    while let Some(pos) = remaining.find(".arg(").or_else(|| remaining.find(".args(")) {
        let is_args = remaining[pos..].starts_with(".args(");
        let pattern_len = if is_args { 6 } else { 5 };

        let after_paren = &remaining[pos + pattern_len..];
        if let Some(end) = find_matching_paren(after_paren) {
            results.push(after_paren[..end].trim().to_string());
            remaining = &after_paren[end..];
        } else {
            break;
        }
    }

    results
}

/// Find matching closing parenthesis
fn find_matching_paren(s: &str) -> Option<usize> {
    let mut depth = 1;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, c) in s.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '(' if !in_string => depth += 1,
            ')' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Check if a value looks like a string literal
fn is_string_literal(value: &str) -> bool {
    let trimmed = value.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with("r#\"") && trimmed.contains("\"#"))
}

/// Check if a value looks like an array of string literals
fn is_array_of_literals(value: &str) -> bool {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return false;
    }

    // Check if all elements look like string literals
    let inner = &trimmed[1..trimmed.len() - 1];
    inner.split(',').all(|elem| {
        let elem = elem.trim();
        is_string_literal(elem) || elem.is_empty()
    })
}

/// Verdict on whether a sink should generate a finding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkVerdict {
    /// Dangerous: tainted data reaches exploitable role
    Dangerous { role: SinkArgRole, arg_index: usize },
    /// Safe by construction: all dangerous roles are constant
    SafeByConstruction,
    /// Not a sink or couldn't determine
    NotASink,
}

/// Evaluate a command sink site
pub fn evaluate_command_sink(site: &SinkSite) -> SinkVerdict {
    // If in shell context, check ShellString role first
    if site.is_shell_context {
        for (idx, role, is_const) in &site.arg_roles {
            if *role == SinkArgRole::ShellString && !is_const {
                return SinkVerdict::Dangerous {
                    role: SinkArgRole::ShellString,
                    arg_index: *idx,
                };
            }
        }
    }

    // Check Program role
    for (idx, role, is_const) in &site.arg_roles {
        if *role == SinkArgRole::Program && !is_const {
            return SinkVerdict::Dangerous {
                role: SinkArgRole::Program,
                arg_index: *idx,
            };
        }
    }

    // If all dangerous roles are constant, it's safe
    if site.is_safe_by_construction() {
        return SinkVerdict::SafeByConstruction;
    }

    // Check ArgList (lower severity)
    for (idx, role, is_const) in &site.arg_roles {
        if *role == SinkArgRole::ArgList && !is_const {
            return SinkVerdict::Dangerous {
                role: SinkArgRole::ArgList,
                arg_index: *idx,
            };
        }
    }

    SinkVerdict::NotASink
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_string_literal() {
        assert!(is_string_literal("\"hello\""));
        assert!(is_string_literal("'hello'"));
        assert!(is_string_literal("  \"hello\"  "));
        assert!(!is_string_literal("variable"));
        assert!(!is_string_literal("func()"));
    }

    #[test]
    fn test_is_array_of_literals() {
        assert!(is_array_of_literals("[\"a\", \"b\"]"));
        assert!(is_array_of_literals("[\"rev-parse\", \"HEAD\"]"));
        assert!(!is_array_of_literals("[variable]"));
        assert!(!is_array_of_literals("not_array"));
    }

    #[test]
    fn test_constant_command_is_safe() {
        let content = r#"
            let output = std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
        "#;

        let site = analyze_rust_command(content, 2, "from_environment").unwrap();
        assert!(site.is_safe_by_construction());
        assert_eq!(
            evaluate_command_sink(&site),
            SinkVerdict::SafeByConstruction
        );
    }

    #[test]
    fn test_shell_invocation_detected() {
        let content = r#"
            Command::new("sh")
                .arg("-c")
                .arg(user_input)
        "#;

        let site = analyze_rust_command(content, 2, "test").unwrap();
        assert!(site.is_shell_context);
    }

    #[test]
    fn test_tainted_program() {
        let content = r#"
            Command::new(user_provided_binary)
                .args(["--version"])
        "#;

        let site = analyze_rust_command(content, 2, "test").unwrap();
        assert!(!site.is_safe_by_construction());

        match evaluate_command_sink(&site) {
            SinkVerdict::Dangerous {
                role: SinkArgRole::Program,
                ..
            } => {}
            _ => panic!("Expected Program role to be dangerous"),
        }
    }
}
