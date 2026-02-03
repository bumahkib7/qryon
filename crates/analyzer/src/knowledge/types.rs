//! Core types for framework knowledge profiles
//!
//! This module defines the types used to describe framework-specific
//! security patterns including sources, sinks, sanitizers, and dangerous patterns.

use rma_common::Severity;
use std::borrow::Cow;

// ============================================================================
// Context-Aware Sink Analysis Types
// ============================================================================

/// The security context where a sink is used.
///
/// Different contexts require different sanitization strategies:
/// - HTML contexts need HTML encoding
/// - URL contexts need URL encoding
/// - SQL contexts need parameterization or escaping
/// - Command contexts need shell escaping or argument separation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkContext {
    /// Plain text content in HTML (between tags) - needs HTML entity encoding
    HtmlText,

    /// HTML attribute value - needs attribute encoding (quotes, entities)
    HtmlAttribute,

    /// Raw/unescaped HTML injection - extremely dangerous, no safe sanitization
    HtmlRaw,

    /// JavaScript code context - needs JS string escaping or CSP
    JavaScript,

    /// URL context (redirects, hrefs, fetch URLs) - needs URL validation/encoding
    Url,

    /// SQL query context - needs parameterization (escaping is risky)
    Sql,

    /// OS command execution - base context for all command sinks
    Command,

    /// Shell string execution - sh -c, cmd /c, system(), backticks
    /// Most dangerous - shell interprets the string
    CommandShell,

    /// Exec with args list - Command::new().args(), spawn with array
    /// Safe if binary is constant; validate args for flags/options
    CommandExecArgs,

    /// Binary path from tainted input - Command::new(user_input)
    /// Very dangerous - attacker chooses what to execute
    CommandBinaryTaint,

    /// Template engine context - depends on engine's auto-escaping
    Template,

    /// File path context - path traversal, file operations
    /// Needs path canonicalization, base directory restriction
    FilePath,

    /// Context couldn't be determined
    Unknown,
}

impl SinkContext {
    /// Returns true if this context has any known safe sanitization
    pub fn has_safe_sanitization(&self) -> bool {
        match self {
            SinkContext::HtmlText | SinkContext::HtmlAttribute => true,
            SinkContext::Url => true,
            SinkContext::Sql => true,
            SinkContext::Command | SinkContext::CommandExecArgs => true,
            SinkContext::Template => true,
            SinkContext::FilePath => true, // Can be sanitized with canonicalization + base dir check
            SinkContext::HtmlRaw => false,
            SinkContext::JavaScript => false,
            SinkContext::CommandShell => false, // Shell strings are inherently risky
            SinkContext::CommandBinaryTaint => false, // Can't sanitize binary path choice
            SinkContext::Unknown => false,
        }
    }

    /// Returns the CWE ID most associated with this context
    pub fn primary_cwe(&self) -> &'static str {
        match self {
            SinkContext::HtmlText | SinkContext::HtmlAttribute | SinkContext::HtmlRaw => "CWE-79",
            SinkContext::JavaScript => "CWE-79",
            SinkContext::Url => "CWE-601",
            SinkContext::Sql => "CWE-89",
            SinkContext::Command
            | SinkContext::CommandShell
            | SinkContext::CommandExecArgs
            | SinkContext::CommandBinaryTaint => "CWE-78",
            SinkContext::Template => "CWE-1336", // SSTI - more precise than CWE-94
            SinkContext::FilePath => "CWE-22",   // Path Traversal
            SinkContext::Unknown => "CWE-74",
        }
    }

    /// Returns a human-readable description for findings
    pub fn description(&self) -> &'static str {
        match self {
            SinkContext::HtmlText => "HTML text content",
            SinkContext::HtmlAttribute => "HTML attribute value",
            SinkContext::HtmlRaw => "raw/unescaped HTML",
            SinkContext::JavaScript => "JavaScript code",
            SinkContext::Url => "URL/redirect target",
            SinkContext::Sql => "SQL query",
            SinkContext::Command => "OS command",
            SinkContext::CommandShell => "shell string execution",
            SinkContext::CommandExecArgs => "command with args array",
            SinkContext::CommandBinaryTaint => "tainted binary path",
            SinkContext::Template => "server-side template",
            SinkContext::FilePath => "file path operation",
            SinkContext::Unknown => "unknown context",
        }
    }

    /// Returns true if this is a command-related context
    pub fn is_command(&self) -> bool {
        matches!(
            self,
            SinkContext::Command
                | SinkContext::CommandShell
                | SinkContext::CommandExecArgs
                | SinkContext::CommandBinaryTaint
        )
    }
}

/// A context-aware sink definition that links sinks to specific contexts
#[derive(Debug, Clone)]
pub struct ContextualSinkDef {
    /// The base sink definition
    pub base: SinkDef,

    /// The security context this sink operates in
    pub context: SinkContext,

    /// Sanitizers that are effective for this specific context
    /// e.g., ["html_escape", "encode_entities"] for HtmlText
    pub effective_sanitizers: &'static [&'static str],

    /// Taint kinds that are dangerous in this context (empty = all dangerous)
    /// Uses string labels matching flow::TaintKind variant names
    pub dangerous_taint_labels: &'static [&'static str],
}

/// Effect of a sanitizer - what it cleans and in what contexts
#[derive(Debug, Clone)]
pub struct SanitizerEffect {
    /// The base sanitizer definition
    pub base: SanitizerDef,

    /// Contexts where this sanitizer is effective
    pub effective_contexts: &'static [SinkContext],

    /// Taint labels this sanitizer clears (empty = all)
    pub clears_taint_labels: &'static [&'static str],

    /// Whether this sanitizer is considered complete (vs partial mitigation)
    pub is_complete: bool,
}

impl ContextualSinkDef {
    /// Check if a taint label is dangerous for this sink
    pub fn is_dangerous_taint_label(&self, label: &str) -> bool {
        if self.dangerous_taint_labels.is_empty() {
            return true; // All taint is dangerous if not specified
        }
        self.dangerous_taint_labels
            .iter()
            .any(|l| label.eq_ignore_ascii_case(l) || label.contains(l))
    }

    /// Check if a sanitizer name is effective for this sink
    pub fn is_sanitizer_effective(&self, sanitizer_name: &str) -> bool {
        self.effective_sanitizers.iter().any(|s| {
            let s_lower = s.to_lowercase();
            let name_lower = sanitizer_name.to_lowercase();
            name_lower.contains(&s_lower) || s_lower.contains(&name_lower)
        })
    }
}

/// A framework profile containing security-relevant knowledge
#[derive(Debug, Clone)]
pub struct FrameworkProfile {
    /// Framework name (e.g., "actix-web", "axum", "rocket")
    pub name: &'static str,

    /// Framework description
    pub description: &'static str,

    /// Import patterns that indicate this framework is in use
    /// Matched against `use` statements in Rust files
    pub detect_imports: &'static [&'static str],

    /// Taint sources - where untrusted data enters
    pub sources: &'static [SourceDef],

    /// Taint sinks - dangerous operations where tainted data should not flow
    pub sinks: &'static [SinkDef],

    /// Sanitizers - functions that neutralize tainted data
    pub sanitizers: &'static [SanitizerDef],

    /// Safe patterns - APIs that are inherently safe (e.g., parameterized queries)
    pub safe_patterns: &'static [SafePattern],

    /// Dangerous patterns - code patterns that indicate potential issues
    pub dangerous_patterns: &'static [DangerousPattern],

    /// Resource types that need proper lifecycle management (RAII)
    pub resource_types: &'static [ResourceType],
}

/// Definition of a taint source
#[derive(Debug, Clone)]
pub struct SourceDef {
    /// Source name for identification
    pub name: &'static str,

    /// Pattern to match (function call, member access, etc.)
    pub pattern: SourceKind,

    /// Label describing what kind of data this is
    pub taint_label: &'static str,

    /// Description for documentation/reporting
    pub description: &'static str,
}

/// Kind of taint source
#[derive(Debug, Clone)]
pub enum SourceKind {
    /// Function or method call (e.g., "env::var", "web::Query::into_inner")
    FunctionCall(&'static str),

    /// Member/field access (e.g., "req.query", "HttpRequest.path")
    MemberAccess(&'static str),

    /// Type extraction (e.g., extracting from web::Path<T>)
    TypeExtractor(&'static str),

    /// Method on a type (e.g., ".headers()" on HttpRequest)
    MethodOnType {
        type_pattern: &'static str,
        method: &'static str,
    },

    /// Any function parameter (conservative)
    Parameter,
}

/// Definition of a taint sink
#[derive(Debug, Clone)]
pub struct SinkDef {
    /// Sink name for identification
    pub name: &'static str,

    /// Pattern to match
    pub pattern: SinkKind,

    /// Rule ID to associate with findings
    pub rule_id: &'static str,

    /// Severity when tainted data flows to this sink
    pub severity: Severity,

    /// Description for documentation/reporting
    pub description: &'static str,

    /// CWE ID if applicable
    pub cwe: Option<&'static str>,
}

/// Kind of taint sink
#[derive(Debug, Clone)]
pub enum SinkKind {
    /// Function call sink (e.g., "Command::new", "execute")
    FunctionCall(&'static str),

    /// Method call on tainted receiver (e.g., ".arg()" when tainted)
    MethodCall(&'static str),

    /// Property/field assignment
    PropertyAssignment(&'static str),

    /// Macro invocation (e.g., "format!" in SQL context)
    MacroInvocation(&'static str),

    /// Template string with tainted interpolation
    TemplateInsertion,

    /// Response body with tainted content
    ResponseBody(&'static str),
}

/// Definition of a sanitizer
#[derive(Debug, Clone)]
pub struct SanitizerDef {
    /// Sanitizer name
    pub name: &'static str,

    /// Pattern to match
    pub pattern: SanitizerKind,

    /// What kind of taint this sanitizes (e.g., "html", "sql", "shell")
    pub sanitizes: &'static str,

    /// Description
    pub description: &'static str,
}

/// Kind of sanitizer
#[derive(Debug, Clone)]
pub enum SanitizerKind {
    /// Function that returns sanitized value
    Function(&'static str),

    /// Method call that returns sanitized value
    MethodCall(&'static str),

    /// Macro that produces safe output (e.g., "html!" in maud)
    Macro(&'static str),

    /// Auto-escaping template engine
    TemplateEngine(&'static str),
}

/// A pattern that is known to be safe
#[derive(Debug, Clone)]
pub struct SafePattern {
    /// Pattern name
    pub name: &'static str,

    /// Pattern to match
    pub pattern: &'static str,

    /// Why this is safe
    pub reason: &'static str,
}

/// A dangerous code pattern (not necessarily involving taint)
#[derive(Debug, Clone)]
pub struct DangerousPattern {
    /// Pattern name
    pub name: &'static str,

    /// Pattern to detect (regex-like description or AST pattern)
    pub pattern: PatternKind,

    /// Rule ID for findings
    pub rule_id: &'static str,

    /// Severity
    pub severity: Severity,

    /// Description
    pub description: &'static str,

    /// CWE ID if applicable
    pub cwe: Option<&'static str>,
}

/// Kind of dangerous pattern
#[derive(Debug, Clone)]
pub enum PatternKind {
    /// Regex pattern to match in source code
    Regex(&'static str),

    /// Method call pattern (e.g., ".unwrap()" on I/O Result)
    MethodCall(&'static str),

    /// AST node kind to look for
    AstNodeKind(&'static str),

    /// Specific code construct
    Construct(&'static str),

    /// Missing expected element (e.g., missing safety comment on unsafe)
    Missing(&'static str),
}

/// Resource type that needs lifecycle management
#[derive(Debug, Clone)]
pub struct ResourceType {
    /// Type name (e.g., "File", "MutexGuard", "Connection")
    pub name: &'static str,

    /// How the resource is acquired
    pub acquire_pattern: &'static str,

    /// How the resource should be released (or "Drop" for RAII)
    pub release_pattern: &'static str,

    /// What happens if not properly released
    pub leak_consequence: &'static str,
}

impl FrameworkProfile {
    /// Check if a source file appears to use this framework
    pub fn is_active(&self, content: &str) -> bool {
        self.detect_imports
            .iter()
            .any(|pattern| content.contains(pattern))
    }

    /// Get all source patterns as strings for quick matching
    pub fn source_patterns(&self) -> Vec<Cow<'static, str>> {
        self.sources
            .iter()
            .filter_map(|s| match &s.pattern {
                SourceKind::FunctionCall(p) => Some(Cow::Borrowed(*p)),
                SourceKind::MemberAccess(p) => Some(Cow::Borrowed(*p)),
                SourceKind::TypeExtractor(p) => Some(Cow::Borrowed(*p)),
                SourceKind::MethodOnType { method, .. } => Some(Cow::Borrowed(*method)),
                SourceKind::Parameter => None,
            })
            .collect()
    }

    /// Get all sink patterns as strings for quick matching
    pub fn sink_patterns(&self) -> Vec<Cow<'static, str>> {
        self.sinks
            .iter()
            .filter_map(|s| match &s.pattern {
                SinkKind::FunctionCall(p) => Some(Cow::Borrowed(*p)),
                SinkKind::MethodCall(p) => Some(Cow::Borrowed(*p)),
                SinkKind::MacroInvocation(p) => Some(Cow::Borrowed(*p)),
                SinkKind::ResponseBody(p) => Some(Cow::Borrowed(*p)),
                _ => None,
            })
            .collect()
    }

    /// Get all sanitizer patterns as strings for quick matching
    pub fn sanitizer_patterns(&self) -> Vec<Cow<'static, str>> {
        self.sanitizers
            .iter()
            .filter_map(|s| match &s.pattern {
                SanitizerKind::Function(p) => Some(Cow::Borrowed(*p)),
                SanitizerKind::MethodCall(p) => Some(Cow::Borrowed(*p)),
                SanitizerKind::Macro(p) => Some(Cow::Borrowed(*p)),
                SanitizerKind::TemplateEngine(p) => Some(Cow::Borrowed(*p)),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_detection() {
        let profile = FrameworkProfile {
            name: "test",
            description: "Test framework",
            detect_imports: &["test_framework::"],
            sources: &[],
            sinks: &[],
            sanitizers: &[],
            safe_patterns: &[],
            dangerous_patterns: &[],
            resource_types: &[],
        };

        assert!(profile.is_active("use test_framework::App;"));
        assert!(!profile.is_active("use other_framework::App;"));
    }
}
