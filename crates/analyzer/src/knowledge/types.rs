//! Core types for framework knowledge profiles
//!
//! This module defines the types used to describe framework-specific
//! security patterns including sources, sinks, sanitizers, and dangerous patterns.

use rma_common::Severity;
use std::borrow::Cow;

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
