//! XSS Detection using Taint Tracking
//!
//! This module implements Cross-Site Scripting (XSS) detection by tracking
//! the flow of user-controlled data to dangerous DOM sinks.
//!
//! Detection Strategy:
//! 1. Identify taint sources (user input, URL data, storage)
//! 2. Track taint propagation through assignments and function calls
//! 3. Detect when tainted data reaches XSS sinks
//! 4. Account for sanitization functions that break the taint chain
//! 5. Classify XSS type (reflected, stored, DOM-based)

use crate::flow::{FlowContext, TaintKind, TaintLevel};
use crate::rules::{Rule, create_finding_at_line};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

// =============================================================================
// XSS Types and Configuration
// =============================================================================

/// XSS source type - determines whether XSS is reflected, stored, or DOM-based
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XssSourceType {
    /// Reflected XSS: input comes from URL (query params, hash, etc.)
    Reflected,
    /// Stored XSS: input comes from database/storage
    Stored,
    /// DOM-based XSS: input comes from DOM APIs
    DomBased,
    /// Server-side: input comes from request body/form
    ServerSide,
}

impl XssSourceType {
    /// Infer XSS source type from the taint source name
    pub fn from_source_name(name: &str) -> Self {
        let lower = name.to_lowercase();

        // URL-based sources (Reflected XSS)
        if lower.contains("location")
            || lower.contains("url")
            || lower.contains("search")
            || lower.contains("hash")
            || lower.contains("query")
            || lower.contains("referrer")
        {
            return XssSourceType::Reflected;
        }

        // Storage-based sources (Stored XSS)
        if lower.contains("storage")
            || lower.contains("cookie")
            || lower.contains("database")
            || lower.contains("db")
            || lower.contains("cache")
        {
            return XssSourceType::Stored;
        }

        // DOM-based sources
        if lower.contains("innerhtml")
            || lower.contains("innertext")
            || lower.contains("textcontent")
            || lower.contains("getelementby")
            || lower.contains("queryselector")
        {
            return XssSourceType::DomBased;
        }

        // Server-side sources
        if lower.contains("body")
            || lower.contains("form")
            || lower.contains("param")
            || lower.contains("args")
            || lower.contains("request")
        {
            return XssSourceType::ServerSide;
        }

        // Default to reflected (most common)
        XssSourceType::Reflected
    }

    /// Get severity based on XSS type
    pub fn severity(&self) -> Severity {
        match self {
            XssSourceType::Stored => Severity::Critical, // Stored XSS is most dangerous
            XssSourceType::Reflected => Severity::Error, // Reflected XSS is high severity
            XssSourceType::DomBased => Severity::Error,  // DOM XSS is high severity
            XssSourceType::ServerSide => Severity::Error, // Server XSS is high severity
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            XssSourceType::Stored => "Stored XSS",
            XssSourceType::Reflected => "Reflected XSS",
            XssSourceType::DomBased => "DOM-based XSS",
            XssSourceType::ServerSide => "Server-side XSS",
        }
    }
}

// =============================================================================
// XSS Detection Rule
// =============================================================================

/// XSS Detection Rule using taint tracking
///
/// This rule detects Cross-Site Scripting (XSS) vulnerabilities by tracking
/// the flow of user-controlled data to dangerous DOM sinks.
pub struct XssDetectionRule;

impl XssDetectionRule {
    // JavaScript/TypeScript property sinks (assignments)
    const JS_PROP_SINKS: &'static [&'static str] = &["innerHTML", "outerHTML"];

    // JavaScript/TypeScript function sinks
    const JS_FUNC_SINKS: &'static [&'static str] =
        &["document.write", "document.writeln", "insertAdjacentHTML"];

    // React JSX attribute sink name
    const REACT_DANGEROUS_ATTR: &'static str = "dangerouslySetInnerHTML";

    // JavaScript/TypeScript XSS sources
    const JS_SOURCES: &'static [&'static str] = &[
        // URL-based (Reflected XSS)
        "location.search",
        "location.hash",
        "location.href",
        "location.pathname",
        "document.URL",
        "document.documentURI",
        "document.referrer",
        "window.location",
        // Request-based (Express/Node)
        "req.query",
        "req.body",
        "req.params",
        "req.headers",
        "request.query",
        "request.body",
        // Storage-based (Stored XSS)
        "localStorage.getItem",
        "sessionStorage.getItem",
        "document.cookie",
        // User input
        "prompt",
        "URLSearchParams",
        // WebSocket/PostMessage
        "event.data",
        "message.data",
    ];

    // Python XSS sinks
    const PYTHON_SINKS: &'static [&'static str] = &["mark_safe", "SafeString", "Markup"];

    // Python XSS sources
    const PYTHON_SOURCES: &'static [&'static str] = &[
        // Flask
        "request.args",
        "request.form",
        "request.values",
        "request.data",
        "request.json",
        "request.cookies",
        "request.headers",
        // Django
        "request.GET",
        "request.POST",
        "request.COOKIES",
        "request.META",
    ];

    // Java XSS sinks (Thymeleaf, JSP)
    const JAVA_SINKS: &'static [&'static str] = &[
        "th:utext",
        "response.getWriter().print",
        "response.getWriter().write",
        "out.print",
    ];

    // Java XSS sources
    #[allow(dead_code)]
    const JAVA_SOURCES: &'static [&'static str] = &[
        "request.getParameter",
        "request.getParameterValues",
        "request.getQueryString",
        "request.getHeader",
        "request.getCookies",
    ];

    // Sanitizers (cross-language)
    const SANITIZERS: &'static [&'static str] = &[
        "DOMPurify.sanitize",
        "sanitize",
        "sanitizeHtml",
        "encodeURIComponent",
        "encodeURI",
        "escape",
        "validator.escape",
        "he.encode",
        "entities.encode",
        "createTextNode",
        "React.createElement",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "cgi.escape",
        "StringEscapeUtils.escapeHtml4",
        "HtmlUtils.htmlEscape",
        "ESAPI.encoder().encodeForHTML",
        "Encode.forHtml",
    ];

    /// Create a new XSS detection rule
    pub fn new() -> Self {
        Self
    }

    /// Check if a function/method name is a sanitizer
    fn is_sanitizer(name: &str) -> bool {
        Self::SANITIZERS
            .iter()
            .any(|s| name == *s || name.contains(s) || name.ends_with(s))
    }

    /// Check if a variable name indicates it's been sanitized
    fn is_likely_sanitized_var(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("safe")
            || lower.contains("sanitized")
            || lower.contains("escaped")
            || lower.contains("encoded")
            || lower.contains("clean")
    }

    /// Check for XSS sinks in JavaScript/TypeScript code
    fn check_js_xss(&self, parsed: &ParsedFile, flow: &FlowContext, findings: &mut Vec<Finding>) {
        let mut cursor = parsed.tree.walk();
        self.walk_js_xss(&mut cursor, parsed, flow, findings);
    }

    /// Walk AST looking for JavaScript XSS sinks
    fn walk_js_xss(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        parsed: &ParsedFile,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
    ) {
        loop {
            let node = cursor.node();

            // Check for property assignments (innerHTML, outerHTML)
            if node.kind() == "assignment_expression" {
                self.check_js_property_sink(node, parsed, flow, findings);
            }

            // Check for function calls (document.write, insertAdjacentHTML)
            if node.kind() == "call_expression" {
                self.check_js_function_sink(node, parsed, flow, findings);
            }

            // Check for JSX attributes (React dangerous attribute)
            if node.kind() == "jsx_attribute" {
                self.check_jsx_dangerous(node, parsed, flow, findings);
            }

            // Recurse
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    /// Check property assignments for XSS sinks
    fn check_js_property_sink(
        &self,
        node: Node,
        parsed: &ParsedFile,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
    ) {
        let left = match node.child_by_field_name("left") {
            Some(l) => l,
            None => return,
        };

        // Check if it's a member expression (obj.property = value)
        if left.kind() != "member_expression" {
            return;
        }

        // Get the property name
        let property = match left.child_by_field_name("property") {
            Some(p) => p,
            None => return,
        };

        let prop_name = match property.utf8_text(parsed.content.as_bytes()) {
            Ok(name) => name,
            Err(_) => return,
        };

        // Check if it's a known XSS sink property
        if !Self::JS_PROP_SINKS.contains(&prop_name) {
            return;
        }

        // Get the value being assigned
        let right = match node.child_by_field_name("right") {
            Some(r) => r,
            None => return,
        };

        // Check if the value is tainted
        if let Some((source, xss_type, partial)) = self.check_tainted_expr(right, parsed, flow) {
            self.emit_xss_finding(
                findings,
                parsed,
                &source,
                prop_name,
                right.start_position().row + 1,
                xss_type,
                partial,
            );
        }
    }

    /// Check function calls for XSS sinks
    fn check_js_function_sink(
        &self,
        node: Node,
        parsed: &ParsedFile,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
    ) {
        let func = match node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };

        let func_text = match func.utf8_text(parsed.content.as_bytes()) {
            Ok(text) => text,
            Err(_) => return,
        };

        // Check if it's a known XSS sink function
        let is_sink = Self::JS_FUNC_SINKS
            .iter()
            .any(|s| func_text.contains(s) || func_text.ends_with(s));

        if !is_sink {
            return;
        }

        // Get arguments
        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Check each argument for taint
        let mut child_cursor = args.walk();
        for arg in args.named_children(&mut child_cursor) {
            if let Some((source, xss_type, partial)) = self.check_tainted_expr(arg, parsed, flow) {
                self.emit_xss_finding(
                    findings,
                    parsed,
                    &source,
                    func_text,
                    arg.start_position().row + 1,
                    xss_type,
                    partial,
                );
                break; // Report only one vulnerability per call
            }
        }
    }

    /// Check JSX attributes for XSS sinks (React)
    fn check_jsx_dangerous(
        &self,
        node: Node,
        parsed: &ParsedFile,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
    ) {
        // Get attribute name
        let name_node = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return,
        };

        let attr_name = match name_node.utf8_text(parsed.content.as_bytes()) {
            Ok(name) => name,
            Err(_) => return,
        };

        // Check for React dangerous attribute
        if attr_name != Self::REACT_DANGEROUS_ATTR {
            return;
        }

        // Get the value
        let value = match node.child_by_field_name("value") {
            Some(v) => v,
            None => return,
        };

        if let Some((source, xss_type, partial)) = self.check_tainted_expr(value, parsed, flow) {
            self.emit_xss_finding(
                findings,
                parsed,
                &source,
                attr_name,
                value.start_position().row + 1,
                xss_type,
                partial,
            );
        }
    }

    /// Check if an expression contains tainted data
    /// Returns (source_name, xss_type, is_partial_sanitization)
    fn check_tainted_expr(
        &self,
        node: Node,
        parsed: &ParsedFile,
        flow: &FlowContext,
    ) -> Option<(String, XssSourceType, bool)> {
        // Extract variable names from the expression
        let var_names = self.collect_identifiers(node, parsed);

        for var_name in &var_names {
            // Skip if the variable name suggests sanitization
            if Self::is_likely_sanitized_var(var_name) {
                continue;
            }

            // Check taint status
            if flow.is_tainted(var_name) {
                let taint_level = flow.taint_level_at(var_name, node.id());

                // Only report if tainted on all paths or partially tainted
                if taint_level == TaintLevel::Clean {
                    continue;
                }

                let xss_type = XssSourceType::from_source_name(var_name);
                let is_partial = taint_level == TaintLevel::Partial;

                return Some((var_name.clone(), xss_type, is_partial));
            }
        }

        // Check for direct taint sources in the value
        let value_text = node.utf8_text(parsed.content.as_bytes()).ok()?;

        // Check for direct use of known XSS sources
        for source in Self::JS_SOURCES {
            if value_text.contains(source) {
                return Some((
                    source.to_string(),
                    XssSourceType::from_source_name(source),
                    false,
                ));
            }
        }

        None
    }

    /// Recursively collect identifier names from an expression
    fn collect_identifiers(&self, node: Node, parsed: &ParsedFile) -> Vec<String> {
        let mut names = Vec::new();
        self.collect_ids_recursive(node, parsed, &mut names);
        names
    }

    fn collect_ids_recursive(&self, node: Node, parsed: &ParsedFile, names: &mut Vec<String>) {
        if node.kind() == "identifier" {
            if let Ok(name) = node.utf8_text(parsed.content.as_bytes()) {
                names.push(name.to_string());
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_ids_recursive(child, parsed, names);
        }
    }

    /// Check for Python XSS vulnerabilities
    fn check_python_xss(
        &self,
        parsed: &ParsedFile,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
    ) {
        let content = &parsed.content;

        // Check for mark_safe() with tainted data
        if content.contains("mark_safe")
            || content.contains("Markup")
            || content.contains("SafeString")
        {
            let mut cursor = parsed.tree.walk();
            self.walk_python_xss(&mut cursor, parsed, flow, findings);
        }

        // Check for |safe filter in templates (if embedded)
        if content.contains("|safe") || content.contains("autoescape off") {
            // Flag as potential issue (template analysis is limited)
            let line = content
                .lines()
                .enumerate()
                .find(|(_, line)| line.contains("|safe") || line.contains("autoescape off"))
                .map(|(i, _)| i + 1)
                .unwrap_or(1);

            self.emit_xss_finding(
                findings,
                parsed,
                "template_variable",
                "|safe filter",
                line,
                XssSourceType::ServerSide,
                false,
            );
        }
    }

    /// Walk Python AST for XSS sinks
    fn walk_python_xss(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        parsed: &ParsedFile,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
    ) {
        loop {
            let node = cursor.node();

            if node.kind() == "call" {
                self.check_python_sink(node, parsed, flow, findings);
            }

            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    /// Check Python function calls for XSS sinks
    fn check_python_sink(
        &self,
        node: Node,
        parsed: &ParsedFile,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
    ) {
        let func = match node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };

        let func_text = match func.utf8_text(parsed.content.as_bytes()) {
            Ok(text) => text,
            Err(_) => return,
        };

        // Check for mark_safe, SafeString, Markup
        let is_xss_sink = Self::PYTHON_SINKS
            .iter()
            .any(|s| func_text == *s || func_text.ends_with(s));

        if !is_xss_sink {
            return;
        }

        // Get arguments
        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        let mut child_cursor = args.walk();
        for arg in args.named_children(&mut child_cursor) {
            let var_names = self.collect_identifiers(arg, parsed);

            for var_name in &var_names {
                if flow.is_tainted(var_name) {
                    self.emit_xss_finding(
                        findings,
                        parsed,
                        var_name,
                        func_text,
                        node.start_position().row + 1,
                        XssSourceType::ServerSide,
                        false,
                    );
                    return;
                }
            }

            // Check for direct Python XSS sources
            if let Ok(arg_text) = arg.utf8_text(parsed.content.as_bytes()) {
                for source in Self::PYTHON_SOURCES {
                    if arg_text.contains(source) {
                        self.emit_xss_finding(
                            findings,
                            parsed,
                            source,
                            func_text,
                            node.start_position().row + 1,
                            XssSourceType::ServerSide,
                            false,
                        );
                        return;
                    }
                }
            }
        }
    }

    /// Check for interprocedural XSS flows
    fn check_interprocedural_xss(
        &self,
        flow: &FlowContext,
        findings: &mut Vec<Finding>,
        parsed: &ParsedFile,
    ) {
        if let Some(interproc) = flow.interprocedural_result() {
            for taint_flow in interproc.get_flows() {
                // Check if sink is an XSS sink
                let is_xss_sink = taint_flow.sink.kind == TaintKind::Html
                    || self.is_xss_sink_name(&taint_flow.sink.name);

                if is_xss_sink {
                    let xss_type = XssSourceType::from_source_name(&taint_flow.source.name);

                    let msg = format!(
                        "{}: Tainted data from '{}' (line {}) flows to XSS sink '{}' (line {}) across functions: {}",
                        xss_type.description(),
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        taint_flow.functions_involved.join(" -> ")
                    );

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        xss_type.severity(),
                        &msg,
                        parsed.language,
                    );
                    finding.confidence = Confidence::Medium;
                    finding.suggestion = Some(self.get_suggestion(xss_type));
                    findings.push(finding);
                }
            }
        }
    }

    /// Check if a name is a known XSS sink
    fn is_xss_sink_name(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("innerhtml")
            || lower.contains("outerhtml")
            || lower.contains("document.write")
            || lower.contains("insertadjacenthtml")
            || lower.contains("dangerouslysetinnerhtml")
            || lower.contains("mark_safe")
            || lower.contains("th:utext")
    }

    /// Emit an XSS finding
    fn emit_xss_finding(
        &self,
        findings: &mut Vec<Finding>,
        parsed: &ParsedFile,
        source: &str,
        sink: &str,
        line: usize,
        xss_type: XssSourceType,
        partial: bool,
    ) {
        let msg = format!(
            "{}: User-controlled data from '{}' flows to XSS sink '{}' without sanitization",
            xss_type.description(),
            source,
            sink
        );

        let confidence = if partial {
            Confidence::Low
        } else {
            Confidence::High
        };

        let mut finding = create_finding_at_line(
            self.id(),
            &parsed.path,
            line,
            sink,
            xss_type.severity(),
            &msg,
            parsed.language,
        );
        finding.confidence = confidence;
        finding.suggestion = Some(self.get_suggestion(xss_type));
        findings.push(finding);
    }

    /// Get remediation suggestion based on XSS type
    fn get_suggestion(&self, xss_type: XssSourceType) -> String {
        match xss_type {
            XssSourceType::Reflected | XssSourceType::DomBased => {
                "Use DOMPurify.sanitize() or textContent for safe DOM manipulation".to_string()
            }
            XssSourceType::Stored => {
                "Sanitize data before storage AND before rendering. Use DOMPurify.sanitize()"
                    .to_string()
            }
            XssSourceType::ServerSide => {
                "Use framework auto-escaping or html.escape(). Avoid mark_safe() with user input"
                    .to_string()
            }
        }
    }
}

impl Default for XssDetectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for XssDetectionRule {
    fn id(&self) -> &str {
        "security/xss-taint-flow"
    }

    fn description(&self) -> &str {
        "Detects Cross-Site Scripting (XSS) vulnerabilities using taint tracking"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript | Language::TypeScript | Language::Python | Language::Java
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // XSS detection requires flow analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip test files
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return findings;
        }

        // Check based on language
        match parsed.language {
            Language::JavaScript | Language::TypeScript => {
                self.check_js_xss(parsed, flow, &mut findings);
            }
            Language::Python => {
                self.check_python_xss(parsed, flow, &mut findings);
            }
            _ => {}
        }

        // Also check interprocedural flows
        self.check_interprocedural_xss(flow, &mut findings, parsed);

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xss_source_type_inference() {
        assert_eq!(
            XssSourceType::from_source_name("location.search"),
            XssSourceType::Reflected
        );
        assert_eq!(
            XssSourceType::from_source_name("document.URL"),
            XssSourceType::Reflected
        );
        assert_eq!(
            XssSourceType::from_source_name("localStorage.getItem"),
            XssSourceType::Stored
        );
        assert_eq!(
            XssSourceType::from_source_name("document.cookie"),
            XssSourceType::Stored
        );
        assert_eq!(
            XssSourceType::from_source_name("req.body"),
            XssSourceType::ServerSide
        );
        assert_eq!(
            XssSourceType::from_source_name("request.form"),
            XssSourceType::ServerSide
        );
    }

    #[test]
    fn test_xss_severity() {
        assert_eq!(XssSourceType::Stored.severity(), Severity::Critical);
        assert_eq!(XssSourceType::Reflected.severity(), Severity::Error);
        assert_eq!(XssSourceType::DomBased.severity(), Severity::Error);
        assert_eq!(XssSourceType::ServerSide.severity(), Severity::Error);
    }

    #[test]
    fn test_sanitizer_detection() {
        assert!(XssDetectionRule::is_sanitizer("DOMPurify.sanitize"));
        assert!(XssDetectionRule::is_sanitizer("sanitize"));
        assert!(XssDetectionRule::is_sanitizer("html.escape"));
        assert!(XssDetectionRule::is_sanitizer("encodeURIComponent"));
        assert!(!XssDetectionRule::is_sanitizer("innerHTML"));
        assert!(!XssDetectionRule::is_sanitizer("document.write"));
    }

    #[test]
    fn test_sanitized_var_detection() {
        assert!(XssDetectionRule::is_likely_sanitized_var("safeHtml"));
        assert!(XssDetectionRule::is_likely_sanitized_var("sanitizedInput"));
        assert!(XssDetectionRule::is_likely_sanitized_var("escapedValue"));
        assert!(XssDetectionRule::is_likely_sanitized_var("encodedData"));
        assert!(!XssDetectionRule::is_likely_sanitized_var("userInput"));
        assert!(!XssDetectionRule::is_likely_sanitized_var("rawData"));
    }

    #[test]
    fn test_rule_metadata() {
        let rule = XssDetectionRule::new();
        assert_eq!(rule.id(), "security/xss-taint-flow");
        assert!(rule.applies_to(Language::JavaScript));
        assert!(rule.applies_to(Language::TypeScript));
        assert!(rule.applies_to(Language::Python));
        assert!(rule.applies_to(Language::Java));
        assert!(!rule.applies_to(Language::Rust));
        assert!(rule.uses_flow());
    }
}
