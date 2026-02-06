//! Function Security Classifier
//!
//! Analyzes function bodies to classify them as sources, sinks, or sanitizers
//! using the knowledge system. This is language-agnostic and thread-safe.

use super::{FunctionClassification, SinkClassification, SourceClassification};
use crate::knowledge::{KnowledgeBuilder, MergedKnowledge};
use rayon::prelude::*;
use rma_common::Language;
use rma_parser::ParsedFile;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::Node;

/// Thread-safe classifier that uses pre-built knowledge bases
pub struct FunctionClassifier {
    /// Pre-built knowledge bases per language (thread-safe)
    knowledge_cache: HashMap<Language, Arc<MergedKnowledge>>,
}

impl FunctionClassifier {
    /// Create a new classifier
    pub fn new() -> Self {
        Self {
            knowledge_cache: HashMap::new(),
        }
    }

    /// Create classifier with pre-built knowledge for specific languages
    pub fn with_languages(languages: &[Language]) -> Self {
        let knowledge_cache: HashMap<Language, Arc<MergedKnowledge>> = languages
            .par_iter()
            .filter(|lang| **lang != Language::Unknown)
            .map(|&lang| {
                let knowledge = KnowledgeBuilder::new(lang).all_profiles();
                (lang, Arc::new(knowledge))
            })
            .collect();

        Self { knowledge_cache }
    }

    /// Get or build knowledge for a language
    fn get_knowledge(&mut self, language: Language) -> Arc<MergedKnowledge> {
        self.knowledge_cache
            .entry(language)
            .or_insert_with(|| Arc::new(KnowledgeBuilder::new(language).all_profiles()))
            .clone()
    }

    /// Get knowledge without mutating (for parallel access)
    fn get_knowledge_readonly(&self, language: Language) -> Option<&Arc<MergedKnowledge>> {
        self.knowledge_cache.get(&language)
    }

    /// Classify a function by analyzing its body
    pub fn classify_function(
        &mut self,
        parsed_file: &ParsedFile,
        func_node: Node,
        func_name: &str,
    ) -> FunctionClassification {
        let language = parsed_file.language;
        let knowledge = self.get_knowledge(language);
        classify_function_with_knowledge(parsed_file, func_node, func_name, &knowledge)
    }
}

/// Classify a function using provided knowledge (thread-safe, no mutable state)
fn classify_function_with_knowledge(
    parsed_file: &ParsedFile,
    func_node: Node,
    func_name: &str,
    knowledge: &MergedKnowledge,
) -> FunctionClassification {
    let language = parsed_file.language;
    let content = &parsed_file.content;

    // Extract all identifiers and call expressions from the function body
    let calls = extract_calls_from_node(func_node, content, language);
    let members = extract_member_accesses(func_node, content, language);

    // Classify based on extracted patterns
    let mut classification = FunctionClassification::default();
    let mut confidence_sum = 0.0;
    let mut confidence_count = 0;

    // Check for source patterns using knowledge system
    for call in &calls {
        if knowledge.is_source_function(call) {
            classification.is_source = true;
            // Use the knowledge system to get the proper classification
            classification.source_kind = Some(
                knowledge
                    .get_source(call)
                    .map(classify_source_from_def)
                    .unwrap_or_else(|| infer_source_kind_fallback(call)),
            );
            confidence_sum += 0.9;
            confidence_count += 1;
        }
    }

    for member in &members {
        if knowledge.is_source_member(member) {
            classification.is_source = true;
            classification.source_kind = Some(
                knowledge
                    .get_source(member)
                    .map(classify_source_from_def)
                    .unwrap_or_else(|| infer_source_kind_fallback(member)),
            );
            confidence_sum += 0.9;
            confidence_count += 1;
        }
    }

    // Check for sink patterns using knowledge system
    for call in &calls {
        if knowledge.is_sink_function(call) || knowledge.is_sink_method(call) {
            classification.contains_sinks = true;
            // Use the knowledge system to get the proper classification
            if let Some(sink_def) = knowledge.get_sink(call) {
                let sink_kind = classify_sink_from_def(sink_def);
                if !classification.sink_kinds.contains(&sink_kind) {
                    classification.sink_kinds.push(sink_kind);
                }
            }
            confidence_sum += 0.9;
            confidence_count += 1;
        }
    }

    // Check for sanitizer patterns
    for call in &calls {
        if knowledge.is_sanitizer(call) {
            classification.calls_sanitizers = true;
            if let Some(sanitizer_def) = knowledge.get_sanitizer(call) {
                let sanitizes = sanitizer_def.sanitizes.to_string();
                if !classification.sanitizes.contains(&sanitizes) {
                    classification.sanitizes.push(sanitizes);
                }
            }
        }
    }

    // Check function name for HTTP handler patterns
    // IMPORTANT: First apply path-based scope gate to prevent browser-side JS
    // (jQuery, validation libs, etc.) from being classified as HTTP handlers
    let passes_scope_gate = can_path_define_http_handler(&parsed_file.path, language);

    if passes_scope_gate && is_http_handler_name(func_name, language) {
        classification.is_source = true;
        if classification.source_kind.is_none() {
            classification.source_kind = Some(SourceClassification::HttpHandler);
        }
        confidence_sum += 0.7;
        confidence_count += 1;
    }

    // Calculate overall confidence
    classification.confidence = if confidence_count > 0 {
        (confidence_sum / confidence_count as f32).min(1.0)
    } else {
        0.0
    };

    classification
}

impl FunctionClassifier {
    /// Classify all functions in a parsed file
    pub fn classify_file(
        &mut self,
        parsed_file: &ParsedFile,
    ) -> HashMap<String, FunctionClassification> {
        let knowledge = self.get_knowledge(parsed_file.language);
        classify_file_with_knowledge(parsed_file, &knowledge)
    }

    /// Classify multiple files in parallel using Rayon
    pub fn classify_files_parallel(
        &self,
        parsed_files: &[ParsedFile],
    ) -> HashMap<(std::path::PathBuf, String), FunctionClassification> {
        parsed_files
            .par_iter()
            .flat_map(|parsed_file| {
                let knowledge = match self.get_knowledge_readonly(parsed_file.language) {
                    Some(k) => k.clone(),
                    None => Arc::new(KnowledgeBuilder::new(parsed_file.language).all_profiles()),
                };
                let classifications = classify_file_with_knowledge(parsed_file, &knowledge);
                classifications
                    .into_iter()
                    .map(|(name, class)| ((parsed_file.path.clone(), name), class))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Classify all functions in a file (thread-safe)
fn classify_file_with_knowledge(
    parsed_file: &ParsedFile,
    knowledge: &MergedKnowledge,
) -> HashMap<String, FunctionClassification> {
    let mut classifications = HashMap::new();

    let tree = &parsed_file.tree;
    let content = &parsed_file.content;
    let language = parsed_file.language;

    // Walk the AST to find function definitions
    let mut cursor = tree.walk();
    collect_function_classifications_fast(
        &mut cursor,
        content,
        language,
        knowledge,
        parsed_file,
        &mut classifications,
    );

    classifications
}

impl Default for FunctionClassifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract function/method calls from an AST node
fn extract_calls_from_node(node: Node, content: &str, language: Language) -> Vec<String> {
    let mut calls = Vec::new();
    let mut cursor = node.walk();
    collect_calls_recursive(&mut cursor, content, language, &mut calls);
    calls
}

fn collect_calls_recursive(
    cursor: &mut tree_sitter::TreeCursor,
    content: &str,
    language: Language,
    calls: &mut Vec<String>,
) {
    let node = cursor.node();
    let kind = node.kind();

    // Language-specific call node types
    let is_call = match language {
        Language::JavaScript | Language::TypeScript => {
            kind == "call_expression" || kind == "new_expression"
        }
        Language::Python => kind == "call",
        Language::Java => kind == "method_invocation" || kind == "object_creation_expression",
        Language::Go => kind == "call_expression",
        Language::Rust => kind == "call_expression" || kind == "macro_invocation",
        Language::Ruby => kind == "call" || kind == "method_call",
        Language::Php => kind == "function_call_expression" || kind == "method_call_expression",
        Language::CSharp => kind == "invocation_expression" || kind == "object_creation_expression",
        Language::Kotlin => kind == "call_expression",
        Language::Swift => kind == "call_expression",
        Language::Scala => kind == "call_expression",
        _ => kind.contains("call") || kind.contains("invocation"),
    };

    if is_call && let Some(callee) = extract_callee_name(node, content, language) {
        calls.push(callee);
    }

    if cursor.goto_first_child() {
        loop {
            collect_calls_recursive(cursor, content, language, calls);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Extract the callee name from a call expression
/// For method calls like `db.Query()`, this extracts "Query" (the method name)
/// The knowledge base should use MethodCall patterns for these
fn extract_callee_name(node: Node, content: &str, _language: Language) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();

            // Simple function call: foo()
            if kind == "identifier" {
                return Some(child.utf8_text(content.as_bytes()).ok()?.to_string());
            }

            // Go: selector_expression for pkg.Func() or obj.Method()
            if kind == "selector_expression" {
                // Get the field (method/function name after the dot)
                if let Some(field) = child.child_by_field_name("field") {
                    return Some(field.utf8_text(content.as_bytes()).ok()?.to_string());
                }
                // Fallback: get the last part after the dot
                let full = child.utf8_text(content.as_bytes()).ok()?;
                if let Some(dot_pos) = full.rfind('.') {
                    return Some(full[dot_pos + 1..].to_string());
                }
                return Some(full.to_string());
            }

            // JS/TS: member_expression for obj.method()
            if kind == "member_expression"
                && let Some(prop) = child.child_by_field_name("property")
            {
                return Some(prop.utf8_text(content.as_bytes()).ok()?.to_string());
            }

            // Java: method_invocation already gives us the method name
            if kind == "field_identifier" || kind == "property_identifier" {
                return Some(child.utf8_text(content.as_bytes()).ok()?.to_string());
            }

            // Python: attribute for obj.method()
            if kind == "attribute"
                && let Some(attr) = child.child_by_field_name("attribute")
            {
                return Some(attr.utf8_text(content.as_bytes()).ok()?.to_string());
            }

            // Rust: field_expression for obj.method()
            if kind == "field_expression"
                && let Some(field) = child.child_by_field_name("field")
            {
                return Some(field.utf8_text(content.as_bytes()).ok()?.to_string());
            }
        }
    }

    // Fallback: parse the text to extract callee
    let text = node.utf8_text(content.as_bytes()).ok()?;
    if text.len() < 100
        && let Some(paren_pos) = text.find('(')
    {
        let callee = text[..paren_pos].trim();
        // Extract just the method/function name (after last dot)
        if let Some(last_dot) = callee.rfind('.') {
            return Some(callee[last_dot + 1..].to_string());
        }
        return Some(callee.to_string());
    }

    None
}

/// Extract member/property accesses from an AST node
fn extract_member_accesses(node: Node, content: &str, language: Language) -> Vec<String> {
    let mut members = Vec::new();
    let mut cursor = node.walk();
    collect_members_recursive(&mut cursor, content, language, &mut members);
    members
}

fn collect_members_recursive(
    cursor: &mut tree_sitter::TreeCursor,
    content: &str,
    language: Language,
    members: &mut Vec<String>,
) {
    let node = cursor.node();
    let kind = node.kind();

    let is_member_access = match language {
        Language::JavaScript | Language::TypeScript => kind == "member_expression",
        Language::Python => kind == "attribute",
        Language::Java => kind == "field_access",
        Language::Go => kind == "selector_expression",
        Language::Rust => kind == "field_expression",
        _ => kind.contains("member") || kind.contains("field") || kind.contains("attribute"),
    };

    if is_member_access
        && let Ok(text) = node.utf8_text(content.as_bytes())
        && text.len() < 200
    {
        members.push(text.to_string());
    }

    if cursor.goto_first_child() {
        loop {
            collect_members_recursive(cursor, content, language, members);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Collect function classifications from an AST (uses classifier)
#[allow(dead_code)]
fn collect_function_classifications(
    cursor: &mut tree_sitter::TreeCursor,
    content: &str,
    language: Language,
    classifier: &mut FunctionClassifier,
    parsed_file: &ParsedFile,
    classifications: &mut HashMap<String, FunctionClassification>,
) {
    let node = cursor.node();
    let kind = node.kind();

    if is_function_node(kind, language)
        && let Some(name) = extract_function_name(node, content)
    {
        let classification = classifier.classify_function(parsed_file, node, &name);
        classifications.insert(name, classification);
    }

    if cursor.goto_first_child() {
        loop {
            collect_function_classifications(
                cursor,
                content,
                language,
                classifier,
                parsed_file,
                classifications,
            );
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Fast function classification using pre-built knowledge (thread-safe)
fn collect_function_classifications_fast(
    cursor: &mut tree_sitter::TreeCursor,
    content: &str,
    language: Language,
    knowledge: &MergedKnowledge,
    parsed_file: &ParsedFile,
    classifications: &mut HashMap<String, FunctionClassification>,
) {
    let node = cursor.node();
    let kind = node.kind();

    if is_function_node(kind, language)
        && let Some(name) = extract_function_name(node, content)
    {
        let classification = classify_function_with_knowledge(parsed_file, node, &name, knowledge);
        classifications.insert(name, classification);
    }

    if cursor.goto_first_child() {
        loop {
            collect_function_classifications_fast(
                cursor,
                content,
                language,
                knowledge,
                parsed_file,
                classifications,
            );
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Check if a node kind represents a function definition
#[inline]
fn is_function_node(kind: &str, language: Language) -> bool {
    match language {
        Language::JavaScript | Language::TypeScript => {
            kind == "function_declaration"
                || kind == "method_definition"
                || kind == "arrow_function"
                || kind == "function_expression"
        }
        Language::Python => kind == "function_definition",
        Language::Java => kind == "method_declaration" || kind == "constructor_declaration",
        Language::Go => kind == "function_declaration" || kind == "method_declaration",
        Language::Rust => kind == "function_item",
        Language::Ruby => kind == "method" || kind == "singleton_method",
        Language::Php => kind == "method_declaration" || kind == "function_definition",
        Language::CSharp => kind == "method_declaration" || kind == "constructor_declaration",
        _ => kind.contains("function") || kind.contains("method"),
    }
}

/// Extract function name from a function node
fn extract_function_name(node: Node, content: &str) -> Option<String> {
    for field in &["name", "declarator", "identifier"] {
        if let Some(name_node) = node.child_by_field_name(field) {
            let mut name_cursor = name_node;
            while name_cursor.kind() != "identifier" && name_cursor.child_count() > 0 {
                if let Some(child) = name_cursor.child(0) {
                    name_cursor = child;
                } else {
                    break;
                }
            }
            if let Ok(name) = name_cursor.utf8_text(content.as_bytes()) {
                return Some(name.to_string());
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i)
            && child.kind() == "identifier"
            && let Ok(name) = child.utf8_text(content.as_bytes())
        {
            return Some(name.to_string());
        }
    }

    None
}

/// Classify source kind from knowledge system SourceDef
fn classify_source_from_def(source_def: &crate::knowledge::SourceDef) -> SourceClassification {
    let label = source_def.taint_label.to_lowercase();

    // Map taint labels to source classifications
    if label.contains("http") || label.contains("request") {
        if label.contains("param")
            || label.contains("query")
            || label.contains("body")
            || label.contains("header")
            || label.contains("cookie")
            || label.contains("input")
        {
            SourceClassification::HttpInput
        } else {
            SourceClassification::HttpHandler
        }
    } else if label.contains("file") || label.contains("stream") || label.contains("read") {
        SourceClassification::FileInput
    } else if label.contains("env") {
        SourceClassification::EnvironmentVariable
    } else if label.contains("database") || label.contains("sql") || label.contains("result") {
        SourceClassification::DatabaseResult
    } else if label.contains("message") || label.contains("event") || label.contains("queue") {
        SourceClassification::MessageInput
    } else if label.contains("argv") || label.contains("args") || label.contains("cli") {
        SourceClassification::CommandLineArgs
    } else {
        SourceClassification::Other(source_def.name.to_string())
    }
}

/// Fallback source classification when no SourceDef is available
fn infer_source_kind_fallback(pattern: &str) -> SourceClassification {
    // Only used when knowledge system doesn't have a match
    SourceClassification::Other(pattern.to_string())
}

/// Classify sink kind from knowledge system SinkDef
fn classify_sink_from_def(sink_def: &crate::knowledge::SinkDef) -> SinkClassification {
    // First, try to classify by CWE if available (most reliable)
    if let Some(cwe) = sink_def.cwe {
        let cwe_lower = cwe.to_lowercase();
        if cwe_lower.contains("89") || cwe_lower.contains("sql") {
            return SinkClassification::SqlInjection;
        } else if cwe_lower.contains("78") || cwe_lower.contains("command") {
            return SinkClassification::CommandInjection;
        } else if cwe_lower.contains("79") || cwe_lower.contains("xss") {
            return SinkClassification::CrossSiteScripting;
        } else if cwe_lower.contains("22") || cwe_lower.contains("path") {
            return SinkClassification::PathTraversal;
        } else if cwe_lower.contains("502") || cwe_lower.contains("deserial") {
            return SinkClassification::Deserialization;
        } else if cwe_lower.contains("90") || cwe_lower.contains("ldap") {
            return SinkClassification::LdapInjection;
        } else if cwe_lower.contains("94") || cwe_lower.contains("template") {
            return SinkClassification::TemplateInjection;
        } else if cwe_lower.contains("611") || cwe_lower.contains("xml") {
            return SinkClassification::XmlInjection;
        } else if cwe_lower.contains("117") || cwe_lower.contains("log") {
            return SinkClassification::LogInjection;
        } else if cwe_lower.contains("601") || cwe_lower.contains("redirect") {
            return SinkClassification::OpenRedirect;
        }
    }

    // Fall back to rule_id classification
    rule_id_to_sink_classification(sink_def.rule_id)
}

/// Convert rule ID to sink classification
fn rule_id_to_sink_classification(rule_id: &str) -> SinkClassification {
    if rule_id.contains("sql") {
        SinkClassification::SqlInjection
    } else if rule_id.contains("command") || rule_id.contains("exec") || rule_id.contains("rce") {
        SinkClassification::CommandInjection
    } else if rule_id.contains("xss") {
        SinkClassification::CrossSiteScripting
    } else if rule_id.contains("path") || rule_id.contains("traversal") {
        SinkClassification::PathTraversal
    } else if rule_id.contains("deserial") {
        SinkClassification::Deserialization
    } else if rule_id.contains("ldap") {
        SinkClassification::LdapInjection
    } else if rule_id.contains("template") {
        SinkClassification::TemplateInjection
    } else if rule_id.contains("xml") {
        SinkClassification::XmlInjection
    } else if rule_id.contains("redirect") {
        SinkClassification::OpenRedirect
    } else {
        SinkClassification::Other(rule_id.to_string())
    }
}

/// Check if a function name indicates it's an HTTP handler
///
/// NOTE: This is name-based detection and should ONLY be used AFTER
/// path-based scope gating via `can_path_define_http_handler()`.
/// Name-based alone will produce false positives (e.g., jQuery validation handlers).
fn is_http_handler_name(name: &str, language: Language) -> bool {
    let lower = name.to_lowercase();

    match language {
        Language::Java => {
            (lower.starts_with("do")
                && (lower == "doget"
                    || lower == "dopost"
                    || lower == "doput"
                    || lower == "dodelete"
                    || lower == "dopatch"))
                || (lower.contains("handle") && lower.contains("request"))
        }
        Language::JavaScript | Language::TypeScript => {
            lower.ends_with("handler")
                || lower.ends_with("controller")
                || lower.starts_with("handle")
                || lower.contains("middleware")
        }
        Language::Python => {
            lower.ends_with("view") || lower.ends_with("handler") || lower.starts_with("handle_")
        }
        Language::Go => lower.ends_with("handler") || lower.starts_with("handle"),
        Language::Rust => lower.ends_with("handler") || lower.starts_with("handle_"),
        Language::Ruby => {
            lower == "index"
                || lower == "show"
                || lower == "create"
                || lower == "update"
                || lower == "destroy"
        }
        Language::Php => lower.ends_with("action") || lower.ends_with("controller"),
        Language::CSharp => {
            lower.ends_with("action") || lower.ends_with("controller") || lower.starts_with("on")
        }
        Language::Kotlin => lower.ends_with("handler") || lower.starts_with("handle"),
        Language::Scala => lower.ends_with("action") || lower.ends_with("handler"),
        Language::Swift => lower.ends_with("handler") || lower.starts_with("handle"),
        Language::Elixir => {
            lower == "index"
                || lower == "show"
                || lower == "create"
                || lower == "update"
                || lower == "delete"
                || lower == "new"
                || lower == "edit"
        }
        Language::Solidity | Language::Bash => false,
        _ => lower.ends_with("handler") || (lower.contains("handle") && lower.contains("request")),
    }
}

/// Path-based scope gate: Can this file path define HTTP handlers?
///
/// Uses project structure heuristics (stable) instead of content pattern matching (brittle).
/// This prevents browser-side JS (jQuery, validation libs) from being classified as HTTP handlers.
pub fn can_path_define_http_handler(file_path: &std::path::Path, language: Language) -> bool {
    let path_str = file_path.to_string_lossy().to_lowercase();
    let path_str = path_str.replace('\\', "/"); // Normalize Windows paths

    // Universal exclusions: vendor/static/dist directories are never server handlers
    let browser_vendor_patterns = [
        "/static/",
        "/public/",
        "/dist/",
        "/vendor/",
        "/webjars/",
        "/node_modules/",
        "/bower_components/",
        "/assets/",
        "/lib/", // Often contains vendored libs
        "/libs/",
        "meta-inf/resources/", // Java static resources
    ];

    for pattern in &browser_vendor_patterns {
        if path_str.contains(pattern) {
            return false;
        }
    }

    // Known browser-side library filenames (even if not in vendor dir)
    let browser_lib_names = [
        "jquery",
        "bootstrap",
        "angular",
        "react",
        "vue",
        "lodash",
        "underscore",
        "backbone",
        "ember",
        "validate",
        "validation", // Form validation libs
    ];

    if let Some(file_name) = file_path.file_name() {
        let name_lower = file_name.to_string_lossy().to_lowercase();
        for lib in &browser_lib_names {
            if name_lower.contains(lib)
                && (name_lower.ends_with(".js") || name_lower.ends_with(".ts"))
            {
                return false;
            }
        }
    }

    // Language-specific server scope rules
    match language {
        Language::Java | Language::Kotlin => {
            // Java/Kotlin: only src/main/** can define handlers (not tests)
            path_str.contains("src/main/") ||
            // Gradle-style
            path_str.contains("/main/java/") ||
            path_str.contains("/main/kotlin/") ||
            // Allow if not in any test directory
            (!path_str.contains("/test/") && !path_str.contains("test.java"))
        }
        Language::JavaScript | Language::TypeScript => {
            // JS/TS: server-side scopes only
            let server_scopes = [
                "/server/",
                "/backend/",
                "/api/",
                "/routes/",
                "/controllers/",
                "/handlers/",
                "/middleware/",
                "pages/api/", // Next.js API routes
                "src/api/",
                "app/api/", // Next.js 13+ app router
            ];

            // If in a known server scope, allow
            for scope in &server_scopes {
                if path_str.contains(scope) {
                    return true;
                }
            }

            // If in src/ but not in browser exclusions, cautiously allow
            // (This catches express apps with src/index.js structure)
            if path_str.contains("/src/") && !path_str.contains("/src/public/") {
                return true;
            }

            // Root-level JS files might be server entry points
            // But be conservative - require explicit server indicators
            false
        }
        Language::Python => {
            // Python: Django views, Flask routes, FastAPI
            path_str.contains("/views/") ||
            path_str.contains("/api/") ||
            path_str.contains("/routes/") ||
            path_str.contains("/endpoints/") ||
            // Django app structure
            path_str.ends_with("views.py") ||
            // General src scope
            (path_str.contains("/src/") && !path_str.contains("/test"))
        }
        Language::Go => {
            // Go: handlers directory or main package
            path_str.contains("/handlers/")
                || path_str.contains("/api/")
                || path_str.contains("/cmd/")
                || path_str.contains("/internal/")
        }
        Language::Rust => {
            // Rust: handlers, routes, or src
            path_str.contains("/handlers/")
                || path_str.contains("/routes/")
                || path_str.contains("/api/")
                || path_str.contains("/src/")
        }
        _ => {
            // For other languages, be permissive but exclude obvious non-server paths
            !path_str.contains("/test/") && !path_str.contains("/spec/")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::Severity;

    #[test]
    fn test_classify_source_from_def() {
        use crate::knowledge::types::{SourceDef, SourceKind};

        // HTTP input source
        let http_source = SourceDef {
            name: "getParameter",
            pattern: SourceKind::FunctionCall("getParameter"),
            taint_label: "http_input",
            description: "HTTP request parameter",
        };
        assert!(matches!(
            classify_source_from_def(&http_source),
            SourceClassification::HttpInput
        ));

        // Environment variable source
        let env_source = SourceDef {
            name: "getenv",
            pattern: SourceKind::FunctionCall("getenv"),
            taint_label: "environment_variable",
            description: "Environment variable",
        };
        assert!(matches!(
            classify_source_from_def(&env_source),
            SourceClassification::EnvironmentVariable
        ));

        // File input source
        let file_source = SourceDef {
            name: "readFile",
            pattern: SourceKind::FunctionCall("readFile"),
            taint_label: "file_input",
            description: "File content",
        };
        assert!(matches!(
            classify_source_from_def(&file_source),
            SourceClassification::FileInput
        ));
    }

    #[test]
    fn test_classify_sink_from_def() {
        use crate::knowledge::types::{SinkDef, SinkKind};

        // SQL injection sink (by CWE)
        let sql_sink = SinkDef {
            name: "executeQuery",
            pattern: SinkKind::FunctionCall("executeQuery"),
            rule_id: "java-sql-injection",
            severity: Severity::Critical,
            description: "SQL query execution",
            cwe: Some("CWE-89"),
        };
        assert!(matches!(
            classify_sink_from_def(&sql_sink),
            SinkClassification::SqlInjection
        ));

        // Command injection sink (by CWE)
        let cmd_sink = SinkDef {
            name: "exec",
            pattern: SinkKind::FunctionCall("exec"),
            rule_id: "command-injection",
            severity: Severity::Critical,
            description: "Command execution",
            cwe: Some("CWE-78"),
        };
        assert!(matches!(
            classify_sink_from_def(&cmd_sink),
            SinkClassification::CommandInjection
        ));

        // Sink classified by rule_id (no CWE)
        let xss_sink = SinkDef {
            name: "innerHTML",
            pattern: SinkKind::FunctionCall("innerHTML"),
            rule_id: "xss-dom",
            severity: Severity::Error,
            description: "DOM XSS",
            cwe: None,
        };
        assert!(matches!(
            classify_sink_from_def(&xss_sink),
            SinkClassification::CrossSiteScripting
        ));
    }

    #[test]
    fn test_http_handler_detection() {
        assert!(is_http_handler_name("doGet", Language::Java));
        assert!(is_http_handler_name("doPost", Language::Java));
        assert!(is_http_handler_name("handleRequest", Language::JavaScript));
        assert!(!is_http_handler_name("calculateSum", Language::Java));
    }
}
