//! Null Pointer / NPE Detection Rule
//!
//! Detects potential null pointer dereferences / NullPointerExceptions using
//! reaching definitions analysis.

use crate::flow::reaching_defs::{DefOrigin, Definition};
use crate::flow::{BlockId, FlowContext};
use crate::rules::{Rule, create_finding_at_line};
use crate::semantics::LanguageSemantics;
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use std::collections::{HashMap, HashSet};

/// Detects potential null pointer dereferences / NullPointerExceptions.
///
/// Uses reaching definitions to track which definitions are "potentially null"
/// and reports when such values are used without a null guard.
///
/// Tracks null-producing patterns per language:
/// - JS: null, undefined, .find() returning undefined, .get()
/// - Python: None, dict.get(), function with no return
/// - Go: nil, error returns, map access
/// - Rust: Option::None, Result::Err (for unwrap detection)
/// - Java: null, Optional.empty(), Collections.find()
pub struct NullPointerRule;

impl Rule for NullPointerRule {
    fn id(&self) -> &str {
        "generic/null-pointer"
    }

    fn description(&self) -> &str {
        "Potentially null value used without null check"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        // Works for all languages
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // Requires dataflow analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip test files
        if crate::security::generic::is_test_or_fixture_file(&parsed.path) {
            return findings;
        }

        let semantics = flow.semantics;
        let language = parsed.language;

        // Get def-use chains
        let chains = match flow.def_use_chains() {
            Some(c) => c,
            None => return findings,
        };

        // Build null guard tracking
        let null_analyzer = NullAnalyzer::new(language, semantics);

        // Track which definitions are potentially null
        let mut null_defs: HashSet<Definition> = HashSet::new();

        // Identify null-producing definitions
        for (def, _uses) in &chains.def_to_uses {
            if null_analyzer.is_potentially_null_origin(&def.origin) {
                null_defs.insert(def.clone());
            }
        }

        // Track which variables have been null-guarded at which blocks
        let guarded_vars = null_analyzer.find_null_guards(parsed, flow);

        // For each use, check if ALL reaching definitions are potentially null
        // and there's no null guard on the path
        for (use_site, defs) in &chains.use_to_defs {
            // Skip if no definitions reach this use (handled by uninitialized check)
            if defs.is_empty() {
                continue;
            }

            // Skip common false positive names
            if should_skip_variable(&use_site.var_name) {
                continue;
            }

            // Check if ANY reaching definition is potentially null
            let potentially_null_defs: Vec<&Definition> =
                defs.iter().filter(|d| null_defs.contains(d)).collect();

            if potentially_null_defs.is_empty() {
                continue; // No null definitions reach this use
            }

            // Check if this use site has a null guard
            let use_block = flow.cfg.block_of(use_site.node_id);
            let is_guarded = use_block.map_or(false, |block_id| {
                guarded_vars
                    .get(&use_site.var_name)
                    .map_or(false, |guarded_blocks| guarded_blocks.contains(&block_id))
            });

            if is_guarded {
                continue; // Null guard exists
            }

            // Determine severity based on how many definitions are null
            let all_null = potentially_null_defs.len() == defs.len();
            let severity = if all_null {
                Severity::Warning
            } else {
                Severity::Info
            };

            // Build description
            let null_sources: Vec<String> = potentially_null_defs
                .iter()
                .map(|d| format!("line {} ({})", d.line, describe_null_origin(&d.origin)))
                .collect();

            let message = if all_null {
                format!(
                    "Variable '{}' is potentially null (from: {}) and used without null check",
                    use_site.var_name,
                    null_sources.join(", ")
                )
            } else {
                format!(
                    "Variable '{}' may be null on some paths (from: {})",
                    use_site.var_name,
                    null_sources.join(", ")
                )
            };

            let mut finding = create_finding_at_line(
                self.id(),
                &parsed.path,
                use_site.line,
                &use_site.var_name,
                severity,
                &message,
                parsed.language,
            );
            finding.confidence = if all_null {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            findings.push(finding);
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

/// Analyzer for null-related patterns per language
struct NullAnalyzer {
    language: Language,
    /// Function names that return nullable values
    nullable_functions: HashSet<&'static str>,
    /// Member access patterns that return nullable values (e.g., ".get", ".find")
    nullable_member_patterns: Vec<&'static str>,
}

impl NullAnalyzer {
    fn new(language: Language, _semantics: &'static LanguageSemantics) -> Self {
        let (nullable_functions, nullable_member_patterns) = match language {
            Language::JavaScript | Language::TypeScript => (
                HashSet::from([
                    "find",
                    "get",
                    "querySelector",
                    "getElementById",
                    "getAttribute",
                    "getItem",
                    "pop",
                    "shift",
                ]),
                vec![
                    ".find(",
                    ".get(",
                    ".querySelector(",
                    ".getElementById(",
                    ".pop(",
                    ".shift(",
                ],
            ),
            Language::Python => (
                HashSet::from(["get", "find", "pop", "next"]),
                vec![".get(", ".find(", ".pop("],
            ),
            Language::Go => (
                HashSet::from([
                    // Go functions that can return nil
                ]),
                vec![], // Go uses comma-ok idiom, tracked differently
            ),
            Language::Rust => (
                HashSet::from([
                    "get",
                    "get_mut",
                    "first",
                    "last",
                    "pop",
                    "find",
                    "ok",
                    "err",
                    "unwrap_or",
                    "and_then",
                ]),
                vec![".get(", ".first(", ".last(", ".pop(", ".find("],
            ),
            Language::Java => (
                HashSet::from([
                    "get",
                    "find",
                    "findFirst",
                    "findAny",
                    "poll",
                    "peek",
                    "remove",
                    "getOrDefault",
                ]),
                vec![".get(", ".find(", ".poll(", ".peek(", ".remove("],
            ),
            Language::Unknown => (HashSet::new(), vec![]),
        };

        Self {
            language,
            nullable_functions,
            nullable_member_patterns,
        }
    }

    /// Check if a definition origin represents a potentially null value
    fn is_potentially_null_origin(&self, origin: &DefOrigin) -> bool {
        match origin {
            // Literal null/None/nil/undefined - actual null literals are tracked separately
            DefOrigin::Literal => false,

            // Function calls that may return null
            DefOrigin::FunctionCall(func_name) => {
                // Check if function name matches nullable patterns
                let base_name = func_name.rsplit('.').next().unwrap_or(func_name);
                self.nullable_functions.contains(base_name)
                    || self.is_nullable_function_call(func_name)
            }

            // Member access patterns like .get(), .find()
            DefOrigin::MemberAccess(path) => {
                self.nullable_member_patterns
                    .iter()
                    .any(|p| path.contains(p))
                    || self.is_nullable_member_access(path)
            }

            // Variable assignment - depends on source (conservative: assume not null)
            DefOrigin::Variable(_) => false,

            // Expression - could be null, be conservative
            DefOrigin::Expression => false,

            // Parameters - depends on caller, be conservative
            DefOrigin::Parameter(_) => false,

            // Unknown - be conservative
            DefOrigin::Unknown => false,
        }
    }

    /// Check if a function call returns a nullable type
    fn is_nullable_function_call(&self, func_name: &str) -> bool {
        match self.language {
            Language::JavaScript | Language::TypeScript => {
                // Array.prototype methods that can return undefined
                func_name.ends_with(".find")
                    || func_name.ends_with(".get")
                    || func_name.contains("querySelector")
                    || func_name.contains("getElementById")
                    // Map/Object access
                    || func_name.ends_with("].get")
                    || func_name.contains("localStorage.getItem")
                    || func_name.contains("sessionStorage.getItem")
            }
            Language::Python => {
                // Dict.get(), list index access
                func_name.ends_with(".get")
                    || func_name.ends_with(".find")
                    || func_name.ends_with(".pop")
            }
            Language::Go => {
                // Go map access (value, ok pattern)
                false // Go uses multi-value returns, harder to track
            }
            Language::Rust => {
                // Option/Result returning functions
                func_name.ends_with(".get")
                    || func_name.ends_with(".first")
                    || func_name.ends_with(".last")
                    || func_name.ends_with(".find")
                    || func_name.contains("Option::")
                    || func_name.contains("Result::")
            }
            Language::Java => {
                // Optional, Collections methods
                func_name.ends_with(".get")
                    || func_name.ends_with(".find")
                    || func_name.contains("Optional.")
                    || func_name.ends_with(".poll")
                    || func_name.ends_with(".peek")
            }
            Language::Unknown => false,
        }
    }

    /// Check if a member access pattern returns nullable
    fn is_nullable_member_access(&self, path: &str) -> bool {
        match self.language {
            Language::JavaScript | Language::TypeScript => {
                // Check for array/map access patterns
                path.contains('[') && path.contains(']') && !path.ends_with(']')
            }
            Language::Python => {
                // dict.get() is explicitly nullable
                path.ends_with(".get")
            }
            Language::Go => {
                // Map access in Go
                path.contains('[') && path.contains(']')
            }
            Language::Rust => {
                // Option/Result method chains
                path.contains(".get(") || path.contains(".first(") || path.contains(".last(")
            }
            Language::Java => {
                // Map.get(), Optional patterns
                path.ends_with(".get(") || path.contains("Optional.")
            }
            Language::Unknown => false,
        }
    }

    /// Find null guards in the code and return which variables are guarded at which blocks
    fn find_null_guards(
        &self,
        parsed: &ParsedFile,
        flow: &FlowContext,
    ) -> HashMap<String, HashSet<BlockId>> {
        let mut guarded: HashMap<String, HashSet<BlockId>> = HashMap::new();

        // Walk the AST looking for null guard patterns
        let root = parsed.tree.root_node();
        self.collect_null_guards(root, parsed.content.as_bytes(), flow, &mut guarded);

        guarded
    }

    /// Recursively collect null guards from AST
    fn collect_null_guards(
        &self,
        node: tree_sitter::Node,
        source: &[u8],
        flow: &FlowContext,
        guarded: &mut HashMap<String, HashSet<BlockId>>,
    ) {
        let kind = node.kind();

        // Check for if statements with null checks
        if flow.semantics.is_if(kind) {
            if let Some(condition) = node.child_by_field_name("condition") {
                if let Some(var_name) = self.extract_null_checked_var(condition, source) {
                    // The "consequence" (then) block is guarded
                    if let Some(consequence) = node
                        .child_by_field_name("consequence")
                        .or_else(|| node.child_by_field_name("body"))
                    {
                        // Find the block ID for the consequence
                        if let Some(block_id) = flow.cfg.block_of(consequence.id()) {
                            guarded
                                .entry(var_name.clone())
                                .or_default()
                                .insert(block_id);
                            // Also add successor blocks within the consequence
                            self.add_guarded_blocks(consequence, flow, &var_name, guarded);
                        }
                    }
                }
            }
        }

        // Check for optional chaining (JS/TS): x?.prop
        if kind == "optional_chain_expression" || kind == "member_expression" {
            let text = node.utf8_text(source).unwrap_or("");
            if text.contains("?.") {
                // Extract the base variable
                if let Some(base_var) = self.extract_optional_chain_base(node, source) {
                    if let Some(block_id) = flow.cfg.block_of(node.id()) {
                        guarded.entry(base_var).or_default().insert(block_id);
                    }
                }
            }
        }

        // Check for nullish coalescing (JS/TS): x ?? default
        if kind == "binary_expression" {
            let op = node
                .child_by_field_name("operator")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            if op == "??" || op == "||" {
                if let Some(left) = node.child_by_field_name("left") {
                    if let Ok(var_name) = left.utf8_text(source) {
                        if flow.semantics.is_identifier(left.kind()) {
                            if let Some(block_id) = flow.cfg.block_of(node.id()) {
                                // After nullish coalescing, the value is guarded
                                guarded
                                    .entry(var_name.to_string())
                                    .or_default()
                                    .insert(block_id);
                            }
                        }
                    }
                }
            }
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.collect_null_guards(child, source, flow, guarded);
        }
    }

    /// Add all blocks within a guarded region
    fn add_guarded_blocks(
        &self,
        node: tree_sitter::Node,
        flow: &FlowContext,
        var_name: &str,
        guarded: &mut HashMap<String, HashSet<BlockId>>,
    ) {
        if let Some(block_id) = flow.cfg.block_of(node.id()) {
            guarded
                .entry(var_name.to_string())
                .or_default()
                .insert(block_id);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.add_guarded_blocks(child, flow, var_name, guarded);
        }
    }

    /// Extract variable name from a null check condition
    fn extract_null_checked_var(
        &self,
        condition: tree_sitter::Node,
        source: &[u8],
    ) -> Option<String> {
        let kind = condition.kind();

        // Binary expression: x !== null, x != nil, x is not None, x != null
        if kind == "binary_expression" || kind == "comparison_operator" || kind == "not_operator" {
            let op = condition
                .child_by_field_name("operator")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");

            // Check for !== null, != null, != nil patterns
            if op == "!==" || op == "!=" || op == "is not" {
                let left = condition.child_by_field_name("left");
                let right = condition.child_by_field_name("right");

                if let (Some(l), Some(r)) = (left, right) {
                    let l_text = l.utf8_text(source).unwrap_or("");
                    let r_text = r.utf8_text(source).unwrap_or("");

                    // Check if right side is null/nil/None/undefined
                    if is_null_literal_text(r_text, self.language) {
                        return Some(l_text.to_string());
                    }
                    // Check reverse: null !== x
                    if is_null_literal_text(l_text, self.language) {
                        return Some(r_text.to_string());
                    }
                }
            }

            // Check for === null (negative guard - else branch is guarded)
            // This is handled by the CFG structure
        }

        // Parenthesized expression: (x !== null)
        if kind == "parenthesized_expression" {
            if let Some(inner) = condition.named_child(0) {
                return self.extract_null_checked_var(inner, source);
            }
        }

        // Simple truthiness check: if (x) { ... }
        if condition.kind() == "identifier" {
            return condition.utf8_text(source).ok().map(|s| s.to_string());
        }

        // Python-style: if x is not None
        if kind == "comparison_operator" {
            // Look for "is not" operator
            let text = condition.utf8_text(source).unwrap_or("");
            if text.contains("is not None") || text.contains("is not nil") {
                // Extract the variable before "is not"
                if let Some(left) = condition.named_child(0) {
                    if left.kind() == "identifier" {
                        return left.utf8_text(source).ok().map(|s| s.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract base variable from optional chaining expression
    fn extract_optional_chain_base(
        &self,
        node: tree_sitter::Node,
        source: &[u8],
    ) -> Option<String> {
        // Walk down to find the base identifier
        let mut current = node;
        loop {
            if current.kind() == "identifier" {
                return current.utf8_text(source).ok().map(|s| s.to_string());
            }
            if let Some(object) = current.child_by_field_name("object") {
                current = object;
            } else if let Some(child) = current.named_child(0) {
                current = child;
            } else {
                break;
            }
        }
        None
    }
}

/// Check if text represents a null literal for the given language
fn is_null_literal_text(text: &str, language: Language) -> bool {
    match language {
        Language::JavaScript | Language::TypeScript => text == "null" || text == "undefined",
        Language::Python => text == "None",
        Language::Go => text == "nil",
        Language::Rust => text == "None" || text == "Err", // For Option/Result
        Language::Java => text == "null",
        Language::Unknown => text == "null" || text == "nil" || text == "None",
    }
}

/// Describe a null origin for error messages
fn describe_null_origin(origin: &DefOrigin) -> &'static str {
    match origin {
        DefOrigin::FunctionCall(_) => "nullable function return",
        DefOrigin::MemberAccess(_) => "nullable member access",
        DefOrigin::Literal => "null literal",
        DefOrigin::Variable(_) => "variable",
        DefOrigin::Expression => "expression",
        DefOrigin::Parameter(_) => "parameter",
        DefOrigin::Unknown => "unknown source",
    }
}

/// Variables that are commonly unused intentionally
fn should_skip_variable(name: &str) -> bool {
    // Underscore-prefixed variables are intentionally unused
    if name.starts_with('_') {
        return true;
    }

    // Common intentionally unused names
    let skip_names = [
        "unused", "ignore", "ignored", "dummy", "temp", "tmp", "_", "__", "err",
    ];
    if skip_names.contains(&name) {
        return true;
    }

    // Very short names are often intentional placeholders
    if name.len() == 1 && name.chars().next().map_or(false, |c| c.is_lowercase()) {
        // Skip single lowercase letters except for common meaningful ones
        let meaningful = ['i', 'j', 'k', 'n', 'x', 'y', 'z'];
        if !meaningful.contains(&name.chars().next().unwrap()) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_pointer_rule_exists() {
        let rule = NullPointerRule;
        assert_eq!(rule.id(), "generic/null-pointer");
        assert!(rule.applies_to(Language::JavaScript));
        assert!(rule.applies_to(Language::Python));
        assert!(rule.applies_to(Language::Java));
        assert!(rule.uses_flow());
    }

    #[test]
    fn test_is_null_literal_text() {
        // JavaScript
        assert!(is_null_literal_text("null", Language::JavaScript));
        assert!(is_null_literal_text("undefined", Language::JavaScript));
        assert!(!is_null_literal_text("nil", Language::JavaScript));

        // Python
        assert!(is_null_literal_text("None", Language::Python));
        assert!(!is_null_literal_text("null", Language::Python));

        // Go
        assert!(is_null_literal_text("nil", Language::Go));
        assert!(!is_null_literal_text("null", Language::Go));

        // Java
        assert!(is_null_literal_text("null", Language::Java));
        assert!(!is_null_literal_text("nil", Language::Java));

        // Rust (Option/Result)
        assert!(is_null_literal_text("None", Language::Rust));
        assert!(is_null_literal_text("Err", Language::Rust));
    }

    #[test]
    fn test_describe_null_origin() {
        assert_eq!(
            describe_null_origin(&DefOrigin::FunctionCall("test".to_string())),
            "nullable function return"
        );
        assert_eq!(
            describe_null_origin(&DefOrigin::MemberAccess("x.get".to_string())),
            "nullable member access"
        );
        assert_eq!(describe_null_origin(&DefOrigin::Literal), "null literal");
    }

    #[test]
    fn test_null_analyzer_nullable_patterns() {
        use crate::semantics::LanguageSemantics;

        let js_semantics = LanguageSemantics::for_language(Language::JavaScript);
        let analyzer = NullAnalyzer::new(Language::JavaScript, js_semantics);

        // Test nullable function calls
        assert!(
            analyzer.is_potentially_null_origin(&DefOrigin::FunctionCall("arr.find".to_string()))
        );
        assert!(
            analyzer.is_potentially_null_origin(&DefOrigin::FunctionCall("map.get".to_string()))
        );
        assert!(
            analyzer.is_potentially_null_origin(&DefOrigin::MemberAccess("obj.find()".to_string()))
        );

        // Test non-nullable patterns
        assert!(!analyzer.is_potentially_null_origin(&DefOrigin::Literal));
        assert!(!analyzer.is_potentially_null_origin(&DefOrigin::Variable("x".to_string())));
    }

    #[test]
    fn test_should_skip_variable() {
        assert!(should_skip_variable("_"));
        assert!(should_skip_variable("_unused"));
        assert!(should_skip_variable("err"));
        assert!(!should_skip_variable("result"));
        assert!(!should_skip_variable("user"));
    }
}
