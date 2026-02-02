//! Dataflow-powered rules for code quality and security analysis
//!
//! These rules use the dataflow analysis framework to detect:
//! - Dead stores (assignments that are never read)
//! - Unused variables (declarations that are never used)
//! - Cross-function taint flows (taint crossing function boundaries)
//!
//! These rules are language-agnostic and work with the CFG and dataflow results.

use crate::flow::FlowContext;
use crate::rules::{Rule, create_finding_at_line};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;

// =============================================================================
// Dead Store Rule
// =============================================================================

/// Detects dead stores: assignments to variables that are never read before
/// being overwritten or going out of scope.
///
/// Dead stores indicate:
/// - Unnecessary computation
/// - Potential bugs (intended to use the variable but forgot)
/// - Leftover code from refactoring
pub struct DeadStoreRule;

impl Rule for DeadStoreRule {
    fn id(&self) -> &str {
        "generic/dead-store"
    }

    fn description(&self) -> &str {
        "Variable is assigned but never read before being overwritten or going out of scope"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        // Works for all languages with dataflow support
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // Requires dataflow analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get dead stores from def-use chains
        let dead_stores = flow.dead_stores();

        for def in dead_stores {
            // Skip common false positives
            if should_skip_variable(&def.var_name) {
                continue;
            }

            // Skip if in test file
            if super::generic::is_test_or_fixture_file(&parsed.path) {
                continue;
            }

            let mut finding = create_finding_at_line(
                self.id(),
                &parsed.path,
                def.line,
                &format!("{} = ...", def.var_name),
                Severity::Info,
                &format!(
                    "Variable '{}' is assigned on line {} but never read",
                    def.var_name, def.line
                ),
                parsed.language,
            );
            finding.confidence = Confidence::Medium;
            findings.push(finding);
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Unused Variable Rule
// =============================================================================

/// Detects unused variables: variables that are declared but never referenced.
///
/// Unused variables indicate:
/// - Dead code
/// - Incomplete implementation
/// - Copy-paste errors
pub struct UnusedVariableRule;

impl Rule for UnusedVariableRule {
    fn id(&self) -> &str {
        "generic/unused-variable"
    }

    fn description(&self) -> &str {
        "Variable is declared but never used"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check def-use chains for definitions with no uses
        if let Some(chains) = flow.def_use_chains() {
            for (def, uses) in &chains.def_to_uses {
                if uses.is_empty() && !should_skip_variable(&def.var_name) {
                    // Skip test files
                    if super::generic::is_test_or_fixture_file(&parsed.path) {
                        continue;
                    }

                    // Only report if the variable is actually defined (not just a declaration)
                    // Parameters are expected to potentially be unused
                    if matches!(
                        def.origin,
                        crate::flow::reaching_defs::DefOrigin::Parameter(_)
                    ) {
                        continue;
                    }

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        def.line,
                        &def.var_name,
                        Severity::Info,
                        &format!(
                            "Variable '{}' is declared on line {} but never used",
                            def.var_name, def.line
                        ),
                        parsed.language,
                    );
                    finding.confidence = Confidence::Medium;
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Cross-Function Taint Rule
// =============================================================================

/// Detects cross-function taint flows: taint originating in one function
/// that reaches a sink in another function.
///
/// These flows are harder to track manually and represent security risks:
/// - Input validation bypass (validation in wrong function)
/// - Unintended data exposure
/// - Complex attack vectors
pub struct CrossFunctionTaintRule;

impl Rule for CrossFunctionTaintRule {
    fn id(&self) -> &str {
        "generic/cross-function-taint"
    }

    fn description(&self) -> &str {
        "Tainted data flows from one function to a sink in another function"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get interprocedural taint flows
        if let Some(interproc) = flow.interprocedural_result() {
            for taint_flow in interproc.interprocedural_flows() {
                // Skip test files
                if super::generic::is_test_or_fixture_file(&parsed.path) {
                    continue;
                }

                let functions_str = taint_flow.functions_involved.join(" -> ");
                let kind_str = format!("{:?}", taint_flow.source.kind);

                let mut finding = create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    taint_flow.sink.line,
                    &taint_flow.sink.name,
                    Severity::Error,
                    &format!(
                        "Tainted data ({}) flows from '{}' (line {}) to sink '{}' (line {}) across functions: {}",
                        kind_str,
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        functions_str
                    ),
                    parsed.language,
                );
                finding.confidence = Confidence::Medium;
                findings.push(finding);
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Uninitialized Variable Rule
// =============================================================================

/// Detects potential use of uninitialized variables.
///
/// Uses reaching definitions: if a variable is used at a point where
/// no definition reaches, it may be uninitialized.
pub struct UninitializedVariableRule;

impl Rule for UninitializedVariableRule {
    fn id(&self) -> &str {
        "generic/uninitialized-variable"
    }

    fn description(&self) -> &str {
        "Variable may be used before being initialized"
    }

    fn applies_to(&self, lang: Language) -> bool {
        // Most useful for languages without strict initialization
        matches!(
            lang,
            Language::JavaScript | Language::TypeScript | Language::Python
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for uses without reaching definitions
        if let Some(chains) = flow.def_use_chains() {
            for (use_site, defs) in &chains.use_to_defs {
                if defs.is_empty() && !should_skip_variable(&use_site.var_name) {
                    // Skip test files
                    if super::generic::is_test_or_fixture_file(&parsed.path) {
                        continue;
                    }

                    // Skip global/builtin names
                    if is_likely_global(&use_site.var_name) {
                        continue;
                    }

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        use_site.line,
                        &use_site.var_name,
                        Severity::Warning,
                        &format!(
                            "Variable '{}' may be used on line {} before being initialized",
                            use_site.var_name, use_site.line
                        ),
                        parsed.language,
                    );
                    finding.confidence = Confidence::Low; // Conservative
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

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

/// Check if a name is likely a global/builtin
fn is_likely_global(name: &str) -> bool {
    // JavaScript/TypeScript globals
    let js_globals = [
        "console",
        "window",
        "document",
        "process",
        "global",
        "require",
        "module",
        "exports",
        "Buffer",
        "setTimeout",
        "setInterval",
        "clearTimeout",
        "clearInterval",
        "Promise",
        "fetch",
        "JSON",
        "Math",
        "Object",
        "Array",
        "String",
        "Number",
        "Boolean",
        "Date",
        "Error",
        "undefined",
        "null",
        "NaN",
        "Infinity",
    ];

    // Python builtins
    let py_builtins = [
        "print",
        "len",
        "range",
        "str",
        "int",
        "float",
        "list",
        "dict",
        "set",
        "tuple",
        "open",
        "True",
        "False",
        "None",
        "type",
        "isinstance",
        "hasattr",
        "getattr",
        "setattr",
        "super",
        "self",
        "cls",
    ];

    js_globals.contains(&name) || py_builtins.contains(&name)
}

/// Get all dataflow-powered rules
pub fn dataflow_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DeadStoreRule),
        Box::new(UnusedVariableRule),
        Box::new(CrossFunctionTaintRule),
        Box::new(UninitializedVariableRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_underscore_variables() {
        assert!(should_skip_variable("_"));
        assert!(should_skip_variable("_unused"));
        assert!(should_skip_variable("__"));
        assert!(!should_skip_variable("x"));
        assert!(!should_skip_variable("data"));
    }

    #[test]
    fn test_skip_common_unused_names() {
        assert!(should_skip_variable("unused"));
        assert!(should_skip_variable("ignore"));
        assert!(should_skip_variable("dummy"));
        assert!(should_skip_variable("err")); // Common Go pattern
    }

    #[test]
    fn test_is_likely_global() {
        assert!(is_likely_global("console"));
        assert!(is_likely_global("window"));
        assert!(is_likely_global("print"));
        assert!(is_likely_global("len"));
        assert!(!is_likely_global("myVariable"));
        assert!(!is_likely_global("userData"));
    }

    #[test]
    fn test_rules_implement_trait() {
        let rules = dataflow_rules();
        assert!(!rules.is_empty());

        for rule in &rules {
            assert!(!rule.id().is_empty());
            assert!(!rule.description().is_empty());
            assert!(rule.uses_flow());
        }
    }
}
