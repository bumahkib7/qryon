//! Forward taint propagation analysis
//!
//! Tracks which variables contain tainted (user-controlled) data
//! by propagating taint through assignments.
//!
//! Supports cross-file taint tracking via CallGraph integration.

use super::cfg::CFG;
use super::interprocedural::TaintSummary;
use super::sources::{SourcePattern, TaintConfig};
use super::symbol_table::{SymbolTable, ValueOrigin};
use crate::callgraph::CallGraph;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Taint level for path-sensitive analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintLevel {
    /// Variable is clean (never tainted, or sanitized on all paths)
    Clean,
    /// Variable is tainted on some paths but not others
    Partial,
    /// Variable is tainted on all paths to this point
    Full,
}

/// Taint analyzer that propagates taint through the symbol table
pub struct TaintAnalyzer;

impl TaintAnalyzer {
    /// Analyze symbol table and determine which variables are tainted
    pub fn analyze(symbols: &SymbolTable, config: &TaintConfig) -> TaintResult {
        Self::analyze_with_call_graph(symbols, config, None, None, None)
    }

    /// Analyze with optional CallGraph for cross-file taint tracking
    ///
    /// # Arguments
    /// * `symbols` - Symbol table from the file being analyzed
    /// * `config` - Taint configuration (sources, sinks, sanitizers)
    /// * `call_graph` - Optional call graph for cross-file function lookups
    /// * `file_path` - Current file path (required if call_graph is provided)
    /// * `cross_file_summaries` - Optional summaries from other files for cross-file taint
    pub fn analyze_with_call_graph(
        symbols: &SymbolTable,
        config: &TaintConfig,
        call_graph: Option<&CallGraph>,
        file_path: Option<&Path>,
        cross_file_summaries: Option<&HashMap<String, TaintSummary>>,
    ) -> TaintResult {
        let mut tainted = HashSet::new();
        let mut sanitization_points: HashMap<String, Vec<usize>> = HashMap::new();
        let mut cross_file_sources: HashSet<String> = HashSet::new();

        // Phase 1: Mark initial taint from sources
        for (name, info) in symbols.iter() {
            if Self::is_initially_tainted(&info.initializer, config) {
                tainted.insert(name.clone());
            }
        }

        // Phase 1.5: Check cross-file sources if call graph is available
        if let (Some(cg), Some(fp)) = (call_graph, file_path) {
            for (name, info) in symbols.iter() {
                if let ValueOrigin::FunctionCall(func_name) = &info.initializer {
                    // Check if this function call is a cross-file source
                    if let Some(is_source) =
                        Self::check_cross_file_source(func_name, cg, fp, cross_file_summaries)
                    {
                        if is_source {
                            tainted.insert(name.clone());
                            cross_file_sources.insert(name.clone());
                        }
                    }
                }
            }
        }

        // Phase 2: Propagate taint through assignments (fixed-point iteration)
        // If x = tainted_var, then x is tainted too
        // If x = sanitize(tainted_var), then x is NOT tainted
        loop {
            let mut changed = false;

            for (name, info) in symbols.iter() {
                if tainted.contains(name) {
                    continue;
                }

                // Check initializer
                let (propagates, is_sanitizer) =
                    Self::propagates_taint_with_sanitizer_and_call_graph(
                        &info.initializer,
                        &tainted,
                        config,
                        call_graph,
                        file_path,
                        cross_file_summaries,
                    );
                if propagates {
                    tainted.insert(name.clone());
                    changed = true;
                    continue;
                }
                if is_sanitizer {
                    // Track sanitization point using the declaration node id
                    sanitization_points
                        .entry(name.clone())
                        .or_default()
                        .push(info.declaration_node_id);
                }

                // Check all reassignments
                for origin in &info.reassignments {
                    let (propagates, is_sanitizer) =
                        Self::propagates_taint_with_sanitizer_and_call_graph(
                            origin,
                            &tainted,
                            config,
                            call_graph,
                            file_path,
                            cross_file_summaries,
                        );
                    if propagates {
                        tainted.insert(name.clone());
                        changed = true;
                        break;
                    }
                    if is_sanitizer {
                        sanitization_points
                            .entry(name.clone())
                            .or_default()
                            .push(info.declaration_node_id);
                    }
                }
            }

            if !changed {
                break;
            }
        }

        TaintResult {
            tainted_vars: tainted,
            sanitization_points,
            cross_file_sources,
            file: file_path.map(|p| p.to_path_buf()),
        }
    }

    /// Check if a function call to another file is a taint source
    fn check_cross_file_source(
        func_name: &str,
        call_graph: &CallGraph,
        current_file: &Path,
        cross_file_summaries: Option<&HashMap<String, TaintSummary>>,
    ) -> Option<bool> {
        // Look up the function in the call graph
        let functions = call_graph.get_functions_by_name(func_name);

        for func in functions {
            // Skip functions in the same file
            if func.file == current_file {
                continue;
            }

            // Check if we have a summary for this cross-file function
            if let Some(summaries) = cross_file_summaries {
                let key = format!("{}:{}", func.file.display(), func_name);
                if let Some(summary) = summaries.get(&key) {
                    if summary.is_source() {
                        return Some(true);
                    }
                }
                // Also check by just the function name
                if let Some(summary) = summaries.get(func_name) {
                    if summary.is_source() {
                        return Some(true);
                    }
                }
            }
        }

        None
    }

    /// Check if a function call from another file propagates taint
    #[allow(dead_code)]
    fn check_cross_file_taint_propagation(
        func_name: &str,
        call_graph: &CallGraph,
        current_file: &Path,
        cross_file_summaries: Option<&HashMap<String, TaintSummary>>,
    ) -> Option<bool> {
        let functions = call_graph.get_functions_by_name(func_name);

        for func in functions {
            if func.file == current_file {
                continue;
            }

            if let Some(summaries) = cross_file_summaries {
                let key = format!("{}:{}", func.file.display(), func_name);
                if let Some(summary) = summaries.get(&key) {
                    // Check if any parameter taints the return value
                    if summary.propagates_taint {
                        return Some(true);
                    }
                }
                if let Some(summary) = summaries.get(func_name) {
                    if summary.propagates_taint {
                        return Some(true);
                    }
                }
            }
        }

        None
    }

    /// Check if taint propagates, considering cross-file function calls
    fn propagates_taint_with_sanitizer_and_call_graph(
        origin: &ValueOrigin,
        tainted: &HashSet<String>,
        config: &TaintConfig,
        call_graph: Option<&CallGraph>,
        file_path: Option<&Path>,
        cross_file_summaries: Option<&HashMap<String, TaintSummary>>,
    ) -> (bool, bool) {
        match origin {
            ValueOrigin::FunctionCall(func_name) => {
                if config.is_sanitizer(func_name) {
                    return (false, true);
                }
                if config.is_source_function(func_name) {
                    return (true, false);
                }

                // Check cross-file sources
                if let (Some(cg), Some(fp)) = (call_graph, file_path) {
                    if let Some(is_source) =
                        Self::check_cross_file_source(func_name, cg, fp, cross_file_summaries)
                    {
                        if is_source {
                            return (true, false);
                        }
                    }
                }

                (false, false)
            }
            ValueOrigin::Variable(src_name) => (tainted.contains(src_name), false),
            ValueOrigin::MemberAccess(path) => (config.is_source_member(path), false),

            // String concatenation: tainted if ANY operand variable is tainted
            ValueOrigin::StringConcat(variables) => {
                let any_tainted = variables.iter().any(|var| {
                    // Check direct variable taint
                    if tainted.contains(var) {
                        return true;
                    }
                    // Check if it's a member access that's a source (e.g., req.query)
                    if config.is_source_member(var) {
                        return true;
                    }
                    // Check partial matches (e.g., "req.query.id" contains "req.query")
                    for tainted_var in tainted {
                        if var.starts_with(tainted_var) || tainted_var.starts_with(var) {
                            return true;
                        }
                    }
                    false
                });
                (any_tainted, false)
            }

            // Template literals: tainted if ANY interpolated variable is tainted
            ValueOrigin::TemplateLiteral(variables) => {
                let any_tainted = variables.iter().any(|var| {
                    if tainted.contains(var) {
                        return true;
                    }
                    if config.is_source_member(var) {
                        return true;
                    }
                    for tainted_var in tainted {
                        if var.starts_with(tainted_var) || tainted_var.starts_with(var) {
                            return true;
                        }
                    }
                    false
                });
                (any_tainted, false)
            }

            // Method calls: check if receiver or any argument is tainted
            ValueOrigin::MethodCall {
                method,
                receiver,
                arguments,
            } => {
                // Check if it's a sanitizer method
                if config.is_sanitizer(method) {
                    return (false, true);
                }

                // String methods that propagate taint
                let propagating_methods = [
                    "concat",
                    "join",
                    "format",
                    "replace",
                    "trim",
                    "toLowerCase",
                    "toUpperCase",
                    "slice",
                    "substring",
                    "substr",
                    "split",
                    "repeat",
                    "padStart",
                    "padEnd",
                    "append",
                    "push_str",
                    "to_string",
                    "to_str",
                    "sprintf",
                    "printf",
                    "Sprintf",
                    "Join",
                    "Format",
                    "format!",
                ];

                let is_propagating = propagating_methods
                    .iter()
                    .any(|m| method.eq_ignore_ascii_case(m) || method.contains(m));

                if is_propagating {
                    // Check if receiver is tainted
                    if let Some(recv) = receiver {
                        if tainted.contains(recv) || config.is_source_member(recv) {
                            return (true, false);
                        }
                    }

                    // Check if any argument is tainted
                    let args_tainted = arguments.iter().any(|arg| {
                        if tainted.contains(arg) {
                            return true;
                        }
                        if config.is_source_member(arg) {
                            return true;
                        }
                        for tainted_var in tainted {
                            if arg.starts_with(tainted_var) || tainted_var.starts_with(arg) {
                                return true;
                            }
                        }
                        false
                    });

                    return (args_tainted, false);
                }

                (false, false)
            }

            // Legacy binary expression - try to be conservative
            ValueOrigin::BinaryExpression => (false, false),
            ValueOrigin::Literal(_) => (false, false),
            ValueOrigin::Parameter(_) => (false, false),
            ValueOrigin::Unknown => (false, false),
        }
    }

    /// Check if taint propagates and whether a sanitizer is applied
    /// Returns (propagates_taint, is_sanitizer_call)
    #[allow(dead_code)]
    fn propagates_taint_with_sanitizer(
        origin: &ValueOrigin,
        tainted: &HashSet<String>,
        config: &TaintConfig,
    ) -> (bool, bool) {
        Self::propagates_taint_with_sanitizer_and_call_graph(
            origin, tainted, config, None, None, None,
        )
    }

    /// Check if a value origin is an initial taint source
    fn is_initially_tainted(origin: &ValueOrigin, config: &TaintConfig) -> bool {
        match origin {
            // All function parameters are conservatively tainted
            ValueOrigin::Parameter(_) => config
                .sources
                .iter()
                .any(|s| matches!(s.pattern, SourcePattern::Parameter)),

            // Check if function call is a source
            ValueOrigin::FunctionCall(func_name) => config.is_source_function(func_name),

            // Check if member access is a source
            ValueOrigin::MemberAccess(path) => config.is_source_member(path),

            // Literals are never tainted
            ValueOrigin::Literal(_) => false,

            // Variables need propagation analysis
            ValueOrigin::Variable(_) => false,

            // Binary expressions need deeper analysis
            ValueOrigin::BinaryExpression => false,

            // String concatenation: check if any operand is directly a source
            ValueOrigin::StringConcat(variables) => {
                variables.iter().any(|var| config.is_source_member(var))
            }

            // Template literals: check if any interpolation is directly a source
            ValueOrigin::TemplateLiteral(variables) => {
                variables.iter().any(|var| config.is_source_member(var))
            }

            // Method calls: check if it's a source function or has source arguments
            ValueOrigin::MethodCall {
                method,
                receiver,
                arguments,
            } => {
                // Check if method itself is a source
                if config.is_source_function(method) {
                    return true;
                }
                // Check if receiver is a source
                if let Some(recv) = receiver {
                    if config.is_source_member(recv) {
                        return true;
                    }
                }
                // Check arguments
                arguments.iter().any(|arg| config.is_source_member(arg))
            }

            // Unknown is conservatively not tainted (would cause too many FPs)
            ValueOrigin::Unknown => false,
        }
    }
}

/// Result of taint analysis
#[derive(Debug, Default)]
pub struct TaintResult {
    /// Set of variable names that are tainted
    pub tainted_vars: HashSet<String>,
    /// Map of variable name to the block ID where it was sanitized
    /// Used for path-sensitive analysis
    pub sanitization_points: HashMap<String, Vec<usize>>,
    /// Variables tainted from cross-file sources
    pub cross_file_sources: HashSet<String>,
    /// File this result is for (if single-file analysis)
    pub file: Option<PathBuf>,
}

impl TaintResult {
    /// Check if a variable is tainted
    pub fn is_tainted(&self, var_name: &str) -> bool {
        self.tainted_vars.contains(var_name)
    }

    /// Check if a variable is tainted from a cross-file source
    pub fn is_tainted_from_cross_file(&self, var_name: &str) -> bool {
        self.cross_file_sources.contains(var_name)
    }

    /// Check if any of the given variables is tainted
    pub fn any_tainted(&self, var_names: &[&str]) -> bool {
        var_names
            .iter()
            .any(|name| self.tainted_vars.contains(*name))
    }

    /// Get count of tainted variables
    pub fn tainted_count(&self) -> usize {
        self.tainted_vars.len()
    }

    /// Get count of variables tainted from cross-file sources
    pub fn cross_file_tainted_count(&self) -> usize {
        self.cross_file_sources.len()
    }

    /// Get all variables tainted from cross-file sources
    pub fn cross_file_tainted_vars(&self) -> &HashSet<String> {
        &self.cross_file_sources
    }

    /// Get the taint level of a variable at a specific program point
    ///
    /// Uses the CFG to determine if sanitization is guaranteed on all paths.
    pub fn taint_level_at(&self, var_name: &str, node_id: usize, cfg: &CFG) -> TaintLevel {
        // If the variable is not in the tainted set, it's clean
        if !self.tainted_vars.contains(var_name) {
            return TaintLevel::Clean;
        }

        // Check if there are sanitization points for this variable
        let sanitization_blocks = match self.sanitization_points.get(var_name) {
            Some(blocks) if !blocks.is_empty() => blocks,
            _ => {
                // No sanitization - fully tainted
                return TaintLevel::Full;
            }
        };

        // Get the block containing the node
        let target_block = match cfg.block_of(node_id) {
            Some(b) => b,
            None => return TaintLevel::Full,
        };

        // Check if ALL paths to target_block go through at least one sanitization point
        let mut all_paths_sanitized = true;
        let mut some_paths_sanitized = false;

        for &sanitize_block in sanitization_blocks {
            if cfg.all_paths_through(target_block, sanitize_block) {
                some_paths_sanitized = true;
            } else if cfg.has_path_bypassing(target_block, sanitize_block) {
                // Can reach target without going through this sanitizer
                all_paths_sanitized = false;
            }
        }

        if all_paths_sanitized && some_paths_sanitized {
            TaintLevel::Clean
        } else if some_paths_sanitized {
            TaintLevel::Partial
        } else {
            TaintLevel::Full
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::symbol_table::SymbolTable;
    use rma_common::Language;
    use rma_parser::ParserEngine;
    use std::path::Path;

    fn parse_js(code: &str) -> rma_parser::ParsedFile {
        let config = rma_common::RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser
            .parse_file(Path::new("test.js"), code)
            .expect("parse failed")
    }

    #[test]
    fn test_parameter_taint() {
        let code = r#"
            function handler(userInput) {
                const data = userInput;
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        // userInput is a parameter, should be tainted
        assert!(result.is_tainted("userInput"));
        // data is assigned from userInput, should propagate
        assert!(result.is_tainted("data"));
    }

    #[test]
    fn test_source_taint() {
        let code = r#"
            const query = req.query;
            const body = req.body;
            const safe = "literal";
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("query"));
        assert!(result.is_tainted("body"));
        assert!(!result.is_tainted("safe"));
    }

    #[test]
    fn test_sanitizer_stops_taint() {
        let code = r#"
            function handler(userInput) {
                const safe = encodeURIComponent(userInput);
                const sanitized = DOMPurify.sanitize(userInput);
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        // userInput is tainted (parameter)
        assert!(result.is_tainted("userInput"));
        // But safe and sanitized should NOT be tainted (sanitizer applied)
        assert!(!result.is_tainted("safe"));
        assert!(!result.is_tainted("sanitized"));
    }

    #[test]
    fn test_taint_propagation_chain() {
        let code = r#"
            function handler(userInput) {
                const a = userInput;
                const b = a;
                const c = b;
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("userInput"));
        assert!(result.is_tainted("a"));
        assert!(result.is_tainted("b"));
        assert!(result.is_tainted("c"));
    }

    #[test]
    fn test_literal_not_tainted() {
        let code = r#"
            const safe1 = "hello";
            const safe2 = 42;
            const safe3 = true;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(!result.is_tainted("safe1"));
        assert!(!result.is_tainted("safe2"));
        assert!(!result.is_tainted("safe3"));
    }

    // =========================================================================
    // String Concatenation Taint Tracking Tests
    // =========================================================================

    #[test]
    fn test_string_concat_binary_plus() {
        // Test: "SELECT " + userInput should be tainted
        let code = r#"
            function handler(userInput) {
                const query = "SELECT * FROM users WHERE id = " + userInput;
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        // userInput is a parameter, should be tainted
        assert!(
            result.is_tainted("userInput"),
            "userInput should be tainted as a parameter"
        );
        // query is a concatenation with tainted variable, should be tainted
        assert!(
            result.is_tainted("query"),
            "query should be tainted due to string concatenation with userInput"
        );
    }

    #[test]
    fn test_string_concat_chain() {
        // Test: chained concatenation preserves taint
        let code = r#"
            function handler(userInput) {
                const a = "prefix" + userInput;
                const b = a + " suffix";
                const c = "SELECT " + b + " FROM table";
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("userInput"));
        assert!(result.is_tainted("a"), "a should be tainted");
        assert!(result.is_tainted("b"), "b should be tainted via chain");
        assert!(result.is_tainted("c"), "c should be tainted via chain");
    }

    #[test]
    fn test_template_literal_taint() {
        // Test: template literals with interpolation should be tainted
        let code = r#"
            function handler(userInput) {
                const query = `SELECT * FROM users WHERE id = ${userInput}`;
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("userInput"));
        assert!(
            result.is_tainted("query"),
            "template literal with tainted interpolation should be tainted"
        );
    }

    #[test]
    fn test_template_literal_multiple_interpolations() {
        // Test: template literal with multiple interpolations
        let code = r#"
            function handler(name, id) {
                const safe = "safe";
                const query = `SELECT ${safe} FROM users WHERE name = '${name}' AND id = ${id}`;
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        // name and id are parameters, should be tainted
        assert!(result.is_tainted("name"));
        assert!(result.is_tainted("id"));
        // safe is a literal, not tainted
        assert!(!result.is_tainted("safe"));
        // query has tainted interpolations
        assert!(
            result.is_tainted("query"),
            "template with tainted interpolations should be tainted"
        );
    }

    #[test]
    fn test_concat_with_source_member() {
        // Test: concatenation with req.query should be tainted
        let code = r#"
            const id = req.query.id;
            const query = "SELECT * FROM users WHERE id = " + id;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(
            result.is_tainted("id"),
            "id from req.query should be tainted"
        );
        assert!(
            result.is_tainted("query"),
            "concatenation with tainted id should be tainted"
        );
    }

    #[test]
    fn test_concat_method_call() {
        // Test: str.concat() should propagate taint
        let code = r#"
            function handler(userInput) {
                const prefix = "SELECT ";
                const query = prefix.concat(userInput);
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("userInput"));
        assert!(
            result.is_tainted("query"),
            "concat() with tainted argument should produce tainted result"
        );
    }

    #[test]
    fn test_join_method_taint() {
        // Test: arr.join() with tainted variable in join call
        // Note: Array literal taint tracking is a more advanced feature.
        // For now, we test that join() propagates taint from its receiver.
        let code = r#"
            function handler(userInput) {
                const taintedParts = userInput.split(",");
                const query = taintedParts.join(" ");
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("userInput"));
        // taintedParts comes from splitting a tainted string
        assert!(
            result.is_tainted("taintedParts"),
            "split result should be tainted"
        );
        // join on a tainted array should produce tainted result
        assert!(
            result.is_tainted("query"),
            "join on tainted array should produce tainted result"
        );
    }

    #[test]
    fn test_safe_concatenation() {
        // Test: concatenation of only safe literals should not be tainted
        let code = r#"
            const safe1 = "hello";
            const safe2 = "world";
            const result = safe1 + " " + safe2;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(!result.is_tainted("safe1"));
        assert!(!result.is_tainted("safe2"));
        assert!(
            !result.is_tainted("result"),
            "concatenation of only safe literals should not be tainted"
        );
    }

    #[test]
    fn test_sanitized_then_concat() {
        // Test: sanitized value used in concatenation should not taint result
        let code = r#"
            function handler(userInput) {
                const safe = encodeURIComponent(userInput);
                const query = "url=" + safe;
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("userInput"));
        // safe is sanitized, should not be tainted
        assert!(
            !result.is_tainted("safe"),
            "sanitized value should not be tainted"
        );
        // query uses sanitized value, should not be tainted
        assert!(
            !result.is_tainted("query"),
            "concatenation with sanitized value should not be tainted"
        );
    }

    #[test]
    fn test_sql_injection_through_concat() {
        // Complete SQL injection test case
        let code = r#"
            const input = req.query.id;
            const query = "SELECT * FROM users WHERE id = " + input;
            db.query(query);
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(
            result.is_tainted("input"),
            "input from req.query should be tainted"
        );
        assert!(
            result.is_tainted("query"),
            "SQL query with tainted input should be tainted"
        );
        // This demonstrates the taint flow that would trigger SQL injection detection
    }

    #[test]
    fn test_complex_expression_taint() {
        // Test: complex expression with method calls
        let code = r#"
            function handler(userInput) {
                const clean = userInput.trim();
                const upper = clean.toUpperCase();
                const query = "SELECT " + upper;
            }
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let result = TaintAnalyzer::analyze(&symbols, &config);

        assert!(result.is_tainted("userInput"));
        // trim() and toUpperCase() don't sanitize
        assert!(result.is_tainted("clean"), "trim() should propagate taint");
        assert!(
            result.is_tainted("upper"),
            "toUpperCase() should propagate taint"
        );
        assert!(
            result.is_tainted("query"),
            "concatenation with tainted value should be tainted"
        );
    }
}
