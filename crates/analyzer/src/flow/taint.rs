//! Forward taint propagation analysis
//!
//! Tracks which variables contain tainted (user-controlled) data
//! by propagating taint through assignments.

use super::cfg::CFG;
use super::sources::{SourcePattern, TaintConfig};
use super::symbol_table::{SymbolTable, ValueOrigin};
use std::collections::{HashMap, HashSet};

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
        let mut tainted = HashSet::new();
        let mut sanitization_points: HashMap<String, Vec<usize>> = HashMap::new();

        // Phase 1: Mark initial taint from sources
        for (name, info) in symbols.iter() {
            if Self::is_initially_tainted(&info.initializer, config) {
                tainted.insert(name.clone());
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
                    Self::propagates_taint_with_sanitizer(&info.initializer, &tainted, config);
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
                        Self::propagates_taint_with_sanitizer(origin, &tainted, config);
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
        }
    }

    /// Check if taint propagates and whether a sanitizer is applied
    /// Returns (propagates_taint, is_sanitizer_call)
    fn propagates_taint_with_sanitizer(
        origin: &ValueOrigin,
        tainted: &HashSet<String>,
        config: &TaintConfig,
    ) -> (bool, bool) {
        match origin {
            ValueOrigin::FunctionCall(func_name) => {
                if config.is_sanitizer(func_name) {
                    // It's a sanitizer - doesn't propagate, but mark it
                    (false, true)
                } else if config.is_source_function(func_name) {
                    (true, false)
                } else {
                    (false, false)
                }
            }
            ValueOrigin::Variable(src_name) => (tainted.contains(src_name), false),
            ValueOrigin::MemberAccess(path) => (config.is_source_member(path), false),
            ValueOrigin::BinaryExpression => (false, false),
            ValueOrigin::Literal(_) => (false, false),
            ValueOrigin::Parameter(_) => (false, false),
            ValueOrigin::Unknown => (false, false),
        }
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
}

impl TaintResult {
    /// Check if a variable is tainted
    pub fn is_tainted(&self, var_name: &str) -> bool {
        self.tainted_vars.contains(var_name)
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
}
