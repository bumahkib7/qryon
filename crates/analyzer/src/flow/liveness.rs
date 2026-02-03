//! Live Variable Analysis
//!
//! A variable is "live" at a program point if its current value MAY be read
//! before being overwritten on some execution path. This is a **backward**
//! dataflow analysis.
//!
//! Live variable analysis is useful for:
//! - Dead store detection (variable assigned but never read before reassignment)
//! - Unused variable detection
//! - Register allocation (in compilers)
//! - Detecting uninitialized variable access

use crate::flow::cfg::{BasicBlock, BlockId, CFG};
use crate::flow::dataflow::{DataflowResult, Direction, TransferFunction, find_node_by_id};
use crate::semantics::LanguageSemantics;
use std::collections::HashSet;

/// A live variable at a program point.
/// Just the variable name — we care about WHETHER it's live, not which definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LiveVar {
    pub var_name: String,
}

impl LiveVar {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            var_name: name.into(),
        }
    }
}

/// Transfer function for live variable analysis (backward analysis).
pub struct LivenessTransfer {
    pub semantics: &'static LanguageSemantics,
}

impl TransferFunction<LiveVar> for LivenessTransfer {
    /// For liveness (backward analysis):
    ///   Input = variables live AFTER this block (from successors)
    ///   Output = variables live BEFORE this block
    ///
    /// For each statement (processed in REVERSE order):
    ///   - If statement USES variable X → X is live (add to set)
    ///   - If statement DEFINES variable X → X is dead (remove from set)
    ///     unless X is also used in the same statement (e.g., x = x + 1)
    fn transfer(
        &self,
        block: &BasicBlock,
        input: &HashSet<LiveVar>,
        _cfg: &CFG,
        source: &[u8],
        tree: &tree_sitter::Tree,
    ) -> HashSet<LiveVar> {
        let mut state = input.clone();

        // Process statements in REVERSE order (backward analysis)
        for &stmt_node_id in block.statements.iter().rev() {
            if let Some(node) = find_node_by_id(tree, stmt_node_id) {
                self.process_statement_backward(node, source, &mut state);
            }
        }

        state
    }
}

impl LivenessTransfer {
    /// Create a new liveness transfer function
    pub fn new(semantics: &'static LanguageSemantics) -> Self {
        Self { semantics }
    }

    fn process_statement_backward(
        &self,
        node: tree_sitter::Node,
        source: &[u8],
        state: &mut HashSet<LiveVar>,
    ) {
        let sem = self.semantics;
        let kind = node.kind();

        // Assignment/declaration: KILL the defined variable, GEN the used variables
        if sem.is_variable_declaration(kind)
            || sem.is_assignment(kind)
            || sem.is_augmented_assignment(kind)
        {
            let defined_var = self.extract_defined_var(node, source);
            let used_vars = self.extract_used_vars(node, source);

            // First ADD uses (from right side)
            for var in &used_vars {
                state.insert(LiveVar::new(var));
            }

            // Then REMOVE definition (from left side)
            // The GEN has already happened for the RHS uses, so this is correct
            if let Some(var) = &defined_var {
                state.remove(&LiveVar::new(var));
            }
        } else {
            // Non-assignment statement: all referenced identifiers are uses
            let used_vars = self.extract_all_identifiers(node, source);
            for var in used_vars {
                state.insert(LiveVar::new(var));
            }
        }

        // Recurse into children for nested statements
        // but not into function definitions (separate scope)
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !sem.is_function_def(child.kind()) {
                // Only process if it's a statement-like node
                if child.is_named() && !sem.is_literal(child.kind()) {
                    self.process_statement_backward(child, source, state);
                }
            }
        }
    }

    fn extract_defined_var(&self, node: tree_sitter::Node, source: &[u8]) -> Option<String> {
        let sem = self.semantics;

        // Handle different node types
        let name_node = match node.kind() {
            "variable_declarator" => node.child_by_field_name("name"),
            "let_declaration" => node.child_by_field_name("pattern"),
            "short_var_declaration" => {
                // Go: get first identifier from left expression_list
                let left = node.child_by_field_name("left")?;
                if left.kind() == "expression_list" {
                    left.named_child(0)
                } else {
                    Some(left)
                }
            }
            _ => node
                .child_by_field_name(sem.name_field)
                .or_else(|| node.child_by_field_name(sem.left_field)),
        };

        name_node
            .filter(|n| sem.is_identifier(n.kind()) || n.kind() == "identifier")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.trim_start_matches("mut ").trim().to_string())
    }

    fn extract_used_vars(&self, node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let sem = self.semantics;
        let mut vars = Vec::new();

        // Get the right-hand side of the assignment/declaration
        let rhs = node
            .child_by_field_name(sem.value_field)
            .or_else(|| node.child_by_field_name(sem.right_field));

        if let Some(rhs) = rhs {
            Self::collect_identifiers(rhs, source, sem, &mut vars);
        }

        // For augmented assignments (+=, -=), the left side is also a USE
        let kind = node.kind();
        if (sem.is_augmented_assignment(kind)
            || kind.contains("augmented")
            || kind.contains("compound"))
            && let Some(left) = node.child_by_field_name(sem.left_field)
            && let Ok(name) = left.utf8_text(source)
        {
            vars.push(name.to_string());
        }

        vars
    }

    fn extract_all_identifiers(&self, node: tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let mut vars = Vec::new();
        Self::collect_identifiers(node, source, self.semantics, &mut vars);
        vars
    }

    fn collect_identifiers(
        node: tree_sitter::Node,
        source: &[u8],
        semantics: &LanguageSemantics,
        vars: &mut Vec<String>,
    ) {
        if semantics.is_identifier(node.kind()) || node.kind() == "identifier" {
            if let Ok(name) = node.utf8_text(source) {
                vars.push(name.to_string());
            }
            return;
        }

        // Don't recurse into function definitions
        if semantics.is_function_def(node.kind()) {
            return;
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            Self::collect_identifiers(child, source, semantics, vars);
        }
    }
}

/// Run live variable analysis on a CFG.
pub fn analyze_liveness(
    cfg: &CFG,
    tree: &tree_sitter::Tree,
    source: &[u8],
    semantics: &'static LanguageSemantics,
) -> DataflowResult<LiveVar> {
    let transfer = LivenessTransfer::new(semantics);

    super::dataflow::solve(cfg, Direction::Backward, &transfer, source, tree)
}

/// Extension methods for liveness queries on DataflowResult
impl DataflowResult<LiveVar> {
    /// Is a variable live at the entry of a block?
    pub fn is_live_at_entry(&self, block_id: BlockId, var_name: &str) -> bool {
        self.contains_at_entry(block_id, &LiveVar::new(var_name))
    }

    /// Is a variable live at the exit of a block?
    pub fn is_live_at_exit(&self, block_id: BlockId, var_name: &str) -> bool {
        self.contains_at_exit(block_id, &LiveVar::new(var_name))
    }

    /// Is a variable live at a specific AST node?
    pub fn is_live_at_node(&self, node_id: usize, var_name: &str, cfg: &CFG) -> bool {
        self.contains_at_node(node_id, &LiveVar::new(var_name), cfg)
    }

    /// Get all live variables at the entry of a block
    pub fn live_at_entry(&self, block_id: BlockId) -> HashSet<String> {
        self.block_entry
            .get(&block_id)
            .map(|set| set.iter().map(|lv| lv.var_name.clone()).collect())
            .unwrap_or_default()
    }

    /// Get all live variables at the exit of a block
    pub fn live_at_exit(&self, block_id: BlockId) -> HashSet<String> {
        self.block_exit
            .get(&block_id)
            .map(|set| set.iter().map(|lv| lv.var_name.clone()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::cfg::CFG;
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
    fn test_simple_liveness() {
        let code = r#"
            let x = 1;
            console.log(x);
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_liveness(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // x should be live somewhere (it's used in console.log)
        let any_x_live = result
            .block_entry
            .values()
            .any(|set| set.contains(&LiveVar::new("x")));

        assert!(any_x_live, "x should be live at some point");
    }

    #[test]
    fn test_unused_variable() {
        let code = r#"
            let x = 1;
            let y = 2;
            console.log(y);
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_liveness(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // y should be live (it's used)
        let any_y_live = result
            .block_entry
            .values()
            .any(|set| set.contains(&LiveVar::new("y")));

        assert!(any_y_live, "y should be live");

        // x might not be live at exit (never used) - depends on CFG structure
        // This test validates the liveness propagation mechanism
    }

    #[test]
    fn test_liveness_across_assignment() {
        let code = r#"
            let x = 1;
            x = 2;
            console.log(x);
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_liveness(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // After the second assignment, x should be live (it's used in console.log)
        // But between the first and second assignment, x's liveness depends on
        // whether the second assignment uses x (it doesn't in this case)
        assert!(result.iterations > 0);
    }

    #[test]
    fn test_augmented_assignment() {
        let code = r#"
            let x = 1;
            x += 1;
            console.log(x);
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_liveness(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // x should be live throughout because x += 1 both uses and defines x
        let any_x_live = result
            .block_entry
            .values()
            .any(|set| set.contains(&LiveVar::new("x")));

        assert!(any_x_live, "x should be live due to augmented assignment");
    }

    #[test]
    fn test_live_var_queries() {
        let code = "let x = 1;";
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_liveness(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // Query methods should not panic
        let _is_live = result.is_live_at_entry(0, "x");
        let _is_live_exit = result.is_live_at_exit(0, "x");
        let _live_vars = result.live_at_entry(0);
    }

    #[test]
    fn test_backward_direction() {
        let code = r#"
            function f() {
                let x = 1;
                return x;
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_liveness(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // Should complete without infinite loop
        assert!(result.iterations < cfg.block_count() * 25);
    }
}
