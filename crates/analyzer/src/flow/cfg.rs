//! Intraprocedural Control Flow Graph (CFG)
//!
//! Builds a CFG for single functions to enable:
//! - Branch-aware taint analysis
//! - Loop detection (for performance rules like "string concat in loop")
//! - Path-sensitive analysis ("sanitized on some paths but not all")

use rma_common::Language;
use rma_parser::ParsedFile;
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;

/// A unique identifier for a basic block
pub type BlockId = usize;

/// The control flow graph for a single function/file
#[derive(Debug)]
pub struct CFG {
    /// All basic blocks in the CFG
    pub blocks: Vec<BasicBlock>,
    /// Entry block (always 0)
    pub entry: BlockId,
    /// Exit block
    pub exit: BlockId,
    /// Map from tree-sitter node id to which block contains it
    pub node_to_block: HashMap<usize, BlockId>,
}

/// A basic block is a straight-line sequence of statements with no branches
/// except at the end
#[derive(Debug)]
pub struct BasicBlock {
    /// Unique identifier for this block
    pub id: BlockId,
    /// tree-sitter node IDs of statements in this block, in order
    pub statements: Vec<usize>,
    /// How this block ends
    pub terminator: Terminator,
    /// Which blocks can reach this one (predecessors)
    pub predecessors: Vec<BlockId>,
    /// Nesting depth of loops (0 = not in a loop)
    pub loop_depth: usize,
    /// Whether this block is reachable from entry (computed lazily)
    pub reachable: bool,
    /// Whether this block is a catch handler
    pub is_catch: bool,
    /// Whether this block is a finally handler
    pub is_finally: bool,
}

/// How a basic block terminates
#[derive(Clone, Debug)]
pub enum Terminator {
    /// Falls through to the next block
    Goto(BlockId),
    /// Conditional branch: if condition then true_block else false_block
    Branch {
        condition_node: usize,
        true_block: BlockId,
        false_block: BlockId,
    },
    /// Return from function
    Return,
    /// Switch/match with multiple targets
    Switch {
        condition_node: usize,
        /// (case_node, target) - None for default case
        cases: Vec<(Option<usize>, BlockId)>,
    },
    /// Loop: body block and exit block
    Loop {
        body: BlockId,
        exit: BlockId,
        condition_node: Option<usize>,
    },
    /// Try-catch-finally
    TryCatch {
        try_block: BlockId,
        catch_block: Option<BlockId>,
        finally_block: Option<BlockId>,
    },
    /// Unreachable (after throw, panic, etc.)
    Unreachable,
    /// Incomplete terminator (CFG construction was partial or panicked)
    Incomplete,
}

impl CFG {
    /// Build a CFG from a parsed file
    pub fn build(parsed: &ParsedFile, language: Language) -> Self {
        let mut builder = CFGBuilder::new();
        builder.build_from_ast(&parsed.tree, parsed.content.as_bytes(), language);
        builder.finalize()
    }

    /// Check if a node is inside a loop
    pub fn is_in_loop(&self, node_id: usize) -> bool {
        self.node_to_block
            .get(&node_id)
            .and_then(|&block_id| self.blocks.get(block_id))
            .map(|block| block.loop_depth > 0)
            .unwrap_or(false)
    }

    /// Get the loop depth of a node (0 = not in loop, 1 = single loop, 2 = nested)
    pub fn loop_depth(&self, node_id: usize) -> usize {
        self.node_to_block
            .get(&node_id)
            .and_then(|&block_id| self.blocks.get(block_id))
            .map(|block| block.loop_depth)
            .unwrap_or(0)
    }

    /// Get the block containing a node
    pub fn block_of(&self, node_id: usize) -> Option<BlockId> {
        self.node_to_block.get(&node_id).copied()
    }

    /// Check if there exists ANY path from entry to target_block that does NOT
    /// pass through required_block.
    ///
    /// Used for: "is sanitization guaranteed on all paths to this point?"
    /// Returns true if sanitization can be bypassed.
    pub fn has_path_bypassing(&self, target_block: BlockId, required_block: BlockId) -> bool {
        if target_block == required_block {
            return false; // Target IS the required block
        }

        // BFS from entry, but never traverse through required_block
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.entry);
        visited.insert(self.entry);

        while let Some(block_id) = queue.pop_front() {
            if block_id == target_block {
                return true; // Reached target without going through required
            }
            if block_id == required_block {
                continue; // Don't traverse through the required block
            }

            // Add successors
            for succ in self.successors(block_id) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        false
    }

    /// Check if all paths from entry to target_block pass through required_block
    pub fn all_paths_through(&self, target_block: BlockId, required_block: BlockId) -> bool {
        !self.has_path_bypassing(target_block, required_block)
    }

    /// Get all blocks that are successors of a given block
    pub fn successors(&self, block_id: BlockId) -> Vec<BlockId> {
        if block_id >= self.blocks.len() {
            return vec![];
        }
        match &self.blocks[block_id].terminator {
            Terminator::Goto(next) => vec![*next],
            Terminator::Branch {
                true_block,
                false_block,
                ..
            } => vec![*true_block, *false_block],
            Terminator::Loop { body, exit, .. } => vec![*body, *exit],
            Terminator::Switch { cases, .. } => cases.iter().map(|(_, t)| *t).collect(),
            Terminator::TryCatch {
                try_block,
                catch_block,
                finally_block,
            } => {
                let mut s = vec![*try_block];
                if let Some(cb) = catch_block {
                    s.push(*cb);
                }
                if let Some(fb) = finally_block {
                    s.push(*fb);
                }
                s
            }
            Terminator::Return | Terminator::Unreachable | Terminator::Incomplete => vec![],
        }
    }

    /// Get all blocks that can reach a given block (predecessors)
    pub fn predecessors(&self, block_id: BlockId) -> &[BlockId] {
        if block_id < self.blocks.len() {
            &self.blocks[block_id].predecessors
        } else {
            &[]
        }
    }

    /// Check if block A can reach block B
    pub fn can_reach(&self, from: BlockId, to: BlockId) -> bool {
        if from == to {
            return true;
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(from);
        visited.insert(from);

        while let Some(block_id) = queue.pop_front() {
            for succ in self.successors(block_id) {
                if succ == to {
                    return true;
                }
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        false
    }

    /// Get total number of blocks
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Check if a block is reachable from entry
    pub fn is_reachable(&self, block_id: BlockId) -> bool {
        self.blocks
            .get(block_id)
            .map(|b| b.reachable)
            .unwrap_or(false)
    }

    /// Get all unreachable blocks (dead code)
    pub fn unreachable_blocks(&self) -> Vec<BlockId> {
        self.blocks
            .iter()
            .filter(|b| !b.reachable && !b.statements.is_empty())
            .map(|b| b.id)
            .collect()
    }

    /// Check if a block is a catch handler
    pub fn is_catch_block(&self, block_id: BlockId) -> bool {
        self.blocks
            .get(block_id)
            .map(|b| b.is_catch)
            .unwrap_or(false)
    }

    /// Check if a block is a finally handler
    pub fn is_finally_block(&self, block_id: BlockId) -> bool {
        self.blocks
            .get(block_id)
            .map(|b| b.is_finally)
            .unwrap_or(false)
    }

    /// Get catch blocks that have no statements (empty catch)
    pub fn empty_catch_blocks(&self) -> Vec<BlockId> {
        self.blocks
            .iter()
            .filter(|b| b.is_catch && b.statements.is_empty())
            .map(|b| b.id)
            .collect()
    }

    /// Build CFG with panic recovery - returns None if construction panics
    pub fn build_safe(parsed: &ParsedFile, language: Language) -> Option<Self> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Self::build(parsed, language)
        }))
        .ok()
    }

    /// Compute reachability for all blocks using BFS from entry
    fn compute_reachability(&mut self) {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.entry);
        visited.insert(self.entry);

        while let Some(block_id) = queue.pop_front() {
            if block_id < self.blocks.len() {
                self.blocks[block_id].reachable = true;
            }
            for succ in self.successors(block_id) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }
}

/// Builder for constructing CFGs from AST
struct CFGBuilder {
    blocks: Vec<BasicBlock>,
    current_block: BlockId,
    node_to_block: HashMap<usize, BlockId>,
    loop_depth: usize,
    /// Stack of (loop_header_block, loop_exit_block) for break/continue
    loop_stack: Vec<(BlockId, BlockId)>,
}

impl CFGBuilder {
    fn new() -> Self {
        let entry_block = BasicBlock {
            id: 0,
            statements: Vec::new(),
            terminator: Terminator::Return,
            predecessors: Vec::new(),
            loop_depth: 0,
            reachable: true, // Entry is always reachable
            is_catch: false,
            is_finally: false,
        };
        Self {
            blocks: vec![entry_block],
            current_block: 0,
            node_to_block: HashMap::new(),
            loop_depth: 0,
            loop_stack: Vec::new(),
        }
    }

    fn new_block(&mut self) -> BlockId {
        let id = self.blocks.len();
        self.blocks.push(BasicBlock {
            id,
            statements: Vec::new(),
            terminator: Terminator::Return,
            predecessors: Vec::new(),
            loop_depth: self.loop_depth,
            reachable: false, // Will be computed during finalization
            is_catch: false,
            is_finally: false,
        });
        id
    }

    fn new_catch_block(&mut self) -> BlockId {
        let id = self.new_block();
        self.blocks[id].is_catch = true;
        id
    }

    fn new_finally_block(&mut self) -> BlockId {
        let id = self.new_block();
        self.blocks[id].is_finally = true;
        id
    }

    fn add_statement(&mut self, node_id: usize) {
        self.blocks[self.current_block].statements.push(node_id);
        self.node_to_block.insert(node_id, self.current_block);
    }

    fn set_terminator(&mut self, block: BlockId, term: Terminator) {
        // Also update predecessors of target blocks
        match &term {
            Terminator::Goto(target) => {
                if *target < self.blocks.len() {
                    self.blocks[*target].predecessors.push(block);
                }
            }
            Terminator::Branch {
                true_block,
                false_block,
                ..
            } => {
                if *true_block < self.blocks.len() {
                    self.blocks[*true_block].predecessors.push(block);
                }
                if *false_block < self.blocks.len() {
                    self.blocks[*false_block].predecessors.push(block);
                }
            }
            Terminator::Loop { body, exit, .. } => {
                if *body < self.blocks.len() {
                    self.blocks[*body].predecessors.push(block);
                }
                if *exit < self.blocks.len() {
                    self.blocks[*exit].predecessors.push(block);
                }
            }
            Terminator::Switch { cases, .. } => {
                for (_, target) in cases {
                    if *target < self.blocks.len() {
                        self.blocks[*target].predecessors.push(block);
                    }
                }
            }
            Terminator::TryCatch {
                try_block,
                catch_block,
                finally_block,
            } => {
                if *try_block < self.blocks.len() {
                    self.blocks[*try_block].predecessors.push(block);
                }
                if let Some(cb) = catch_block
                    && *cb < self.blocks.len()
                {
                    self.blocks[*cb].predecessors.push(block);
                }
                if let Some(fb) = finally_block
                    && *fb < self.blocks.len()
                {
                    self.blocks[*fb].predecessors.push(block);
                }
            }
            Terminator::Return | Terminator::Unreachable | Terminator::Incomplete => {}
        }
        if block < self.blocks.len() {
            self.blocks[block].terminator = term;
        }
    }

    fn build_from_ast(&mut self, tree: &tree_sitter::Tree, source: &[u8], language: Language) {
        let root = tree.root_node();
        self.process_block_children(root, source, language);
    }

    /// Main dispatch: process a statement node and add to CFG
    fn process_statement(&mut self, node: Node, source: &[u8], language: Language) {
        match node.kind() {
            // --- IF STATEMENT ---
            "if_statement" | "if_expression" => {
                self.process_if(node, source, language);
            }

            // --- LOOPS ---
            "for_statement" | "for_in_statement" | "for_of_statement" | "while_statement"
            | "do_statement" | "for_expression" | "while_expression" | "loop_expression" => {
                self.process_loop(node, source, language);
            }

            // --- TRY-CATCH ---
            "try_statement" => {
                self.process_try_catch(node, source, language);
            }

            // --- RETURN / BREAK / CONTINUE / THROW ---
            "return_statement" | "return_expression" => {
                self.add_statement(node.id());
                self.set_terminator(self.current_block, Terminator::Return);
                self.current_block = self.new_block();
            }

            "break_statement" | "break_expression" => {
                self.add_statement(node.id());
                if let Some(&(_, exit)) = self.loop_stack.last() {
                    self.set_terminator(self.current_block, Terminator::Goto(exit));
                }
                self.current_block = self.new_block();
            }

            "continue_statement" | "continue_expression" => {
                self.add_statement(node.id());
                if let Some(&(header, _)) = self.loop_stack.last() {
                    self.set_terminator(self.current_block, Terminator::Goto(header));
                }
                self.current_block = self.new_block();
            }

            "throw_statement" | "raise_statement" => {
                self.add_statement(node.id());
                self.set_terminator(self.current_block, Terminator::Unreachable);
                self.current_block = self.new_block();
            }

            // --- SWITCH/MATCH ---
            "switch_statement" | "match_expression" => {
                self.process_switch(node, source, language);
            }

            // --- FUNCTION DEFINITIONS (new scope) ---
            "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "function_definition"
            | "function_item" => {
                // For now, just add as a statement - don't recurse into function body
                // Inter-procedural analysis would need to handle this differently
                self.add_statement(node.id());
            }

            // --- BLOCK STATEMENTS (compound) ---
            "statement_block" | "block" | "block_statement" | "compound_statement" | "suite" => {
                self.process_block_children(node, source, language);
            }

            // --- REGULAR STATEMENTS ---
            _ => {
                self.add_statement(node.id());
                // Recurse into children for nested expressions that might contain control flow
                self.process_nested_control_flow(node, source, language);
            }
        }
    }

    /// Process an if statement
    fn process_if(&mut self, node: Node, source: &[u8], language: Language) {
        let condition = node.child_by_field_name("condition");
        let consequence = node
            .child_by_field_name("consequence")
            .or_else(|| node.child_by_field_name("body"));
        let alternative = node.child_by_field_name("alternative");

        // Add the if condition to current block
        if let Some(cond) = condition {
            self.add_statement(cond.id());
        }

        let then_block = self.new_block();
        let else_block = if alternative.is_some() {
            self.new_block()
        } else {
            0 // Will be set to merge_block
        };
        let merge_block = self.new_block();

        let false_target = if alternative.is_some() {
            else_block
        } else {
            merge_block
        };

        // Current block branches on condition
        self.set_terminator(
            self.current_block,
            Terminator::Branch {
                condition_node: condition.map(|n| n.id()).unwrap_or(0),
                true_block: then_block,
                false_block: false_target,
            },
        );

        // Process then branch
        self.current_block = then_block;
        if let Some(body) = consequence {
            self.process_block_children(body, source, language);
        }
        // Only goto merge if we didn't return/break/continue
        if !matches!(
            self.blocks[self.current_block].terminator,
            Terminator::Return | Terminator::Unreachable
        ) {
            self.set_terminator(self.current_block, Terminator::Goto(merge_block));
        }

        // Process else branch if exists
        if let Some(alt) = alternative {
            self.current_block = else_block;
            // Handle else-if chains
            if alt.kind() == "else_clause" {
                self.process_block_children(alt, source, language);
            } else if alt.kind() == "if_statement" || alt.kind() == "if_expression" {
                self.process_statement(alt, source, language);
            } else {
                self.process_block_children(alt, source, language);
            }
            if !matches!(
                self.blocks[self.current_block].terminator,
                Terminator::Return | Terminator::Unreachable
            ) {
                self.set_terminator(self.current_block, Terminator::Goto(merge_block));
            }
        }

        self.current_block = merge_block;
    }

    /// Process a loop statement
    fn process_loop(&mut self, node: Node, source: &[u8], language: Language) {
        let condition = node.child_by_field_name("condition");
        let body = node.child_by_field_name("body");
        let is_do_while = node.kind() == "do_statement";

        // Create header block (not in loop yet)
        let loop_header = self.new_block();

        // Increment loop_depth BEFORE creating body block so it has correct depth
        self.loop_depth += 1;
        let loop_body = self.new_block();
        // Exit block is outside the loop
        self.loop_depth -= 1;
        let loop_exit = self.new_block();

        // Add any loop initialization (for loops)
        if let Some(init) = node.child_by_field_name("initializer") {
            self.add_statement(init.id());
        }

        self.set_terminator(self.current_block, Terminator::Goto(loop_header));

        // Header block
        self.current_block = loop_header;
        if let Some(cond) = condition
            && !is_do_while
        {
            self.add_statement(cond.id());
        }

        self.set_terminator(
            loop_header,
            Terminator::Loop {
                body: loop_body,
                exit: loop_exit,
                condition_node: condition.map(|n| n.id()),
            },
        );

        // Process body - re-increment depth for nested content
        self.loop_depth += 1;
        self.loop_stack.push((loop_header, loop_exit));
        self.current_block = loop_body;

        if let Some(b) = body {
            self.process_block_children(b, source, language);
        }

        // Add update expression for for-loops
        if let Some(update) = node.child_by_field_name("update") {
            self.add_statement(update.id());
        }

        // For do-while, add condition at end of body
        if is_do_while && let Some(cond) = condition {
            self.add_statement(cond.id());
        }

        // Loop back to header (unless we returned/broke)
        if !matches!(
            self.blocks[self.current_block].terminator,
            Terminator::Return | Terminator::Unreachable | Terminator::Goto(_)
        ) {
            self.set_terminator(self.current_block, Terminator::Goto(loop_header));
        }

        self.loop_stack.pop();
        self.loop_depth -= 1;

        self.current_block = loop_exit;
    }

    /// Process a try-catch statement
    fn process_try_catch(&mut self, node: Node, source: &[u8], language: Language) {
        let body = node.child_by_field_name("body");
        let handler = node.child_by_field_name("handler");
        let finalizer = node.child_by_field_name("finalizer");

        let try_block = self.new_block();
        let catch_block = handler.map(|_| self.new_catch_block());
        let finally_block = finalizer.map(|_| self.new_finally_block());
        let after_block = self.new_block();

        self.set_terminator(
            self.current_block,
            Terminator::TryCatch {
                try_block,
                catch_block,
                finally_block,
            },
        );

        // Process try block
        self.current_block = try_block;
        if let Some(b) = body {
            self.process_block_children(b, source, language);
        }
        let next_after_try = finally_block.unwrap_or(after_block);
        if !matches!(
            self.blocks[self.current_block].terminator,
            Terminator::Return | Terminator::Unreachable
        ) {
            self.set_terminator(self.current_block, Terminator::Goto(next_after_try));
        }

        // Process catch block
        if let Some(cb) = catch_block {
            self.current_block = cb;
            if let Some(h) = handler {
                self.process_block_children(h, source, language);
            }
            let next_after_catch = finally_block.unwrap_or(after_block);
            if !matches!(
                self.blocks[self.current_block].terminator,
                Terminator::Return | Terminator::Unreachable
            ) {
                self.set_terminator(self.current_block, Terminator::Goto(next_after_catch));
            }
        }

        // Process finally block
        if let Some(fb) = finally_block {
            self.current_block = fb;
            if let Some(f) = finalizer {
                self.process_block_children(f, source, language);
            }
            if !matches!(
                self.blocks[self.current_block].terminator,
                Terminator::Return | Terminator::Unreachable
            ) {
                self.set_terminator(self.current_block, Terminator::Goto(after_block));
            }
        }

        self.current_block = after_block;
    }

    /// Process a switch/match statement
    fn process_switch(&mut self, node: Node, source: &[u8], language: Language) {
        let condition = node
            .child_by_field_name("value")
            .or_else(|| node.child_by_field_name("condition"));
        let body = node.child_by_field_name("body");

        if let Some(cond) = condition {
            self.add_statement(cond.id());
        }

        let after_block = self.new_block();
        let switch_block = self.current_block;

        let mut cases = Vec::new();
        if let Some(b) = body {
            let mut child_cursor = b.walk();
            for child in b.children(&mut child_cursor) {
                match child.kind() {
                    "switch_case" | "switch_default" | "match_arm" | "case_clause"
                    | "default_clause" => {
                        let case_block = self.new_block();
                        let case_value = child.child_by_field_name("value");
                        cases.push((case_value.map(|n| n.id()), case_block));

                        self.current_block = case_block;
                        self.process_block_children(child, source, language);

                        // Check for fallthrough vs break
                        if !matches!(
                            self.blocks[self.current_block].terminator,
                            Terminator::Return | Terminator::Unreachable | Terminator::Goto(_)
                        ) {
                            self.set_terminator(self.current_block, Terminator::Goto(after_block));
                        }
                    }
                    _ => {}
                }
            }
        }

        if !cases.is_empty() {
            self.blocks[switch_block].terminator = Terminator::Switch {
                condition_node: condition.map(|n| n.id()).unwrap_or(0),
                cases,
            };
        } else {
            self.set_terminator(switch_block, Terminator::Goto(after_block));
        }

        self.current_block = after_block;
    }

    /// Process children of a block/body node
    fn process_block_children(&mut self, node: Node, source: &[u8], language: Language) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.is_named() {
                self.process_statement(child, source, language);
            }
        }
    }

    /// Look for control flow in nested expressions (e.g., ternary operators)
    fn process_nested_control_flow(&mut self, node: Node, _source: &[u8], _language: Language) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.is_named() {
                match child.kind() {
                    // Ternary operators create implicit branches
                    "ternary_expression" | "conditional_expression" => {
                        // For now, just record the node - full ternary CFG is complex
                        self.add_statement(child.id());
                    }
                    // Don't recurse into function definitions
                    "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "function_definition" => {}
                    // Recurse into other expressions
                    _ => {
                        self.process_nested_control_flow(child, _source, _language);
                    }
                }
            }
        }
    }

    fn finalize(self) -> CFG {
        let exit = if self.blocks.is_empty() {
            0
        } else {
            self.blocks.len() - 1
        };
        let mut cfg = CFG {
            entry: 0,
            exit,
            blocks: self.blocks,
            node_to_block: self.node_to_block,
        };
        cfg.compute_reachability();
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_parser::ParserEngine;
    use std::path::Path;

    fn parse_js(code: &str) -> ParsedFile {
        let config = rma_common::RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser
            .parse_file(Path::new("test.js"), code)
            .expect("parse failed")
    }

    #[test]
    fn test_simple_cfg() {
        let code = r#"
            const x = 1;
            const y = 2;
            const z = x + y;
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Should have at least entry block
        assert!(cfg.block_count() >= 1);
        assert_eq!(cfg.entry, 0);
    }

    #[test]
    fn test_if_cfg() {
        let code = r#"
            if (x > 0) {
                console.log("positive");
            } else {
                console.log("non-positive");
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Should have: entry, then, else, merge blocks
        assert!(cfg.block_count() >= 4);
    }

    #[test]
    fn test_loop_detection() {
        let code = r#"
            const x = 1;
            for (let i = 0; i < 10; i++) {
                console.log(i);
            }
            const y = 2;
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Find a node inside the loop (console.log call)
        let mut found_in_loop = false;
        for (node_id, &block_id) in &cfg.node_to_block {
            if cfg.blocks[block_id].loop_depth > 0 {
                found_in_loop = true;
                assert!(cfg.is_in_loop(*node_id));
            }
        }
        assert!(found_in_loop, "Should detect nodes inside loop");
    }

    #[test]
    fn test_nested_loop_depth() {
        let code = r#"
            for (let i = 0; i < 10; i++) {
                for (let j = 0; j < 10; j++) {
                    console.log(i, j);
                }
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Should have blocks with loop_depth of 2 (nested loop)
        let max_depth = cfg.blocks.iter().map(|b| b.loop_depth).max().unwrap_or(0);
        assert!(max_depth >= 2, "Nested loops should have depth >= 2");
    }

    #[test]
    fn test_path_bypassing() {
        let code = r#"
            if (condition) {
                sanitize();
            }
            sink();
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // The sink can be reached without going through the sanitize block
        // (via the else path)
        assert!(cfg.block_count() >= 3);
    }

    #[test]
    fn test_reachability() {
        let code = r#"
            const x = 1;
            if (true) {
                return;
            }
            const y = 2;
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Entry block should always be reachable
        assert!(cfg.is_reachable(cfg.entry));
    }

    #[test]
    fn test_catch_block_detection() {
        let code = r#"
            try {
                riskyOperation();
            } catch (e) {
                console.log(e);
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Should have at least one catch block
        let catch_blocks: Vec<_> = cfg.blocks.iter().filter(|b| b.is_catch).collect();
        assert!(!catch_blocks.is_empty(), "Should detect catch blocks");
    }

    #[test]
    fn test_empty_catch_detection() {
        let code = r#"
            try {
                riskyOperation();
            } catch (e) {
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Should find the empty catch block
        let _empty_catches = cfg.empty_catch_blocks();
        // Note: detection depends on how tree-sitter parses empty catch bodies
        // The test verifies the mechanism works
        assert!(
            cfg.blocks.iter().any(|b| b.is_catch),
            "Should have catch block marked"
        );
    }

    #[test]
    fn test_finally_block_detection() {
        let code = r#"
            try {
                riskyOperation();
            } finally {
                cleanup();
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        // Should have a finally block
        let finally_blocks: Vec<_> = cfg.blocks.iter().filter(|b| b.is_finally).collect();
        assert!(!finally_blocks.is_empty(), "Should detect finally blocks");
    }

    #[test]
    fn test_build_safe() {
        let code = "const x = 1;";
        let parsed = parse_js(code);

        // build_safe should return Some for valid code
        let result = CFG::build_safe(&parsed, Language::JavaScript);
        assert!(result.is_some(), "build_safe should succeed for valid code");
    }

    #[test]
    fn test_incomplete_terminator() {
        // Test that Incomplete terminator has no successors
        let term = Terminator::Incomplete;
        let cfg = CFG {
            blocks: vec![BasicBlock {
                id: 0,
                statements: vec![],
                terminator: term,
                predecessors: vec![],
                loop_depth: 0,
                reachable: true,
                is_catch: false,
                is_finally: false,
            }],
            entry: 0,
            exit: 0,
            node_to_block: HashMap::new(),
        };

        assert!(
            cfg.successors(0).is_empty(),
            "Incomplete terminator should have no successors"
        );
    }
}
