//! Generic Dataflow Framework
//!
//! Implements an iterative worklist solver that computes fixed-point solutions
//! over any CFG. The framework is parameterized by:
//! - Direction: Forward (entry → exit) or Backward (exit → entry)
//! - Transfer function: How each basic block transforms the dataflow state
//!
//! This is the foundation for all dataflow analyses: reaching definitions,
//! live variables, available expressions, etc.

use crate::flow::cfg::{BasicBlock, BlockId, CFG, Terminator};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

/// Direction of dataflow analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Propagate from entry to exit (e.g., reaching definitions)
    Forward,
    /// Propagate from exit to entry (e.g., live variables)
    Backward,
}

/// A dataflow fact — the element type in the lattice.
/// Must be cloneable, comparable, and hashable for set operations.
pub trait Fact: Clone + Eq + Hash + Debug + Send + Sync {}

// Blanket impl: anything that satisfies the bounds is a Fact
impl<T: Clone + Eq + Hash + Debug + Send + Sync> Fact for T {}

/// The result of a dataflow analysis: maps each block to its entry and exit states.
#[derive(Debug)]
pub struct DataflowResult<F: Fact> {
    /// State at the ENTRY of each block (before any statements execute)
    pub block_entry: HashMap<BlockId, HashSet<F>>,
    /// State at the EXIT of each block (after all statements execute)
    pub block_exit: HashMap<BlockId, HashSet<F>>,
    /// Number of iterations the solver took to converge
    pub iterations: usize,
}

impl<F: Fact> Default for DataflowResult<F> {
    fn default() -> Self {
        Self {
            block_entry: HashMap::new(),
            block_exit: HashMap::new(),
            iterations: 0,
        }
    }
}

impl<F: Fact> DataflowResult<F> {
    /// Get the dataflow state at the entry of a block
    pub fn at_entry(&self, block_id: BlockId) -> Option<&HashSet<F>> {
        self.block_entry.get(&block_id)
    }

    /// Get the dataflow state at the exit of a block
    pub fn at_exit(&self, block_id: BlockId) -> Option<&HashSet<F>> {
        self.block_exit.get(&block_id)
    }

    /// Check if a fact holds at the entry of a specific block
    pub fn contains_at_entry(&self, block_id: BlockId, fact: &F) -> bool {
        self.block_entry
            .get(&block_id)
            .is_some_and(|set| set.contains(fact))
    }

    /// Check if a fact holds at the exit of a specific block
    pub fn contains_at_exit(&self, block_id: BlockId, fact: &F) -> bool {
        self.block_exit
            .get(&block_id)
            .is_some_and(|set| set.contains(fact))
    }

    /// Check if a fact holds at a specific AST node (uses CFG's node_to_block mapping)
    pub fn contains_at_node(&self, node_id: usize, fact: &F, cfg: &CFG) -> bool {
        // Conservative: check the block entry state
        // (precise per-statement analysis would need statement-level tracking)
        cfg.node_to_block
            .get(&node_id)
            .is_some_and(|&block_id| self.contains_at_entry(block_id, fact))
    }

    /// Get all facts that hold at a specific AST node
    pub fn facts_at_node(&self, node_id: usize, cfg: &CFG) -> HashSet<F> {
        cfg.node_to_block
            .get(&node_id)
            .and_then(|&block_id| self.block_entry.get(&block_id))
            .cloned()
            .unwrap_or_default()
    }

    /// Get facts at entry, returning empty set if block not found
    pub fn entry_facts(&self, block_id: BlockId) -> HashSet<F> {
        self.block_entry.get(&block_id).cloned().unwrap_or_default()
    }

    /// Get facts at exit, returning empty set if block not found
    pub fn exit_facts(&self, block_id: BlockId) -> HashSet<F> {
        self.block_exit.get(&block_id).cloned().unwrap_or_default()
    }
}

/// Transfer function: given a basic block and an input state, produce an output state.
/// The framework calls this for each block during iteration.
///
/// For forward analysis: input = entry state, output = exit state
/// For backward analysis: input = exit state, output = entry state
pub trait TransferFunction<F: Fact>: Send + Sync {
    /// Apply the transfer function to a single basic block.
    ///
    /// # Arguments
    /// * `block` — the basic block being processed
    /// * `input` — the dataflow state flowing INTO this block
    /// * `cfg` — the control flow graph (for context)
    /// * `source` — the source code bytes (for inspecting AST nodes)
    /// * `tree` — the parsed tree-sitter tree
    ///
    /// # Returns
    /// The dataflow state flowing OUT of this block.
    fn transfer(
        &self,
        block: &BasicBlock,
        input: &HashSet<F>,
        cfg: &CFG,
        source: &[u8],
        tree: &tree_sitter::Tree,
    ) -> HashSet<F>;
}

/// Iterative worklist dataflow solver.
///
/// Computes a fixed-point solution by repeatedly applying the transfer function
/// to each basic block until no block's state changes. Uses a worklist to avoid
/// redundant recomputation of blocks whose inputs haven't changed.
///
/// For forward analysis:
///   - Start from entry block
///   - block_entry[B] = UNION of block_exit[P] for all predecessors P of B
///   - block_exit[B] = transfer(B, block_entry[B])
///   - Propagate along successors
///
/// For backward analysis:
///   - Start from exit blocks (Return/Unreachable terminators)
///   - block_exit[B] = UNION of block_entry[S] for all successors S of B
///   - block_entry[B] = transfer(B, block_exit[B])
///   - Propagate along predecessors
pub fn solve<F: Fact, T: TransferFunction<F>>(
    cfg: &CFG,
    direction: Direction,
    transfer: &T,
    source: &[u8],
    tree: &tree_sitter::Tree,
) -> DataflowResult<F> {
    let num_blocks = cfg.blocks.len();
    if num_blocks == 0 {
        return DataflowResult::default();
    }

    let mut block_entry: HashMap<BlockId, HashSet<F>> = HashMap::new();
    let mut block_exit: HashMap<BlockId, HashSet<F>> = HashMap::new();

    // Initialize all states to empty
    for block in &cfg.blocks {
        block_entry.insert(block.id, HashSet::new());
        block_exit.insert(block.id, HashSet::new());
    }

    // Worklist: blocks that need (re-)processing
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    let mut in_worklist: HashSet<BlockId> = HashSet::new();

    match direction {
        Direction::Forward => {
            // Seed worklist with entry block
            worklist.push_back(cfg.entry);
            in_worklist.insert(cfg.entry);
        }
        Direction::Backward => {
            // Seed worklist with all blocks that have Return/Unreachable terminators
            for block in &cfg.blocks {
                if block.reachable
                    && matches!(
                        block.terminator,
                        Terminator::Return | Terminator::Unreachable
                    )
                {
                    worklist.push_back(block.id);
                    in_worklist.insert(block.id);
                }
            }
            // If no exit blocks found, seed with all reachable blocks
            if worklist.is_empty() {
                for block in &cfg.blocks {
                    if block.reachable {
                        worklist.push_back(block.id);
                        in_worklist.insert(block.id);
                    }
                }
            }
        }
    }

    let mut iterations = 0;
    let max_iterations = num_blocks * 20; // Safety bound to prevent infinite loops

    while let Some(block_id) = worklist.pop_front() {
        in_worklist.remove(&block_id);
        iterations += 1;

        if iterations > max_iterations {
            // Analysis didn't converge — return what we have (conservative)
            tracing::warn!(
                "Dataflow analysis did not converge after {} iterations",
                max_iterations
            );
            break;
        }

        if block_id >= cfg.blocks.len() {
            continue;
        }

        let block = &cfg.blocks[block_id];
        if !block.reachable {
            continue;
        }

        match direction {
            Direction::Forward => {
                // Compute entry state: union of all predecessors' exit states
                let mut new_entry = HashSet::new();
                for &pred in &block.predecessors {
                    if let Some(pred_exit) = block_exit.get(&pred) {
                        new_entry.extend(pred_exit.iter().cloned());
                    }
                }

                // Apply transfer function
                let new_exit = transfer.transfer(block, &new_entry, cfg, source, tree);

                // Store entry state
                block_entry.insert(block_id, new_entry);

                // Check if exit state changed
                let old_exit = block_exit.get(&block_id);
                let changed = old_exit.is_none_or(|old| *old != new_exit);

                if changed {
                    block_exit.insert(block_id, new_exit);
                    // Add successors to worklist
                    for succ in cfg.successors(block_id) {
                        if !in_worklist.contains(&succ) {
                            worklist.push_back(succ);
                            in_worklist.insert(succ);
                        }
                    }
                }
            }
            Direction::Backward => {
                // Compute exit state: union of all successors' entry states
                let mut new_exit = HashSet::new();
                for succ in cfg.successors(block_id) {
                    if let Some(succ_entry) = block_entry.get(&succ) {
                        new_exit.extend(succ_entry.iter().cloned());
                    }
                }

                // Apply transfer function (backward: input is exit state, output is entry state)
                let new_entry = transfer.transfer(block, &new_exit, cfg, source, tree);

                // Store exit state
                block_exit.insert(block_id, new_exit);

                // Check if entry state changed
                let old_entry = block_entry.get(&block_id);
                let changed = old_entry.is_none_or(|old| *old != new_entry);

                if changed {
                    block_entry.insert(block_id, new_entry);
                    // Add predecessors to worklist
                    for &pred in &block.predecessors {
                        if !in_worklist.contains(&pred) {
                            worklist.push_back(pred);
                            in_worklist.insert(pred);
                        }
                    }
                }
            }
        }
    }

    DataflowResult {
        block_entry,
        block_exit,
        iterations,
    }
}

/// Pre-built index from node ID to node, for O(1) lookup during analysis.
///
/// tree-sitter doesn't have O(1) node-by-id lookup — you have to walk the tree.
/// This index is built once per analysis and provides fast lookup.
pub struct NodeIndex<'tree> {
    nodes: HashMap<usize, tree_sitter::Node<'tree>>,
}

impl<'tree> NodeIndex<'tree> {
    /// Build an index of all nodes in the tree
    pub fn build(tree: &'tree tree_sitter::Tree) -> Self {
        let mut nodes = HashMap::new();
        fn walk<'a>(node: tree_sitter::Node<'a>, map: &mut HashMap<usize, tree_sitter::Node<'a>>) {
            map.insert(node.id(), node);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                walk(child, map);
            }
        }
        walk(tree.root_node(), &mut nodes);
        Self { nodes }
    }

    /// Get a node by its ID
    pub fn get(&self, id: usize) -> Option<tree_sitter::Node<'tree>> {
        self.nodes.get(&id).copied()
    }

    /// Get the number of indexed nodes
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the index is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Find a node by its ID by walking the tree (fallback when NodeIndex isn't available).
/// This is O(n) per lookup — prefer NodeIndex when doing multiple lookups.
pub fn find_node_by_id(
    tree: &tree_sitter::Tree,
    target_id: usize,
) -> Option<tree_sitter::Node<'_>> {
    fn walk_find(node: tree_sitter::Node<'_>, target: usize) -> Option<tree_sitter::Node<'_>> {
        if node.id() == target {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = walk_find(child, target) {
                return Some(found);
            }
        }
        None
    }
    walk_find(tree.root_node(), target_id)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// A simple test fact: just a string identifier
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestFact(String);

    /// Identity transfer function: passes through all facts unchanged
    struct IdentityTransfer;

    impl TransferFunction<TestFact> for IdentityTransfer {
        fn transfer(
            &self,
            _block: &BasicBlock,
            input: &HashSet<TestFact>,
            _cfg: &CFG,
            _source: &[u8],
            _tree: &tree_sitter::Tree,
        ) -> HashSet<TestFact> {
            input.clone()
        }
    }

    #[test]
    fn test_empty_cfg() {
        let parsed = parse_js("");
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let transfer = IdentityTransfer;

        let result = solve(&cfg, Direction::Forward, &transfer, b"", &parsed.tree);

        // Should not panic, even on empty input
        assert!(result.iterations <= 1);
    }

    #[test]
    fn test_simple_forward_propagation() {
        let code = "const x = 1; const y = 2;";
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let transfer = IdentityTransfer;

        let result = solve(
            &cfg,
            Direction::Forward,
            &transfer,
            code.as_bytes(),
            &parsed.tree,
        );

        // Should complete in reasonable iterations
        assert!(result.iterations < cfg.block_count() * 5);
    }

    #[test]
    fn test_backward_direction() {
        let code = "function f() { return 1; }";
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let transfer = IdentityTransfer;

        let result = solve(
            &cfg,
            Direction::Backward,
            &transfer,
            code.as_bytes(),
            &parsed.tree,
        );

        assert!(result.iterations < cfg.block_count() * 5);
    }

    #[test]
    fn test_node_index() {
        let code = "const x = 1;";
        let parsed = parse_js(code);
        let index = NodeIndex::build(&parsed.tree);

        assert!(!index.is_empty());

        // Should be able to find the root node
        let root_id = parsed.tree.root_node().id();
        assert!(index.get(root_id).is_some());
    }

    #[test]
    fn test_find_node_by_id_fallback() {
        let code = "const x = 1;";
        let parsed = parse_js(code);

        let root_id = parsed.tree.root_node().id();
        let found = find_node_by_id(&parsed.tree, root_id);
        assert!(found.is_some());

        // Non-existent ID should return None
        let not_found = find_node_by_id(&parsed.tree, usize::MAX);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_dataflow_result_queries() {
        let mut result: DataflowResult<TestFact> = DataflowResult::default();

        result
            .block_entry
            .insert(0, HashSet::from([TestFact("x".to_string())]));
        result
            .block_exit
            .insert(0, HashSet::from([TestFact("y".to_string())]));

        assert!(result.contains_at_entry(0, &TestFact("x".to_string())));
        assert!(!result.contains_at_entry(0, &TestFact("y".to_string())));
        assert!(result.contains_at_exit(0, &TestFact("y".to_string())));
        assert!(!result.contains_at_exit(0, &TestFact("x".to_string())));

        // Non-existent block
        assert!(!result.contains_at_entry(999, &TestFact("x".to_string())));
    }
}
