//! Flow analysis module for scope resolution and taint tracking
//!
//! This module provides:
//! - Symbol table construction from tree-sitter AST
//! - Taint source/sink/sanitizer configuration
//! - Forward taint propagation analysis
//! - Control flow graph (CFG) for path-sensitive analysis
//! - Framework-aware knowledge integration
//! - Generic dataflow framework (reaching definitions, live variables)
//! - Inter-procedural taint analysis with function summaries
//! - Type inference for variables without explicit annotations
//!
//! Supports both intra-procedural and inter-procedural analysis.

mod cfg;
pub mod dataflow;
pub mod interprocedural;
pub mod liveness;
pub mod reaching_defs;
mod sources;
mod symbol_table;
mod taint;
pub mod type_inference;

pub use cfg::{BasicBlock, BlockId, CFG, Terminator};
pub use dataflow::{DataflowResult, Direction, Fact, TransferFunction};
pub use interprocedural::{
    CallArg, CallSite, FunctionSummary, InterproceduralResult, ParamEffect, TaintEndpoint,
    TaintFlow, TaintKind, TaintSummary, analyze_interprocedural,
    analyze_interprocedural_with_call_graph,
};
pub use liveness::{LiveVar, analyze_liveness};
pub use reaching_defs::{DefOrigin, DefUseChains, Definition, Use, analyze_reaching_definitions};
pub use sources::{SinkPattern, SourcePattern, TaintConfig, TaintSink, TaintSource};
pub use symbol_table::{SymbolInfo, SymbolTable, ValueOrigin};
pub use taint::{TaintAnalyzer, TaintLevel, TaintResult};
pub use type_inference::{
    InferredType, Nullability, NullabilityRefinements, TypeFact, TypeInferrer, TypeInfo, TypeTable,
    analyze_types, compute_nullability_refinements, infer_types_from_symbols,
};

use crate::callgraph::CallGraph;
use crate::knowledge::{KnowledgeBuilder, MergedKnowledge};
use crate::semantics::LanguageSemantics;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Combined flow analysis context passed to flow-aware rules
///
/// This is the primary interface for flow-sensitive security analysis.
/// It combines symbol table, taint analysis, CFG, dataflow results, and framework knowledge.
/// Now supports cross-file taint tracking via CallGraph integration.
#[derive(Debug)]
pub struct FlowContext {
    /// Symbol table mapping variable names to their info
    pub symbols: SymbolTable,

    /// Taint analysis result
    pub taint: TaintResult,

    /// Legacy taint configuration (for backwards compatibility)
    pub config: TaintConfig,

    /// Control flow graph for path-sensitive analysis
    pub cfg: CFG,

    /// Merged knowledge from detected frameworks
    pub knowledge: MergedKnowledge,

    /// Language semantics for AST traversal
    pub semantics: &'static LanguageSemantics,

    /// Reaching definitions result (lazily computed)
    reaching_defs: Option<(DataflowResult<Definition>, DefUseChains)>,

    /// Live variable analysis result (lazily computed)
    liveness: Option<DataflowResult<LiveVar>>,

    /// Inter-procedural taint result (lazily computed)
    interprocedural: Option<InterproceduralResult>,

    /// Type inference result (lazily computed)
    type_result: Option<DataflowResult<TypeFact>>,

    /// Type table built from symbol table (lazily computed)
    type_table: Option<TypeTable>,

    /// Nullability refinements from branch analysis (lazily computed)
    nullability_refinements: Option<NullabilityRefinements>,

    /// Cached tree reference for dataflow analysis
    tree: Option<tree_sitter::Tree>,

    /// Cached source bytes for dataflow analysis
    source: Option<Vec<u8>>,

    /// Optional call graph for cross-file taint tracking
    call_graph: Option<Arc<CallGraph>>,

    /// Current file path (for cross-file analysis)
    file_path: Option<PathBuf>,

    /// Taint summaries from other files (for cross-file taint propagation)
    cross_file_summaries: Option<HashMap<String, TaintSummary>>,
}

impl FlowContext {
    /// Build flow context for a parsed file
    ///
    /// This is the standard constructor that:
    /// 1. Detects frameworks from source content
    /// 2. Builds symbol table using language semantics
    /// 3. Runs taint analysis with framework knowledge
    /// 4. Constructs CFG for path-sensitive queries
    pub fn build(parsed: &rma_parser::ParsedFile, language: rma_common::Language) -> Self {
        // Get language semantics
        let semantics = LanguageSemantics::for_language(language);

        // Detect frameworks and build merged knowledge
        let knowledge_builder = KnowledgeBuilder::new(language);
        let knowledge = knowledge_builder.from_content(&parsed.content);

        // Build symbol table
        let symbols = SymbolTable::build(parsed, language);

        // Build taint config that uses both legacy patterns and knowledge
        let config = TaintConfig::for_language_with_knowledge(language, &knowledge);

        // Run taint analysis
        let taint = TaintAnalyzer::analyze(&symbols, &config);

        // Build CFG
        let cfg = CFG::build(parsed, language);

        Self {
            symbols,
            taint,
            config,
            cfg,
            knowledge,
            semantics,
            reaching_defs: None,
            liveness: None,
            interprocedural: None,
            type_result: None,
            type_table: None,
            nullability_refinements: None,
            tree: Some(parsed.tree.clone()),
            source: Some(parsed.content.as_bytes().to_vec()),
            call_graph: None,
            file_path: Some(parsed.path.clone()),
            cross_file_summaries: None,
        }
    }

    /// Build flow context with all known framework profiles
    ///
    /// Use this when you want maximum detection capability without
    /// framework auto-detection (e.g., for single-file analysis).
    pub fn build_with_all_profiles(
        parsed: &rma_parser::ParsedFile,
        language: rma_common::Language,
    ) -> Self {
        let semantics = LanguageSemantics::for_language(language);

        let knowledge_builder = KnowledgeBuilder::new(language);
        let knowledge = knowledge_builder.all_profiles();

        let symbols = SymbolTable::build(parsed, language);
        let config = TaintConfig::for_language_with_knowledge(language, &knowledge);
        let taint = TaintAnalyzer::analyze(&symbols, &config);
        let cfg = CFG::build(parsed, language);

        Self {
            symbols,
            taint,
            config,
            cfg,
            knowledge,
            semantics,
            reaching_defs: None,
            liveness: None,
            interprocedural: None,
            type_result: None,
            type_table: None,
            nullability_refinements: None,
            tree: Some(parsed.tree.clone()),
            source: Some(parsed.content.as_bytes().to_vec()),
            call_graph: None,
            file_path: Some(parsed.path.clone()),
            cross_file_summaries: None,
        }
    }

    /// Build flow context with specific framework knowledge
    ///
    /// Use this when framework detection has already been performed
    /// at the project level (more efficient for monorepo analysis).
    pub fn build_with_knowledge(
        parsed: &rma_parser::ParsedFile,
        language: rma_common::Language,
        knowledge: MergedKnowledge,
    ) -> Self {
        let semantics = LanguageSemantics::for_language(language);
        let symbols = SymbolTable::build(parsed, language);
        let config = TaintConfig::for_language_with_knowledge(language, &knowledge);
        let taint = TaintAnalyzer::analyze(&symbols, &config);
        let cfg = CFG::build(parsed, language);

        Self {
            symbols,
            taint,
            config,
            cfg,
            knowledge,
            semantics,
            reaching_defs: None,
            liveness: None,
            interprocedural: None,
            type_result: None,
            type_table: None,
            nullability_refinements: None,
            tree: Some(parsed.tree.clone()),
            source: Some(parsed.content.as_bytes().to_vec()),
            call_graph: None,
            file_path: Some(parsed.path.clone()),
            cross_file_summaries: None,
        }
    }

    /// Build flow context with call graph for cross-file taint tracking
    ///
    /// This constructor enables cross-file taint analysis by providing
    /// a call graph and optionally taint summaries from other files.
    pub fn build_with_call_graph(
        parsed: &rma_parser::ParsedFile,
        language: rma_common::Language,
        call_graph: Arc<CallGraph>,
        cross_file_summaries: Option<HashMap<String, TaintSummary>>,
    ) -> Self {
        let semantics = LanguageSemantics::for_language(language);
        let knowledge_builder = KnowledgeBuilder::new(language);
        let knowledge = knowledge_builder.from_content(&parsed.content);
        let symbols = SymbolTable::build(parsed, language);
        let config = TaintConfig::for_language_with_knowledge(language, &knowledge);

        // Run taint analysis with cross-file support
        let taint = TaintAnalyzer::analyze_with_call_graph(
            &symbols,
            &config,
            Some(&call_graph),
            Some(&parsed.path),
            cross_file_summaries.as_ref(),
        );

        let cfg = CFG::build(parsed, language);

        Self {
            symbols,
            taint,
            config,
            cfg,
            knowledge,
            semantics,
            reaching_defs: None,
            liveness: None,
            interprocedural: None,
            type_result: None,
            type_table: None,
            nullability_refinements: None,
            tree: Some(parsed.tree.clone()),
            source: Some(parsed.content.as_bytes().to_vec()),
            call_graph: Some(call_graph),
            file_path: Some(parsed.path.clone()),
            cross_file_summaries,
        }
    }

    /// Build flow context with dataflow analysis enabled
    ///
    /// This constructor runs the more expensive dataflow analyses upfront.
    /// Use when you need reaching definitions or liveness information.
    pub fn build_with_dataflow(
        parsed: &rma_parser::ParsedFile,
        language: rma_common::Language,
    ) -> Self {
        let mut ctx = Self::build(parsed, language);
        ctx.compute_dataflow();
        ctx
    }

    /// Lazily compute and cache dataflow analyses
    pub fn compute_dataflow(&mut self) {
        if self.reaching_defs.is_some() {
            return; // Already computed
        }

        if let (Some(tree), Some(source)) = (&self.tree, &self.source) {
            // Compute reaching definitions
            let (reaching, def_use) = reaching_defs::analyze_reaching_definitions(
                &self.cfg,
                tree,
                source,
                self.semantics,
            );
            self.reaching_defs = Some((reaching, def_use));

            // Compute liveness
            let live = liveness::analyze_liveness(&self.cfg, tree, source, self.semantics);
            self.liveness = Some(live);

            // Compute interprocedural
            let interproc = interprocedural::analyze_interprocedural(
                &self.symbols,
                &self.cfg,
                &self.config,
                tree,
                source,
                self.semantics,
            );
            self.interprocedural = Some(interproc);

            // Compute type inference
            let types = type_inference::analyze_types(&self.cfg, tree, source, self.semantics);
            self.type_result = Some(types);

            // Compute nullability refinements
            let refinements = type_inference::compute_nullability_refinements(
                &self.cfg,
                tree,
                source,
                self.semantics,
            );
            self.nullability_refinements = Some(refinements);
        }

        // Build type table from symbols (doesn't require tree/source)
        self.type_table = Some(type_inference::infer_types_from_symbols(
            &self.symbols,
            self.semantics,
        ));
    }

    /// Lazily compute and cache type inference only (lighter weight than full dataflow)
    pub fn compute_types(&mut self) {
        if self.type_table.is_some() {
            return; // Already computed
        }

        // Build type table from symbols
        self.type_table = Some(type_inference::infer_types_from_symbols(
            &self.symbols,
            self.semantics,
        ));

        // If we have tree/source, also compute CFG-based type analysis
        if let (Some(tree), Some(source)) = (&self.tree, &self.source) {
            let types = type_inference::analyze_types(&self.cfg, tree, source, self.semantics);
            self.type_result = Some(types);

            let refinements = type_inference::compute_nullability_refinements(
                &self.cfg,
                tree,
                source,
                self.semantics,
            );
            self.nullability_refinements = Some(refinements);
        }
    }

    // =========================================================================
    // Dataflow queries
    // =========================================================================

    /// Get reaching definitions at a block entry
    pub fn reaching_defs_at_entry(
        &self,
        block_id: BlockId,
    ) -> Option<&std::collections::HashSet<Definition>> {
        self.reaching_defs
            .as_ref()
            .and_then(|(result, _)| result.block_entry.get(&block_id))
    }

    /// Get def-use chains
    pub fn def_use_chains(&self) -> Option<&DefUseChains> {
        self.reaching_defs.as_ref().map(|(_, chains)| chains)
    }

    /// Get dead stores (definitions never used)
    pub fn dead_stores(&self) -> Vec<&Definition> {
        self.reaching_defs
            .as_ref()
            .map(|(_, chains)| chains.dead_stores())
            .unwrap_or_default()
    }

    /// Check if a variable is live at block entry
    pub fn is_live_at_entry(&self, block_id: BlockId, var_name: &str) -> bool {
        self.liveness
            .as_ref()
            .map(|result| result.is_live_at_entry(block_id, var_name))
            .unwrap_or(false)
    }

    /// Check if a variable is live at block exit
    pub fn is_live_at_exit(&self, block_id: BlockId, var_name: &str) -> bool {
        self.liveness
            .as_ref()
            .map(|result| result.is_live_at_exit(block_id, var_name))
            .unwrap_or(false)
    }

    /// Get all live variables at block entry
    pub fn live_at_entry(&self, block_id: BlockId) -> std::collections::HashSet<String> {
        self.liveness
            .as_ref()
            .map(|result| result.live_at_entry(block_id))
            .unwrap_or_default()
    }

    /// Get inter-procedural analysis result
    pub fn interprocedural_result(&self) -> Option<&InterproceduralResult> {
        self.interprocedural.as_ref()
    }

    // =========================================================================
    // Type inference queries
    // =========================================================================

    /// Get the type table (lazily computed from symbols)
    pub fn type_table(&mut self) -> &TypeTable {
        if self.type_table.is_none() {
            self.type_table = Some(type_inference::infer_types_from_symbols(
                &self.symbols,
                self.semantics,
            ));
        }
        self.type_table.as_ref().unwrap()
    }

    /// Get the inferred type of a variable
    pub fn get_type(&mut self, var_name: &str) -> Option<InferredType> {
        self.type_table().get_type(var_name).cloned()
    }

    /// Get the nullability of a variable
    pub fn get_nullability(&mut self, var_name: &str) -> Nullability {
        self.type_table().get_nullability(var_name)
    }

    /// Check if a variable is definitely null
    #[inline]
    pub fn is_definitely_null(&mut self, var_name: &str) -> bool {
        self.type_table().is_definitely_null(var_name)
    }

    /// Check if a variable is possibly null
    #[inline]
    pub fn is_possibly_null(&mut self, var_name: &str) -> bool {
        self.type_table().is_possibly_null(var_name)
    }

    /// Check if a variable is definitely non-null
    #[inline]
    pub fn is_definitely_non_null(&mut self, var_name: &str) -> bool {
        self.type_table().is_definitely_non_null(var_name)
    }

    /// Get the type info for a variable at a specific block entry (requires dataflow)
    pub fn type_at_block(&self, block_id: BlockId, var_name: &str) -> Option<TypeInfo> {
        self.type_result
            .as_ref()
            .and_then(|result| result.type_at_entry(block_id, var_name))
    }

    /// Get the nullability of a variable at a specific block (with refinements)
    pub fn nullability_at_block(&self, block_id: BlockId, var_name: &str) -> Nullability {
        // First check refinements (from null checks in conditions)
        if let Some(refinements) = &self.nullability_refinements {
            if let Some(refined) = refinements.get(block_id, var_name) {
                return refined;
            }
        }
        // Fall back to type result
        self.type_result
            .as_ref()
            .map(|result| result.nullability_at_entry(block_id, var_name))
            .unwrap_or(Nullability::Unknown)
    }

    /// Check if a variable is possibly null at a specific block
    pub fn is_possibly_null_at_block(&self, block_id: BlockId, var_name: &str) -> bool {
        self.nullability_at_block(block_id, var_name)
            .could_be_null()
    }

    /// Check if a variable is definitely non-null at a specific block
    pub fn is_definitely_non_null_at_block(&self, block_id: BlockId, var_name: &str) -> bool {
        self.nullability_at_block(block_id, var_name)
            .is_definitely_non_null()
    }

    /// Get the nullability refinements (computed from branch conditions)
    pub fn nullability_refinements(&self) -> Option<&NullabilityRefinements> {
        self.nullability_refinements.as_ref()
    }

    /// Get the type inference dataflow result
    pub fn type_result(&self) -> Option<&DataflowResult<TypeFact>> {
        self.type_result.as_ref()
    }

    /// Get detected taint flows (source to sink)
    pub fn taint_flows(&self) -> Vec<&TaintFlow> {
        self.interprocedural
            .as_ref()
            .map(|r| r.flows.iter().collect())
            .unwrap_or_default()
    }

    /// Get function summary by name
    pub fn function_summary(&self, name: &str) -> Option<&FunctionSummary> {
        self.interprocedural
            .as_ref()
            .and_then(|r| r.get_summary(name))
    }

    // =========================================================================
    // CFG queries
    // =========================================================================

    /// Check if a node is inside a loop
    #[inline]
    pub fn is_in_loop(&self, node_id: usize) -> bool {
        self.cfg.is_in_loop(node_id)
    }

    /// Get the loop depth of a node (0 = not in loop)
    #[inline]
    pub fn loop_depth(&self, node_id: usize) -> usize {
        self.cfg.loop_depth(node_id)
    }

    /// Check if a block is reachable from entry
    #[inline]
    pub fn is_reachable(&self, block_id: usize) -> bool {
        self.cfg.is_reachable(block_id)
    }

    /// Get all unreachable blocks (dead code)
    #[inline]
    pub fn unreachable_blocks(&self) -> Vec<usize> {
        self.cfg.unreachable_blocks()
    }

    /// Check if a block is a catch handler
    #[inline]
    pub fn is_catch_block(&self, block_id: usize) -> bool {
        self.cfg.is_catch_block(block_id)
    }

    /// Check if a block is a finally handler
    #[inline]
    pub fn is_finally_block(&self, block_id: usize) -> bool {
        self.cfg.is_finally_block(block_id)
    }

    /// Get catch blocks that have no statements (empty catch)
    #[inline]
    pub fn empty_catch_blocks(&self) -> Vec<usize> {
        self.cfg.empty_catch_blocks()
    }

    // =========================================================================
    // Taint queries
    // =========================================================================

    /// Get the taint level of a variable at a specific program point
    ///
    /// Returns TaintLevel::Full if tainted on all paths,
    /// TaintLevel::Partial if tainted on some paths,
    /// TaintLevel::Clean if sanitized on all paths.
    #[inline]
    pub fn taint_level_at(&self, var_name: &str, node_id: usize) -> TaintLevel {
        self.taint.taint_level_at(var_name, node_id, &self.cfg)
    }

    /// Check if a variable is tainted (on any path)
    #[inline]
    pub fn is_tainted(&self, var_name: &str) -> bool {
        self.taint.is_tainted(var_name)
    }

    /// Check if any of the given variables is tainted
    #[inline]
    pub fn any_tainted(&self, var_names: &[&str]) -> bool {
        self.taint.any_tainted(var_names)
    }

    /// Check if a variable is tainted from a cross-file source
    #[inline]
    pub fn is_tainted_from_cross_file(&self, var_name: &str) -> bool {
        self.taint.is_tainted_from_cross_file(var_name)
    }

    /// Get all variables tainted from cross-file sources
    pub fn cross_file_tainted_vars(&self) -> &std::collections::HashSet<String> {
        self.taint.cross_file_tainted_vars()
    }

    // =========================================================================
    // Call Graph queries
    // =========================================================================

    /// Check if a call graph is available for cross-file analysis
    #[inline]
    pub fn has_call_graph(&self) -> bool {
        self.call_graph.is_some()
    }

    /// Get the call graph (if available)
    pub fn call_graph(&self) -> Option<&CallGraph> {
        self.call_graph.as_ref().map(|arc| arc.as_ref())
    }

    /// Get the current file path
    pub fn file_path(&self) -> Option<&std::path::Path> {
        self.file_path.as_deref()
    }

    /// Check if a function exists in another file (via call graph)
    pub fn is_cross_file_function(&self, func_name: &str) -> bool {
        if let (Some(cg), Some(fp)) = (self.call_graph.as_ref(), self.file_path.as_ref()) {
            let functions = cg.get_functions_by_name(func_name);
            functions.iter().any(|f| f.file != *fp)
        } else {
            false
        }
    }

    /// Get cross-file taint summary for a function
    pub fn get_cross_file_taint_summary(&self, func_name: &str) -> Option<&TaintSummary> {
        self.cross_file_summaries
            .as_ref()
            .and_then(|summaries| summaries.get(func_name))
    }

    /// Check if a cross-file function is a taint source
    pub fn is_cross_file_source(&self, func_name: &str) -> bool {
        if let Some(summary) = self.get_cross_file_taint_summary(func_name) {
            summary.is_source()
        } else {
            false
        }
    }

    /// Check if a cross-file function is a sanitizer
    pub fn is_cross_file_sanitizer(&self, func_name: &str) -> bool {
        if let Some(summary) = self.get_cross_file_taint_summary(func_name) {
            summary.is_sanitizer()
        } else {
            false
        }
    }

    /// Get cross-file taint flows (flows that cross file boundaries)
    pub fn cross_file_taint_flows(&self) -> Vec<&TaintFlow> {
        self.interprocedural
            .as_ref()
            .map(|r| r.cross_file_flows())
            .unwrap_or_default()
    }

    /// Set the call graph for cross-file analysis
    pub fn set_call_graph(&mut self, call_graph: Arc<CallGraph>) {
        self.call_graph = Some(call_graph);
    }

    /// Set cross-file taint summaries
    pub fn set_cross_file_summaries(&mut self, summaries: HashMap<String, TaintSummary>) {
        self.cross_file_summaries = Some(summaries);
    }

    // =========================================================================
    // Knowledge queries
    // =========================================================================

    /// Check if a function is a known taint source
    #[inline]
    pub fn is_source_function(&self, func_name: &str) -> bool {
        self.knowledge.is_source_function(func_name)
    }

    /// Check if a member access is a known taint source
    #[inline]
    pub fn is_source_member(&self, member_path: &str) -> bool {
        self.knowledge.is_source_member(member_path)
    }

    /// Check if a function is a known sink
    #[inline]
    pub fn is_sink_function(&self, func_name: &str) -> bool {
        self.knowledge.is_sink_function(func_name)
    }

    /// Check if a property is a known sink
    #[inline]
    pub fn is_sink_property(&self, prop_name: &str) -> bool {
        self.knowledge.is_sink_property(prop_name)
    }

    /// Check if a function is a known sanitizer
    #[inline]
    pub fn is_sanitizer(&self, func_name: &str) -> bool {
        self.knowledge.is_sanitizer(func_name)
    }

    /// Get active framework names
    pub fn active_frameworks(&self) -> &[&'static str] {
        &self.knowledge.active_frameworks
    }

    /// Check if any frameworks were detected
    #[inline]
    pub fn has_frameworks(&self) -> bool {
        self.knowledge.has_frameworks()
    }

    // =========================================================================
    // Semantic queries
    // =========================================================================

    /// Check if a node kind represents a function definition
    #[inline]
    pub fn is_function_def(&self, kind: &str) -> bool {
        self.semantics.is_function_def(kind)
    }

    /// Check if a node kind represents a loop
    #[inline]
    pub fn is_loop(&self, kind: &str) -> bool {
        self.semantics.is_loop(kind)
    }

    /// Check if a node kind represents a call expression
    #[inline]
    pub fn is_call(&self, kind: &str) -> bool {
        self.semantics.is_call(kind)
    }

    /// Check if a node kind represents an assignment
    #[inline]
    pub fn is_assignment(&self, kind: &str) -> bool {
        self.semantics.is_assignment(kind)
    }

    /// Check if a node kind represents a literal
    #[inline]
    pub fn is_literal(&self, kind: &str) -> bool {
        self.semantics.is_literal(kind)
    }

    /// Check if a node kind represents control flow
    #[inline]
    pub fn is_control_flow(&self, kind: &str) -> bool {
        self.semantics.is_control_flow(kind)
    }
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

    #[test]
    fn test_flow_context_with_knowledge() {
        let code = r#"
import express from 'express';
const app = express();

app.get('/user', (req, res) => {
    const query = req.query.name;
    res.send(query);
});
"#;
        let parsed = parse_js(code);
        let ctx = FlowContext::build(&parsed, Language::JavaScript);

        // Should detect express
        assert!(ctx.has_frameworks());
        assert!(ctx.active_frameworks().contains(&"express"));

        // Should recognize sources
        assert!(ctx.is_source_member("req.query"));
    }

    #[test]
    fn test_flow_context_taint_propagation() {
        let code = r#"
function handler(userInput) {
    const data = userInput;
    const safe = encodeURIComponent(data);
}
"#;
        let parsed = parse_js(code);
        let ctx = FlowContext::build_with_all_profiles(&parsed, Language::JavaScript);

        assert!(ctx.is_tainted("userInput"));
        assert!(ctx.is_tainted("data"));
        // safe should not be tainted (sanitized)
        assert!(!ctx.is_tainted("safe"));
    }

    #[test]
    fn test_flow_context_semantics() {
        let code = "function foo() {}";
        let parsed = parse_js(code);
        let ctx = FlowContext::build(&parsed, Language::JavaScript);

        assert!(ctx.is_function_def("function_declaration"));
        assert!(ctx.is_call("call_expression"));
        assert!(ctx.is_loop("for_statement"));
    }
}
