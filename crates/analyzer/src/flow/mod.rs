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
//! - Typestate analysis for tracking object state transitions
//! - Field-sensitive taint tracking for precise property-level analysis
//! - Alias/points-to analysis for tracking variable aliasing
//!
//! Supports both intra-procedural and inter-procedural analysis.

pub mod alias;
pub mod callbacks;
mod cfg;
pub mod collections;
pub mod context_inference;
pub mod dataflow;
pub mod events;
pub mod field_sensitive;
pub mod implicit_flow;
pub mod interprocedural;
pub mod liveness;
pub mod reaching_defs;
pub mod sink_args;
mod sources;
mod symbol_table;
pub mod symbolic;
mod taint;
pub mod type_inference;
pub mod typestate;

pub use alias::{
    AliasAnalyzer, AliasResult, AliasSet, AllocKind, AllocationSite, Location, LocationId,
    PointsToGraph, analyze_aliases, any_tainted_with_aliases, propagate_taint_through_aliases,
};

pub use callbacks::{
    CallbackAnalyzer, CallbackKind, CallbackPatterns, CallbackRegistry, CallbackSite,
    CallbackTaintFlow, TaintConfidence, TaintSource as CallbackTaintSource, analyze_callback_taint,
    propagate_callback_taint,
};
pub use cfg::{BasicBlock, BlockId, CFG, Terminator};
pub use collections::{
    CollectionKey, CollectionOpResult, CollectionOperation, CollectionTaint,
    CollectionTaintTracker, CollectionType,
};
pub use context_inference::{
    SafeReason, SinkVerdict as ContextSinkVerdict, fix_recommendation, infer_sink_context,
    infer_sink_verdict, recommended_sanitizers,
};
pub use dataflow::{DataflowResult, Direction, Fact, TransferFunction};
pub use events::{
    EventBinding, EventPatterns, EventRegistry, EventSite, extract_emit_args, extract_event_name,
};
pub use field_sensitive::{
    FieldPath, FieldSensitiveAnalyzer, FieldSensitiveTaintResult, FieldTaintFlow, FieldTaintInfo,
    FieldTaintMap, FieldTaintStatus,
};
pub use implicit_flow::{
    ControlDependence, ControlDependenceGraph, ImplicitFlow, ImplicitFlowAnalyzer,
    ImplicitFlowResult, ImplicitFlowType, ImplicitFlowViolation, LabelFact, LabelTransfer,
    SecurityLabel, ViolationSeverity, analyze_implicit_flows, analyze_implicit_flows_with_taint,
    analyze_labels,
};
pub use interprocedural::{
    CallArg, CallSite, FunctionSummary, InterproceduralResult, ParamEffect, TaintEndpoint,
    TaintFlow, TaintKind, TaintSummary, analyze_interprocedural,
    analyze_interprocedural_with_call_graph,
};
pub use liveness::{LiveVar, analyze_liveness};
pub use reaching_defs::{DefOrigin, DefUseChains, Definition, Use, analyze_reaching_definitions};
pub use sink_args::{
    SinkArgRole, SinkSite, SinkVerdict as ArgSinkVerdict, analyze_rust_command,
    evaluate_command_sink,
};
pub use sources::{SinkPattern, SourcePattern, TaintConfig, TaintSink, TaintSource};
pub use symbol_table::{SymbolInfo, SymbolTable, ValueOrigin};
pub use symbolic::{
    ComparisonOp, ConditionExtractor, GuardedType, PathCondition, SymbolicAnalysisResult,
    SymbolicFact, SymbolicState, SymbolicTransfer, analyze_symbolic_conditions,
    analyze_symbolic_dataflow, get_constraints, is_feasible,
};
pub use taint::{
    FunctionBodyTaintAnalyzer, FunctionBodyTaintResult, TaintAnalyzer, TaintLevel, TaintResult,
    TaintSourceInfo, TaintState, analyze_function_bodies,
};
pub use type_inference::{
    InferredType, Nullability, NullabilityRefinements, TypeFact, TypeInferrer, TypeInfo, TypeTable,
    analyze_types, compute_nullability_refinements, infer_types_from_symbols,
};
pub use typestate::{
    MethodCallInfo, ResourceAction, State, StateMachine, TrackedState, Transition,
    TransitionTrigger, TypestateAnalyzer, TypestateResult, TypestateSummary,
    TypestateSummaryRegistry, TypestateViolation, ViolationKind, analyze_typestate_with_context,
    connection_state_machine, file_state_machine, find_assignments_to_var,
    find_method_calls_on_var, iterator_state_machine, lock_state_machine,
};

use crate::callgraph::CallGraph;
use crate::knowledge::{KnowledgeBuilder, MergedKnowledge};
use crate::semantics::LanguageSemantics;
use rma_common::Language;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

// =============================================================================
// Test Context for Setup Method Detection
// =============================================================================

/// Context for tracking test setup methods and the variables they initialize.
///
/// This helps reduce false positives in typestate rules by recognizing that
/// variables initialized in @Before/@BeforeEach/setUp methods are available
/// in test methods.
#[derive(Debug, Clone, Default)]
pub struct TestContext {
    /// Variables initialized in setup methods (e.g., @Before, setUp)
    pub setup_initialized_vars: HashSet<String>,
    /// Line numbers of setup method declarations
    pub setup_method_lines: HashSet<usize>,
    /// Whether the file is a test file
    pub is_test_file: bool,
    /// Setup method names detected
    pub setup_methods: Vec<String>,
}

impl TestContext {
    /// Create a new empty test context
    pub fn new() -> Self {
        Self::default()
    }

    /// Build test context from parsed file content
    pub fn from_content(content: &str, language: Language) -> Self {
        let mut ctx = Self::new();
        ctx.detect_test_context(content, language);
        ctx
    }

    /// Detect test context from file content
    fn detect_test_context(&mut self, content: &str, language: Language) {
        // Detect if this is a test file
        self.is_test_file = Self::is_test_content(content, language);
        if !self.is_test_file {
            return;
        }

        // Find setup methods and their initialized variables
        let setup_patterns = Self::setup_patterns(language);

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check if this line declares a setup method
            for pattern in &setup_patterns {
                if line.contains(pattern) {
                    self.setup_method_lines.insert(line_num);

                    // Extract method name if possible
                    if let Some(method_name) = Self::extract_method_name(line, language) {
                        self.setup_methods.push(method_name);
                    }
                }
            }
        }

        // Now find variables assigned in setup method blocks
        self.find_setup_initialized_vars(content, language);
    }

    /// Check if content indicates a test file
    fn is_test_content(content: &str, language: Language) -> bool {
        match language {
            Language::Java => {
                content.contains("@Test")
                    || content.contains("@Before")
                    || content.contains("@BeforeEach")
                    || content.contains("@BeforeAll")
                    || content.contains("org.junit")
                    || content.contains("org.testng")
            }
            Language::JavaScript | Language::TypeScript => {
                content.contains("describe(")
                    || content.contains("it(")
                    || content.contains("test(")
                    || content.contains("beforeEach(")
                    || content.contains("beforeAll(")
                    || content.contains("jest")
                    || content.contains("mocha")
                    || content.contains("vitest")
            }
            Language::Python => {
                content.contains("def test_")
                    || content.contains("unittest")
                    || content.contains("pytest")
                    || content.contains("@pytest.fixture")
                    || content.contains("def setUp(")
            }
            Language::Go => {
                content.contains("func Test")
                    || content.contains("func Benchmark")
                    || content.contains("testing.T")
                    || content.contains("func TestMain")
            }
            Language::Rust => {
                content.contains("#[test]")
                    || content.contains("#[cfg(test)]")
                    || content.contains("mod tests")
            }
            _ => false,
        }
    }

    /// Get setup method patterns for a language
    fn setup_patterns(language: Language) -> Vec<&'static str> {
        match language {
            Language::Java => vec![
                "@Before",
                "@BeforeEach",
                "@BeforeAll",
                "@BeforeClass",
                "void setUp(",
                "public void setUp(",
            ],
            Language::JavaScript | Language::TypeScript => {
                vec!["beforeEach(", "beforeAll(", "before("]
            }
            Language::Python => vec![
                "def setUp(",
                "@pytest.fixture",
                "@fixture",
                "def setup_method(",
                "def setup_function(",
            ],
            Language::Go => vec!["func TestMain(", "func setup(", "func Setup("],
            Language::Rust => vec!["fn setup(", "fn before_each("],
            _ => vec![],
        }
    }

    /// Extract method name from a line
    fn extract_method_name(line: &str, language: Language) -> Option<String> {
        match language {
            Language::Java => {
                // Look for "void methodName(" or "public void methodName("
                if let Some(idx) = line.find('(') {
                    let before_paren = &line[..idx];
                    let words: Vec<&str> = before_paren.split_whitespace().collect();
                    if let Some(name) = words.last() {
                        return Some(name.to_string());
                    }
                }
                None
            }
            Language::JavaScript | Language::TypeScript => {
                // beforeEach(async () => {}) or beforeEach(function() {})
                if line.contains("beforeEach") {
                    return Some("beforeEach".to_string());
                }
                if line.contains("beforeAll") {
                    return Some("beforeAll".to_string());
                }
                None
            }
            Language::Python => {
                // def setUp(self): or def setup_method(self):
                if let Some(start) = line.find("def ")
                    && let Some(end) = line[start..].find('(')
                {
                    let name = &line[start + 4..start + end];
                    return Some(name.trim().to_string());
                }
                None
            }
            Language::Go => {
                // func TestMain(m *testing.M) or func setup()
                if let Some(start) = line.find("func ")
                    && let Some(end) = line[start..].find('(')
                {
                    let name = &line[start + 5..start + end];
                    return Some(name.trim().to_string());
                }
                None
            }
            _ => None,
        }
    }

    /// Find variables initialized in setup methods
    fn find_setup_initialized_vars(&mut self, content: &str, language: Language) {
        if self.setup_method_lines.is_empty() {
            return;
        }

        let lines: Vec<&str> = content.lines().collect();
        let mut in_setup_block = false;
        let mut brace_depth = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let line_num = line_num + 1;

            // Check if we're entering a setup method
            if self.setup_method_lines.contains(&line_num) {
                in_setup_block = true;
                brace_depth = 0;
            }

            if in_setup_block {
                // Track brace depth to know when we exit the method
                for ch in line.chars() {
                    match ch {
                        '{' => brace_depth += 1,
                        '}' => {
                            brace_depth -= 1;
                            if brace_depth == 0 {
                                in_setup_block = false;
                            }
                        }
                        _ => {}
                    }
                }

                // Extract variable assignments in setup block
                if (in_setup_block || brace_depth > 0)
                    && let Some(var) = Self::extract_assigned_var(line, language)
                {
                    self.setup_initialized_vars.insert(var);
                }
            }
        }
    }

    /// Extract the variable name from an assignment
    fn extract_assigned_var(line: &str, language: Language) -> Option<String> {
        let trimmed = line.trim();

        match language {
            Language::Java => {
                // this.conn = dataSource.getConnection();
                // conn = dataSource.getConnection();
                if let Some(eq_pos) = trimmed.find('=')
                    && eq_pos > 0
                    && !trimmed[..eq_pos].ends_with(['!', '<', '>', '='])
                {
                    let lhs = trimmed[..eq_pos].trim();
                    // Handle "this.field" pattern
                    if let Some(dot_pos) = lhs.find("this.") {
                        return Some(lhs[dot_pos + 5..].trim().to_string());
                    }
                    // Handle simple variable
                    let words: Vec<&str> = lhs.split_whitespace().collect();
                    if let Some(name) = words.last() {
                        return Some(name.to_string());
                    }
                }
                None
            }
            Language::JavaScript | Language::TypeScript => {
                // this.conn = await pool.getConnection();
                // const conn = await pool.getConnection();
                // let conn = pool.getConnection();
                if let Some(eq_pos) = trimmed.find('=')
                    && eq_pos > 0
                    && !trimmed[..eq_pos].ends_with(['!', '<', '>', '='])
                {
                    let lhs = trimmed[..eq_pos].trim();
                    // Handle "this.field" pattern
                    if let Some(dot_pos) = lhs.find("this.") {
                        return Some(lhs[dot_pos + 5..].trim().to_string());
                    }
                    // Handle const/let/var declarations
                    let lhs = lhs
                        .trim_start_matches("const ")
                        .trim_start_matches("let ")
                        .trim_start_matches("var ")
                        .trim();
                    if !lhs.is_empty() && !lhs.contains(' ') {
                        return Some(lhs.to_string());
                    }
                }
                None
            }
            Language::Python => {
                // self.conn = pool.get_connection()
                // conn = pool.get_connection()
                if let Some(eq_pos) = trimmed.find('=')
                    && eq_pos > 0
                    && !trimmed[..eq_pos].ends_with(['!', '<', '>', '='])
                {
                    let lhs = trimmed[..eq_pos].trim();
                    // Handle "self.field" pattern
                    if let Some(dot_pos) = lhs.find("self.") {
                        return Some(lhs[dot_pos + 5..].trim().to_string());
                    }
                    // Handle simple variable
                    if !lhs.contains(' ') && !lhs.contains('[') {
                        return Some(lhs.to_string());
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Check if a variable was initialized in a setup method
    pub fn is_setup_initialized(&self, var_name: &str) -> bool {
        self.setup_initialized_vars.contains(var_name)
    }

    /// Check if we're in a test file with setup methods
    pub fn has_setup_context(&self) -> bool {
        self.is_test_file && !self.setup_method_lines.is_empty()
    }
}

/// DI (Dependency Injection) context for tracking injected fields
#[derive(Debug, Clone, Default)]
pub struct DIContext {
    /// Fields annotated with DI annotations (field name -> annotation)
    pub injected_fields: HashMap<String, String>,
    /// Whether DI framework is detected
    pub has_di_framework: bool,
}

impl DIContext {
    /// Create a new empty DI context
    pub fn new() -> Self {
        Self::default()
    }

    /// Build DI context from parsed file content
    pub fn from_content(content: &str, language: Language) -> Self {
        let mut ctx = Self::new();
        ctx.detect_di_context(content, language);
        ctx
    }

    /// DI annotation patterns by language
    fn di_annotations(language: Language) -> Vec<&'static str> {
        match language {
            Language::Java => vec![
                "@Autowired",
                "@Inject",
                "@Resource",
                "@Value",
                "@PersistenceContext",
                "@EJB",
            ],
            Language::TypeScript | Language::JavaScript => vec![
                "@Inject",
                "@Injectable",
                // NestJS patterns
                "@InjectRepository",
                "@InjectConnection",
            ],
            Language::Python => vec![
                "@inject", "@Inject", // FastAPI patterns
                "Depends(",
            ],
            _ => vec![],
        }
    }

    /// Detect DI context from file content
    fn detect_di_context(&mut self, content: &str, language: Language) {
        let annotations = Self::di_annotations(language);
        if annotations.is_empty() {
            return;
        }

        let lines: Vec<&str> = content.lines().collect();
        let mut pending_annotation: Option<&str> = None;

        for line in lines.iter() {
            for annotation in &annotations {
                if line.contains(annotation) {
                    self.has_di_framework = true;

                    // Try to extract the field name from current line
                    if let Some(field_name) = Self::extract_di_field(line, language) {
                        self.injected_fields
                            .insert(field_name, annotation.to_string());
                    } else if language == Language::Java {
                        // In Java, annotation might be on a separate line
                        // Look at the next line for the field declaration
                        pending_annotation = Some(annotation);
                    }
                }
            }

            // Handle pending annotation (annotation was on previous line)
            if let Some(annotation) = pending_annotation {
                // Check if this line looks like a field declaration
                let trimmed = line.trim();
                if !trimmed.starts_with('@') && !trimmed.is_empty() && !trimmed.starts_with("//") {
                    if let Some(field_name) =
                        Self::extract_field_from_declaration(trimmed, language)
                    {
                        self.injected_fields
                            .insert(field_name, annotation.to_string());
                    }
                    pending_annotation = None;
                }
            }
        }
    }

    /// Extract field name from a field declaration (without annotation)
    fn extract_field_from_declaration(line: &str, language: Language) -> Option<String> {
        let trimmed = line.trim().trim_end_matches(';').trim();

        match language {
            Language::Java => {
                // private DataSource dataSource
                // private final UserRepository userRepo
                let words: Vec<&str> = trimmed.split_whitespace().collect();
                // Last word is the field name
                words.last().map(|s| s.to_string())
            }
            _ => None,
        }
    }

    /// Extract field name from a DI-annotated line
    fn extract_di_field(line: &str, language: Language) -> Option<String> {
        let trimmed = line.trim();

        match language {
            Language::Java => {
                // @Autowired private DataSource dataSource;
                // @Inject DataSource ds;
                let after_annotation = if let Some(pos) = trimmed.rfind('@') {
                    // Find end of annotation
                    let rest = &trimmed[pos..];
                    if let Some(space_pos) = rest.find(' ') {
                        rest[space_pos..].trim()
                    } else {
                        return None;
                    }
                } else {
                    trimmed
                };

                // Extract last word before semicolon
                let field_part = after_annotation.trim_end_matches(';').trim();
                let words: Vec<&str> = field_part.split_whitespace().collect();
                words.last().map(|s| s.to_string())
            }
            Language::TypeScript | Language::JavaScript => {
                // @Inject() private readonly dataSource: DataSource
                // constructor(@Inject() private ds: DataSource)
                if let Some(colon_pos) = trimmed.find(':') {
                    let before_colon = &trimmed[..colon_pos];
                    let words: Vec<&str> = before_colon.split_whitespace().collect();
                    words.last().map(|s| s.to_string())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Check if a field is DI-managed
    pub fn is_injected(&self, field_name: &str) -> bool {
        self.injected_fields.contains_key(field_name)
    }

    /// Check if DI framework is present
    pub fn has_di(&self) -> bool {
        self.has_di_framework
    }
}

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

    /// Typestate analysis results (lazily computed)
    typestate_results: Option<Vec<TypestateResult>>,

    /// Test context for detecting setup methods and initialized variables
    test_context: Option<TestContext>,

    /// DI context for tracking dependency-injected fields
    di_context: Option<DIContext>,

    /// Callback registry for tracking higher-order function taint flows (lazily computed)
    callback_registry: Option<CallbackRegistry>,

    /// Cached language for context building
    language: Language,
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
            typestate_results: None,
            test_context: None,
            di_context: None,
            callback_registry: None,
            language,
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
            typestate_results: None,
            test_context: None,
            di_context: None,
            callback_registry: None,
            language,
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
            typestate_results: None,
            test_context: None,
            di_context: None,
            callback_registry: None,
            language,
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
            typestate_results: None,
            test_context: None,
            di_context: None,
            callback_registry: None,
            language,
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
        if let Some(refinements) = &self.nullability_refinements
            && let Some(refined) = refinements.get(block_id, var_name)
        {
            return refined;
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

    // =========================================================================
    // Typestate analysis queries
    // =========================================================================

    /// Analyze typestate for tracked variables using provided state machines
    ///
    /// This method requires the parsed file reference to be available.
    /// For standalone analysis, use `analyze_typestate_with_context` directly.
    ///
    /// # Arguments
    /// * `state_machines` - The state machines to use for tracking
    /// * `parsed` - The parsed file (needed for AST traversal)
    ///
    /// # Returns
    /// A vector of TypestateResult, one per tracked variable
    pub fn compute_typestate(
        &mut self,
        state_machines: &[StateMachine],
        parsed: &rma_parser::ParsedFile,
    ) -> &[TypestateResult] {
        if self.typestate_results.is_none() {
            let results =
                analyze_typestate_with_context(parsed, &self.cfg, self.semantics, state_machines);
            self.typestate_results = Some(results);
        }
        self.typestate_results.as_ref().unwrap()
    }

    /// Get cached typestate results (if computed)
    pub fn typestate_results(&self) -> Option<&[TypestateResult]> {
        self.typestate_results.as_deref()
    }

    /// Check if any typestate violations were detected
    pub fn has_typestate_violations(&self) -> bool {
        self.typestate_results
            .as_ref()
            .map(|results| results.iter().any(|r| r.has_violations()))
            .unwrap_or(false)
    }

    /// Get all typestate violations from all tracked variables
    pub fn all_typestate_violations(&self) -> Vec<&TypestateViolation> {
        self.typestate_results
            .as_ref()
            .map(|results| results.iter().flat_map(|r| r.violations.iter()).collect())
            .unwrap_or_default()
    }

    // =========================================================================
    // Test Context queries
    // =========================================================================

    /// Get or compute the test context (lazily computed)
    pub fn test_context(&mut self) -> &TestContext {
        if self.test_context.is_none() {
            if let Some(source) = &self.source {
                let content = String::from_utf8_lossy(source);
                self.test_context = Some(TestContext::from_content(&content, self.language));
            } else {
                self.test_context = Some(TestContext::new());
            }
        }
        self.test_context.as_ref().unwrap()
    }

    /// Check if this is a test file with setup methods
    pub fn has_test_setup_context(&mut self) -> bool {
        self.test_context().has_setup_context()
    }

    /// Check if a variable was initialized in a setup method (@Before, setUp, etc.)
    pub fn is_setup_initialized(&mut self, var_name: &str) -> bool {
        self.test_context().is_setup_initialized(var_name)
    }

    /// Get variables initialized in setup methods
    pub fn setup_initialized_vars(&mut self) -> &HashSet<String> {
        &self.test_context().setup_initialized_vars
    }

    // =========================================================================
    // DI Context queries
    // =========================================================================

    /// Get or compute the DI context (lazily computed)
    pub fn di_context(&mut self) -> &DIContext {
        if self.di_context.is_none() {
            if let Some(source) = &self.source {
                let content = String::from_utf8_lossy(source);
                self.di_context = Some(DIContext::from_content(&content, self.language));
            } else {
                self.di_context = Some(DIContext::new());
            }
        }
        self.di_context.as_ref().unwrap()
    }

    /// Check if a field is dependency-injected (@Autowired, @Inject, etc.)
    pub fn is_injected_field(&mut self, field_name: &str) -> bool {
        self.di_context().is_injected(field_name)
    }

    /// Check if DI framework is present in this file
    pub fn has_di_framework(&mut self) -> bool {
        self.di_context().has_di()
    }

    /// Get all injected fields
    pub fn injected_fields(&mut self) -> &HashMap<String, String> {
        &self.di_context().injected_fields
    }

    /// Get the language of this file
    pub fn language(&self) -> Language {
        self.language
    }

    // =========================================================================
    // Callback Analysis queries
    // =========================================================================

    /// Compute callback taint flows (lazily computed)
    ///
    /// This analyzes the AST for callback patterns like:
    /// - Array methods: map, filter, forEach
    /// - Promise chains: .then(), .catch()
    /// - Event handlers: on('event', handler)
    ///
    /// Returns the callback registry which can be queried for tainted callback parameters.
    pub fn compute_callbacks(&mut self) -> &CallbackRegistry {
        if let Some(ref registry) = self.callback_registry {
            return registry;
        }

        if let (Some(tree), Some(source)) = (&self.tree, &self.source) {
            let file_path = self.file_path.clone().unwrap_or_default();
            let analyzer = CallbackAnalyzer::with_tainted_vars(
                self.semantics,
                source,
                file_path,
                self.taint.tainted_vars.clone(),
            );
            self.callback_registry = Some(analyzer.analyze(tree));
        } else {
            self.callback_registry = Some(CallbackRegistry::new());
        }

        self.callback_registry.as_ref().unwrap()
    }

    /// Get the callback registry (if already computed)
    pub fn callback_registry(&self) -> Option<&CallbackRegistry> {
        self.callback_registry.as_ref()
    }

    /// Check if a variable is tainted through a callback parameter
    ///
    /// This catches cases like:
    /// ```javascript
    /// taintedArray.forEach(item => {
    ///     // 'item' is tainted through callback propagation
    /// });
    /// ```
    pub fn is_tainted_via_callback(&mut self, var_name: &str) -> bool {
        let registry = self.compute_callbacks();
        registry.tainted_callback_params().contains(var_name)
    }

    /// Get all callback sites in the file
    pub fn callback_sites(&mut self) -> &[CallbackSite] {
        self.compute_callbacks().all_callbacks()
    }

    /// Get callback taint flows (source -> callback param)
    pub fn callback_taint_flows(&mut self) -> &[CallbackTaintFlow] {
        self.compute_callbacks().taint_flows()
    }

    /// Get all variables that are tainted (including through callbacks)
    ///
    /// This combines the results of basic taint analysis with callback taint propagation.
    pub fn all_tainted_vars(&mut self) -> HashSet<String> {
        let mut tainted = self.taint.tainted_vars.clone();
        let callback_tainted = self.compute_callbacks().tainted_callback_params();
        tainted.extend(callback_tainted);
        tainted
    }

    /// Check if a variable is tainted (including callback propagation)
    pub fn is_tainted_including_callbacks(&mut self, var_name: &str) -> bool {
        self.taint.is_tainted(var_name) || self.is_tainted_via_callback(var_name)
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

    #[test]
    fn test_test_context_js_detection() {
        let code = r#"
describe('User tests', () => {
    let conn;

    beforeEach(async () => {
        conn = await pool.getConnection();
    });

    it('should query users', async () => {
        const result = await conn.query('SELECT * FROM users');
    });
});
"#;
        let ctx = TestContext::from_content(code, Language::JavaScript);
        assert!(ctx.is_test_file);
        assert!(ctx.has_setup_context());
        assert!(ctx.is_setup_initialized("conn"));
    }

    #[test]
    fn test_test_context_java_detection() {
        let code = r#"
import org.junit.Before;
import org.junit.Test;

public class UserServiceTest {
    private Connection conn;

    @Before
    public void setUp() {
        this.conn = dataSource.getConnection();
    }

    @Test
    public void testQuery() {
        conn.query("SELECT * FROM users");
    }
}
"#;
        let ctx = TestContext::from_content(code, Language::Java);
        assert!(ctx.is_test_file);
        assert!(ctx.has_setup_context());
        assert!(ctx.is_setup_initialized("conn"));
    }

    #[test]
    fn test_di_context_java_detection() {
        let code = r#"
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class UserService {
    @Autowired
    private DataSource dataSource;

    @Inject
    private UserRepository userRepo;

    public void query() {
        dataSource.getConnection().query("SELECT * FROM users");
    }
}
"#;
        let ctx = DIContext::from_content(code, Language::Java);
        assert!(ctx.has_di());
        assert!(ctx.is_injected("dataSource"));
        assert!(ctx.is_injected("userRepo"));
    }

    #[test]
    fn test_test_context_python_detection() {
        let code = r#"
import unittest

class TestUserService(unittest.TestCase):
    def setUp(self):
        self.conn = get_connection()

    def test_query(self):
        result = self.conn.execute("SELECT * FROM users")
"#;
        let ctx = TestContext::from_content(code, Language::Python);
        assert!(ctx.is_test_file);
        assert!(ctx.has_setup_context());
        assert!(ctx.is_setup_initialized("conn"));
    }
}
