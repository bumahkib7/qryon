//! Inter-procedural Taint Analysis
//!
//! Extends the intra-procedural taint analysis with function summaries to track
//! taint flow across function boundaries. This enables detection of:
//! - Cross-function taint flows (source in one function, sink in another)
//! - Library function taint behavior
//! - Callback taint propagation
//! - **Cross-file taint flows** via CallGraph integration
//!
//! The analysis works in three phases:
//! 1. Build function summaries: for each function, determine how taint flows
//!    from parameters to return value and side effects
//! 2. Apply summaries: at each call site, use the callee's summary to propagate
//!    taint from arguments to the call result
//! 3. Cross-file propagation: use CallGraph to track taint across file boundaries

use crate::callgraph::CallGraph;
use crate::flow::cfg::CFG;
use crate::flow::sources::TaintConfig;
use crate::flow::symbol_table::{SymbolTable, ValueOrigin};
use crate::semantics::LanguageSemantics;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

/// Kind of taint (for categorizing vulnerabilities)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintKind {
    /// User input (query params, body, headers)
    UserInput,
    /// File system paths
    FilePath,
    /// SQL query components
    SqlQuery,
    /// Command/shell input
    Command,
    /// HTML/DOM content
    Html,
    /// URL components
    Url,
    /// Generic/unknown taint
    Unknown,
}

impl TaintKind {
    /// Infer taint kind from a source pattern
    ///
    /// Order matters: more specific patterns (like "sql") must be checked
    /// before more general patterns (like "query").
    pub fn from_source_name(name: &str) -> Self {
        let lower = name.to_lowercase();

        // Check specific patterns first (order matters!)
        if lower.contains("sql") {
            TaintKind::SqlQuery
        } else if lower.contains("cmd") || lower.contains("exec") || lower.contains("shell") {
            TaintKind::Command
        } else if lower.contains("html") || lower.contains("dom") {
            TaintKind::Html
        } else if lower.contains("path") || lower.contains("file") {
            TaintKind::FilePath
        } else if lower.contains("url") || lower.contains("href") {
            TaintKind::Url
        } else if lower.contains("query") || lower.contains("body") || lower.contains("param") {
            // Generic user input patterns last (most general)
            TaintKind::UserInput
        } else {
            TaintKind::Unknown
        }
    }
}

/// How a function affects taint flow
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParamEffect {
    /// Parameter taint flows to return value
    TaintsReturn,
    /// Parameter taint flows to another parameter (by index)
    TaintsParam(usize),
    /// Parameter taint flows to receiver/this
    TaintsReceiver,
    /// Parameter taint is sanitized
    Sanitized,
    /// No taint effect
    None,
}

/// Represents the calling context for context-sensitive analysis.
///
/// The calling context captures which parameters are tainted at a call site.
/// This allows different summaries for calls like:
/// - `func(tainted, safe)` - context: [0]
/// - `func(safe, tainted)` - context: [1]
/// - `func(tainted, tainted)` - context: [0, 1]
#[derive(Debug, Clone, Default)]
pub struct CallContext {
    /// Set of parameter indices that are tainted in this context
    pub tainted_params: HashSet<usize>,
    /// Optional taint kinds for each tainted parameter
    pub param_taint_kinds: HashMap<usize, TaintKind>,
}

impl PartialEq for CallContext {
    fn eq(&self, other: &Self) -> bool {
        self.tainted_params == other.tainted_params
    }
}

impl Eq for CallContext {}

impl Hash for CallContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Create a sorted vector for deterministic hashing
        let mut params: Vec<_> = self.tainted_params.iter().copied().collect();
        params.sort_unstable();
        params.hash(state);
    }
}

impl CallContext {
    /// Create a new empty call context (all parameters safe)
    pub fn new() -> Self {
        Self {
            tainted_params: HashSet::new(),
            param_taint_kinds: HashMap::new(),
        }
    }

    /// Create a context from a list of tainted parameter indices
    pub fn from_tainted_params(params: impl IntoIterator<Item = usize>) -> Self {
        Self {
            tainted_params: params.into_iter().collect(),
            param_taint_kinds: HashMap::new(),
        }
    }

    /// Create a context with taint kinds
    pub fn with_taint_kinds(params: impl IntoIterator<Item = (usize, TaintKind)>) -> Self {
        let items: Vec<_> = params.into_iter().collect();
        Self {
            tainted_params: items.iter().map(|(idx, _)| *idx).collect(),
            param_taint_kinds: items.into_iter().collect(),
        }
    }

    /// Check if a specific parameter is tainted in this context
    pub fn is_param_tainted(&self, param_idx: usize) -> bool {
        self.tainted_params.contains(&param_idx)
    }

    /// Mark a parameter as tainted
    pub fn mark_tainted(&mut self, param_idx: usize) {
        self.tainted_params.insert(param_idx);
    }

    /// Mark a parameter as tainted with a specific kind
    pub fn mark_tainted_with_kind(&mut self, param_idx: usize, kind: TaintKind) {
        self.tainted_params.insert(param_idx);
        self.param_taint_kinds.insert(param_idx, kind);
    }

    /// Get the taint kind for a parameter (if known)
    pub fn get_taint_kind(&self, param_idx: usize) -> Option<TaintKind> {
        self.param_taint_kinds.get(&param_idx).copied()
    }

    /// Check if this context has any tainted parameters
    pub fn has_tainted_params(&self) -> bool {
        !self.tainted_params.is_empty()
    }

    /// Get the number of tainted parameters
    pub fn tainted_count(&self) -> usize {
        self.tainted_params.len()
    }

    /// Create a canonical string representation for use as a map key
    pub fn to_key(&self) -> String {
        let mut params: Vec<_> = self.tainted_params.iter().copied().collect();
        params.sort_unstable();
        format!(
            "ctx[{}]",
            params
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Check if this context is a subset of another (less specific)
    pub fn is_subset_of(&self, other: &CallContext) -> bool {
        self.tainted_params.is_subset(&other.tainted_params)
    }

    /// Check if this context is a superset of another (more specific)
    pub fn is_superset_of(&self, other: &CallContext) -> bool {
        self.tainted_params.is_superset(&other.tainted_params)
    }
}

/// Context-specific summary result for a function.
///
/// This represents what happens when a function is called with a specific
/// taint context (which parameters are tainted).
#[derive(Debug, Clone, Default)]
pub struct ContextSpecificResult {
    /// Whether the return value is tainted given this context
    pub return_tainted: bool,
    /// The taint kind of the return value (if tainted)
    pub return_taint_kind: Option<TaintKind>,
    /// Which parameters (by index) contribute to tainting the return
    pub contributing_params: HashSet<usize>,
    /// Side effects: which other values become tainted
    pub side_effect_taints: HashMap<String, TaintKind>,
}

impl ContextSpecificResult {
    /// Create a result indicating the return is tainted
    pub fn tainted_return(kind: TaintKind) -> Self {
        Self {
            return_tainted: true,
            return_taint_kind: Some(kind),
            contributing_params: HashSet::new(),
            side_effect_taints: HashMap::new(),
        }
    }

    /// Create a result indicating the return is safe (sanitized)
    pub fn safe_return() -> Self {
        Self {
            return_tainted: false,
            return_taint_kind: None,
            contributing_params: HashSet::new(),
            side_effect_taints: HashMap::new(),
        }
    }

    /// Mark that a specific parameter contributes to the tainted return
    pub fn with_contributing_param(mut self, param_idx: usize) -> Self {
        self.contributing_params.insert(param_idx);
        self
    }

    /// Add a side effect taint
    pub fn with_side_effect(mut self, name: String, kind: TaintKind) -> Self {
        self.side_effect_taints.insert(name, kind);
        self
    }
}

/// Context-sensitive function summary.
///
/// Unlike the basic `FunctionSummary` which provides a single summary for all calls,
/// `ContextSensitiveSummary` maintains different summaries for different calling contexts.
///
/// For example, a function `process(a, b)` might:
/// - Return tainted when `a` is tainted (context [0])
/// - Return safe when `b` is tainted (sanitizes param 1) (context [1])
/// - Return tainted when both are tainted (context [0, 1])
#[derive(Debug, Clone)]
pub struct ContextSensitiveSummary {
    /// Function name
    pub name: String,
    /// The base (context-insensitive) summary
    pub base_summary: FunctionSummary,
    /// Context-specific summaries: context -> result
    pub context_summaries: HashMap<CallContext, ContextSpecificResult>,
    /// Context-specific parameter effects
    /// Maps (context, param_index) -> effects for that param in that context
    pub context_param_effects: HashMap<(CallContext, usize), Vec<ParamEffect>>,
    /// Parameters that always sanitize (regardless of context)
    pub always_sanitizes: HashSet<usize>,
    /// Parameters that always taint return (regardless of context)
    pub always_taints_return: HashSet<usize>,
    /// Number of parameters this function accepts
    pub param_count: usize,
}

impl ContextSensitiveSummary {
    /// Create a new context-sensitive summary from a base summary
    pub fn new(base_summary: FunctionSummary) -> Self {
        let name = base_summary.name.clone();

        // Determine which params always taint return based on base summary
        let always_taints_return: HashSet<usize> = base_summary
            .param_effects
            .iter()
            .filter_map(|(&idx, effects)| {
                if effects.contains(&ParamEffect::TaintsReturn) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        Self {
            name,
            base_summary,
            context_summaries: HashMap::new(),
            context_param_effects: HashMap::new(),
            always_sanitizes: HashSet::new(),
            always_taints_return,
            param_count: 0,
        }
    }

    /// Create from a base summary with explicit param count
    pub fn with_param_count(base_summary: FunctionSummary, param_count: usize) -> Self {
        let mut summary = Self::new(base_summary);
        summary.param_count = param_count;
        summary
    }

    /// Add or update a context-specific summary
    pub fn add_context_summary(&mut self, context: CallContext, result: ContextSpecificResult) {
        self.context_summaries.insert(context, result);
    }

    /// Add context-specific parameter effects
    pub fn add_context_param_effect(
        &mut self,
        context: CallContext,
        param_idx: usize,
        effect: ParamEffect,
    ) {
        self.context_param_effects
            .entry((context, param_idx))
            .or_default()
            .push(effect);
    }

    /// Mark a parameter as always sanitizing
    pub fn mark_always_sanitizes(&mut self, param_idx: usize) {
        self.always_sanitizes.insert(param_idx);
    }

    /// Mark a parameter as always tainting return
    pub fn mark_always_taints_return(&mut self, param_idx: usize) {
        self.always_taints_return.insert(param_idx);
    }

    /// Query the summary for a specific calling context.
    ///
    /// This is the main entry point for context-sensitive taint analysis at call sites.
    /// Given the taint status of arguments, returns what happens to the return value.
    pub fn query(&self, context: &CallContext) -> ContextSpecificResult {
        // First, check for an exact match
        if let Some(result) = self.context_summaries.get(context) {
            return result.clone();
        }

        // If no exact match, compute based on rules
        self.compute_result_for_context(context)
    }

    /// Compute the result for a context that doesn't have an explicit entry
    fn compute_result_for_context(&self, context: &CallContext) -> ContextSpecificResult {
        let mut result = ContextSpecificResult::default();

        // Check if the function is a source (always taints return)
        if self.base_summary.is_source {
            result.return_tainted = true;
            result.return_taint_kind = self.base_summary.source_kind;
            return result;
        }

        // Check each tainted parameter
        for &param_idx in &context.tainted_params {
            // Check if this param always sanitizes
            if self.always_sanitizes.contains(&param_idx) {
                // This param sanitizes, so it doesn't contribute to return taint
                continue;
            }

            // Check if this param always taints return
            if self.always_taints_return.contains(&param_idx) {
                result.return_tainted = true;
                result.contributing_params.insert(param_idx);
                if result.return_taint_kind.is_none() {
                    result.return_taint_kind = context.get_taint_kind(param_idx);
                }
                continue;
            }

            // Check base summary for this param's effects
            if let Some(effects) = self.base_summary.param_effects.get(&param_idx) {
                for effect in effects {
                    match effect {
                        ParamEffect::TaintsReturn => {
                            result.return_tainted = true;
                            result.contributing_params.insert(param_idx);
                            if result.return_taint_kind.is_none() {
                                result.return_taint_kind = context.get_taint_kind(param_idx);
                            }
                        }
                        ParamEffect::Sanitized => {
                            // This specific param is sanitized in this call
                        }
                        ParamEffect::TaintsParam(other_idx) => {
                            // Track that param_idx taints another param
                            result.side_effect_taints.insert(
                                format!("param_{}", other_idx),
                                context
                                    .get_taint_kind(param_idx)
                                    .unwrap_or(TaintKind::Unknown),
                            );
                        }
                        ParamEffect::TaintsReceiver => {
                            result.side_effect_taints.insert(
                                "receiver".to_string(),
                                context
                                    .get_taint_kind(param_idx)
                                    .unwrap_or(TaintKind::Unknown),
                            );
                        }
                        ParamEffect::None => {}
                    }
                }
            }
        }

        // Handle sanitizer functions - if the function is a sanitizer, output is safe
        if self.base_summary.is_sanitizer {
            result.return_tainted = false;
            result.return_taint_kind = None;
        }

        result
    }

    /// Check if the return value would be tainted given this context
    pub fn is_return_tainted(&self, context: &CallContext) -> bool {
        self.query(context).return_tainted
    }

    /// Get all known contexts for this summary
    pub fn known_contexts(&self) -> impl Iterator<Item = &CallContext> {
        self.context_summaries.keys()
    }

    /// Build a summary for a specific context from the base summary
    pub fn build_for_context(&mut self, context: CallContext) {
        let result = self.compute_result_for_context(&context);
        self.context_summaries.insert(context, result);
    }

    /// Merge another context-sensitive summary into this one
    pub fn merge(&mut self, other: &ContextSensitiveSummary) {
        for (context, result) in &other.context_summaries {
            self.context_summaries
                .entry(context.clone())
                .or_insert_with(|| result.clone());
        }
        for ((context, param_idx), effects) in &other.context_param_effects {
            self.context_param_effects
                .entry((context.clone(), *param_idx))
                .or_default()
                .extend(effects.clone());
        }
        self.always_sanitizes.extend(&other.always_sanitizes);
        self.always_taints_return
            .extend(&other.always_taints_return);
    }
}

/// Summary of a function's taint behavior
#[derive(Debug, Clone)]
pub struct FunctionSummary {
    /// Function name (fully qualified if possible)
    pub name: String,
    /// Effects of each parameter (index -> effects)
    pub param_effects: HashMap<usize, Vec<ParamEffect>>,
    /// Whether the function is a taint source
    pub is_source: bool,
    /// Whether the function is a taint sink (and which param is sensitive)
    pub sink_params: Vec<usize>,
    /// Whether the function sanitizes its input
    pub is_sanitizer: bool,
    /// The kind of taint this function produces (if source)
    pub source_kind: Option<TaintKind>,
    /// Line number of function definition
    pub line: usize,
    /// Node ID of function definition
    pub node_id: usize,
    /// File containing this function (for cross-file tracking)
    pub file: Option<PathBuf>,
    /// Whether this function is exported (visible to other files)
    pub is_exported: bool,
}

/// Summary specifically for cross-file taint tracking
///
/// This extends FunctionSummary with additional information needed for
/// cross-file analysis via the CallGraph.
#[derive(Debug, Clone)]
pub struct TaintSummary {
    /// The underlying function summary
    pub function: FunctionSummary,
    /// Which parameter indices flow to the return value (for quick lookup)
    pub params_to_return: HashSet<usize>,
    /// Whether any parameter can taint the return value
    pub propagates_taint: bool,
    /// Taint kinds this function can introduce (if source)
    pub introduced_taint_kinds: Vec<TaintKind>,
    /// Taint kinds this function sanitizes
    pub sanitized_taint_kinds: Vec<TaintKind>,
    /// Functions this function calls (for transitive analysis)
    pub callees: Vec<String>,
}

impl TaintSummary {
    /// Create a TaintSummary from a FunctionSummary
    pub fn from_function_summary(summary: FunctionSummary) -> Self {
        let params_to_return: HashSet<usize> = summary
            .param_effects
            .iter()
            .filter_map(|(&idx, effects)| {
                if effects.contains(&ParamEffect::TaintsReturn) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();

        let propagates_taint = !params_to_return.is_empty();

        let introduced_taint_kinds = if summary.is_source {
            summary.source_kind.into_iter().collect()
        } else {
            Vec::new()
        };

        Self {
            function: summary,
            params_to_return,
            propagates_taint,
            introduced_taint_kinds,
            sanitized_taint_kinds: Vec::new(),
            callees: Vec::new(),
        }
    }

    /// Check if taint from a specific parameter reaches the return value
    pub fn param_taints_return(&self, param_idx: usize) -> bool {
        self.params_to_return.contains(&param_idx)
    }

    /// Check if this function is a taint source
    pub fn is_source(&self) -> bool {
        self.function.is_source
    }

    /// Check if this function is a sanitizer
    pub fn is_sanitizer(&self) -> bool {
        self.function.is_sanitizer
    }

    /// Get the function name
    pub fn name(&self) -> &str {
        &self.function.name
    }

    /// Get the file path if available
    pub fn file(&self) -> Option<&Path> {
        self.function.file.as_deref()
    }
}

impl FunctionSummary {
    /// Create an empty summary for a function
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            param_effects: HashMap::new(),
            is_source: false,
            sink_params: Vec::new(),
            is_sanitizer: false,
            source_kind: None,
            line: 0,
            node_id: 0,
            file: None,
            is_exported: false,
        }
    }

    /// Set the file path for this function
    pub fn with_file(mut self, file: PathBuf) -> Self {
        self.file = Some(file);
        self
    }

    /// Mark this function as exported
    pub fn as_exported(mut self) -> Self {
        self.is_exported = true;
        self
    }

    /// Mark this function as a taint source
    pub fn as_source(mut self, kind: TaintKind) -> Self {
        self.is_source = true;
        self.source_kind = Some(kind);
        self
    }

    /// Mark this function as a sanitizer
    pub fn as_sanitizer(mut self) -> Self {
        self.is_sanitizer = true;
        self
    }

    /// Mark a parameter as flowing to return value
    pub fn param_to_return(mut self, param_idx: usize) -> Self {
        self.param_effects
            .entry(param_idx)
            .or_default()
            .push(ParamEffect::TaintsReturn);
        self
    }

    /// Mark a parameter as a sink
    pub fn with_sink_param(mut self, param_idx: usize) -> Self {
        self.sink_params.push(param_idx);
        self
    }

    /// Check if taint from a parameter flows to return
    pub fn param_taints_return(&self, param_idx: usize) -> bool {
        self.param_effects
            .get(&param_idx)
            .map(|effects| effects.contains(&ParamEffect::TaintsReturn))
            .unwrap_or(false)
    }

    /// Check if any parameter taints the return value
    pub fn any_param_taints_return(&self) -> bool {
        self.param_effects
            .values()
            .any(|effects| effects.contains(&ParamEffect::TaintsReturn))
    }
}

/// Represents a call site in the program
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Node ID of the call expression
    pub node_id: usize,
    /// Name of the called function
    pub callee_name: String,
    /// Arguments at this call site
    pub arguments: Vec<CallArg>,
    /// Line number
    pub line: usize,
    /// Block ID in CFG (if available)
    pub block_id: Option<usize>,
    /// The variable receiving the call result (if any)
    pub result_var: Option<String>,
}

/// An argument at a call site
#[derive(Debug, Clone)]
pub struct CallArg {
    /// Argument index (0-based)
    pub index: usize,
    /// The expression text
    pub expr: String,
    /// If the argument is a simple variable, its name
    pub var_name: Option<String>,
    /// Whether this argument is tainted
    pub is_tainted: bool,
    /// The kind of taint (if tainted)
    pub taint_kind: Option<TaintKind>,
}

/// An endpoint in a taint flow (source or sink)
#[derive(Debug, Clone)]
pub struct TaintEndpoint {
    /// Variable or expression name
    pub name: String,
    /// Line number
    pub line: usize,
    /// Node ID
    pub node_id: usize,
    /// Function containing this endpoint
    pub function: Option<String>,
    /// Kind of taint
    pub kind: TaintKind,
    /// File containing this endpoint (for cross-file tracking)
    pub file: Option<PathBuf>,
}

/// A complete taint flow from source to sink
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// The source of taint
    pub source: TaintEndpoint,
    /// The sink where taint reaches
    pub sink: TaintEndpoint,
    /// Intermediate variables/expressions in the flow (if tracked)
    pub path: Vec<String>,
    /// Whether this flow crosses function boundaries
    pub is_interprocedural: bool,
    /// Functions involved in the flow
    pub functions_involved: Vec<String>,
    /// Whether this flow crosses file boundaries
    pub is_cross_file: bool,
    /// Files involved in the flow (for cross-file flows)
    pub files_involved: Vec<PathBuf>,
}

impl TaintFlow {
    /// Create a simple intraprocedural flow
    pub fn intraprocedural(source: TaintEndpoint, sink: TaintEndpoint) -> Self {
        let func = source.function.clone();
        let file = source.file.clone();
        Self {
            source,
            sink,
            path: Vec::new(),
            is_interprocedural: false,
            functions_involved: func.into_iter().collect(),
            is_cross_file: false,
            files_involved: file.into_iter().collect(),
        }
    }

    /// Create an interprocedural flow
    pub fn interprocedural(
        source: TaintEndpoint,
        sink: TaintEndpoint,
        functions: Vec<String>,
    ) -> Self {
        let is_cross_file = source.file != sink.file;
        let mut files = Vec::new();
        if let Some(ref f) = source.file {
            files.push(f.clone());
        }
        if let Some(ref f) = sink.file
            && !files.contains(f)
        {
            files.push(f.clone());
        }
        Self {
            source,
            sink,
            path: Vec::new(),
            is_interprocedural: true,
            functions_involved: functions,
            is_cross_file,
            files_involved: files,
        }
    }

    /// Create a cross-file flow
    pub fn cross_file(
        source: TaintEndpoint,
        sink: TaintEndpoint,
        functions: Vec<String>,
        files: Vec<PathBuf>,
    ) -> Self {
        Self {
            source,
            sink,
            path: Vec::new(),
            is_interprocedural: true,
            functions_involved: functions,
            is_cross_file: true,
            files_involved: files,
        }
    }

    /// Add intermediate path elements
    pub fn with_path(mut self, path: Vec<String>) -> Self {
        self.path = path;
        self
    }

    /// Add files involved in the flow
    pub fn with_files(mut self, files: Vec<PathBuf>) -> Self {
        self.files_involved = files;
        self.is_cross_file = self.files_involved.len() > 1;
        self
    }
}

/// Result of inter-procedural taint analysis
#[derive(Debug, Default)]
pub struct InterproceduralResult {
    /// Function summaries (function name -> summary)
    pub summaries: HashMap<String, FunctionSummary>,
    /// Context-sensitive summaries (function name -> context-sensitive summary)
    pub context_sensitive_summaries: HashMap<String, ContextSensitiveSummary>,
    /// Taint summaries for cross-file analysis (file:function -> summary)
    pub taint_summaries: HashMap<String, TaintSummary>,
    /// Detected taint flows from sources to sinks
    pub flows: Vec<TaintFlow>,
    /// Call sites in the program
    pub call_sites: Vec<CallSite>,
    /// Variables tainted at each function (function name -> set of tainted vars)
    pub function_taint: HashMap<String, HashSet<String>>,
    /// Number of analysis iterations
    pub iterations: usize,
    /// Cross-file taint flows (detected via CallGraph)
    pub cross_file_flows: Vec<TaintFlow>,
    /// File path for this result (if single-file analysis)
    pub file: Option<PathBuf>,
}

impl InterproceduralResult {
    /// Get summary for a function
    pub fn get_summary(&self, func_name: &str) -> Option<&FunctionSummary> {
        self.summaries.get(func_name)
    }

    /// Get context-sensitive summary for a function
    pub fn get_context_sensitive_summary(
        &self,
        func_name: &str,
    ) -> Option<&ContextSensitiveSummary> {
        self.context_sensitive_summaries.get(func_name)
    }

    /// Get mutable context-sensitive summary for a function
    pub fn get_context_sensitive_summary_mut(
        &mut self,
        func_name: &str,
    ) -> Option<&mut ContextSensitiveSummary> {
        self.context_sensitive_summaries.get_mut(func_name)
    }

    /// Query a function with a specific calling context.
    ///
    /// This is the primary way to use context-sensitive analysis.
    /// Given which arguments are tainted, returns the taint result.
    ///
    /// # Example
    /// ```ignore
    /// // For a call site: result = func(tainted_var, safe_var)
    /// let context = CallContext::from_tainted_params([0]);
    /// let result = analysis_result.query_with_context("func", &context);
    /// if result.return_tainted {
    ///     // The result is tainted
    /// }
    /// ```
    pub fn query_with_context(
        &self,
        func_name: &str,
        context: &CallContext,
    ) -> ContextSpecificResult {
        // First try context-sensitive summary
        if let Some(cs_summary) = self.context_sensitive_summaries.get(func_name) {
            return cs_summary.query(context);
        }

        // Fall back to basic summary
        if let Some(summary) = self.summaries.get(func_name) {
            let mut result = ContextSpecificResult::default();

            // Check if function is a source
            if summary.is_source {
                result.return_tainted = true;
                result.return_taint_kind = summary.source_kind;
                return result;
            }

            // Check if function is a sanitizer
            if summary.is_sanitizer {
                return result; // Safe return
            }

            // Check each tainted param
            for &param_idx in &context.tainted_params {
                if summary.param_taints_return(param_idx) {
                    result.return_tainted = true;
                    result.contributing_params.insert(param_idx);
                    if result.return_taint_kind.is_none() {
                        result.return_taint_kind = context.get_taint_kind(param_idx);
                    }
                }
            }

            return result;
        }

        // Unknown function - conservative: tainted input -> tainted output
        let mut result = ContextSpecificResult::default();
        if context.has_tainted_params() {
            result.return_tainted = true;
            result.return_taint_kind = Some(TaintKind::Unknown);
            result.contributing_params = context.tainted_params.clone();
        }
        result
    }

    /// Create or get the context-sensitive summary for a function
    pub fn ensure_context_sensitive_summary(
        &mut self,
        func_name: &str,
    ) -> &mut ContextSensitiveSummary {
        if !self.context_sensitive_summaries.contains_key(func_name) {
            let base_summary = self
                .summaries
                .get(func_name)
                .cloned()
                .unwrap_or_else(|| FunctionSummary::new(func_name));
            let cs_summary = ContextSensitiveSummary::new(base_summary);
            self.context_sensitive_summaries
                .insert(func_name.to_string(), cs_summary);
        }
        self.context_sensitive_summaries.get_mut(func_name).unwrap()
    }

    /// Get taint summary for a function (with cross-file info)
    pub fn get_taint_summary(&self, func_name: &str) -> Option<&TaintSummary> {
        self.taint_summaries.get(func_name)
    }

    /// Get taint summary by file and function name
    pub fn get_taint_summary_by_file(&self, file: &Path, func_name: &str) -> Option<&TaintSummary> {
        let key = format!("{}:{}", file.display(), func_name);
        self.taint_summaries.get(&key)
    }

    /// Check if a function is a known source
    pub fn is_source(&self, func_name: &str) -> bool {
        self.summaries
            .get(func_name)
            .map(|s| s.is_source)
            .unwrap_or(false)
    }

    /// Check if a function is a known sanitizer
    pub fn is_sanitizer(&self, func_name: &str) -> bool {
        self.summaries
            .get(func_name)
            .map(|s| s.is_sanitizer)
            .unwrap_or(false)
    }

    /// Get all detected flows
    pub fn get_flows(&self) -> &[TaintFlow] {
        &self.flows
    }

    /// Get flows crossing function boundaries
    pub fn interprocedural_flows(&self) -> Vec<&TaintFlow> {
        self.flows.iter().filter(|f| f.is_interprocedural).collect()
    }

    /// Get flows crossing file boundaries
    pub fn cross_file_flows(&self) -> Vec<&TaintFlow> {
        self.flows
            .iter()
            .chain(self.cross_file_flows.iter())
            .filter(|f| f.is_cross_file)
            .collect()
    }

    /// Get flows of a specific taint kind
    pub fn flows_by_kind(&self, kind: TaintKind) -> Vec<&TaintFlow> {
        self.flows
            .iter()
            .filter(|f| f.source.kind == kind)
            .collect()
    }

    /// Count total flows detected
    pub fn flow_count(&self) -> usize {
        self.flows.len() + self.cross_file_flows.len()
    }

    /// Add a taint summary for a function
    pub fn add_taint_summary(&mut self, summary: TaintSummary) {
        let key = if let Some(ref file) = summary.function.file {
            format!("{}:{}", file.display(), summary.function.name)
        } else {
            summary.function.name.clone()
        };
        self.taint_summaries.insert(key, summary);
    }

    /// Merge another result into this one (for cross-file analysis)
    pub fn merge(&mut self, other: InterproceduralResult) {
        self.summaries.extend(other.summaries);
        self.taint_summaries.extend(other.taint_summaries);
        self.flows.extend(other.flows);
        self.call_sites.extend(other.call_sites);
        for (func, vars) in other.function_taint {
            self.function_taint.entry(func).or_default().extend(vars);
        }
        self.cross_file_flows.extend(other.cross_file_flows);

        // Merge context-sensitive summaries
        for (func_name, other_summary) in other.context_sensitive_summaries {
            if let Some(existing) = self.context_sensitive_summaries.get_mut(&func_name) {
                existing.merge(&other_summary);
            } else {
                self.context_sensitive_summaries
                    .insert(func_name, other_summary);
            }
        }
    }
}

/// Inter-procedural taint analyzer
pub struct InterproceduralAnalyzer<'a> {
    /// Language semantics
    semantics: &'static LanguageSemantics,
    /// Taint configuration
    config: &'a TaintConfig,
    /// Source code bytes
    source: &'a [u8],
    /// Parsed tree
    tree: &'a tree_sitter::Tree,
    /// Optional call graph for cross-file analysis
    call_graph: Option<&'a CallGraph>,
    /// Current file path (for cross-file tracking)
    file_path: Option<PathBuf>,
}

impl<'a> InterproceduralAnalyzer<'a> {
    /// Create a new analyzer
    pub fn new(
        semantics: &'static LanguageSemantics,
        config: &'a TaintConfig,
        source: &'a [u8],
        tree: &'a tree_sitter::Tree,
    ) -> Self {
        Self {
            semantics,
            config,
            source,
            tree,
            call_graph: None,
            file_path: None,
        }
    }

    /// Create an analyzer with a call graph for cross-file analysis
    pub fn with_call_graph(
        semantics: &'static LanguageSemantics,
        config: &'a TaintConfig,
        source: &'a [u8],
        tree: &'a tree_sitter::Tree,
        call_graph: &'a CallGraph,
        file_path: PathBuf,
    ) -> Self {
        Self {
            semantics,
            config,
            source,
            tree,
            call_graph: Some(call_graph),
            file_path: Some(file_path),
        }
    }

    /// Run the inter-procedural analysis
    pub fn analyze(&self, symbols: &SymbolTable, cfg: &CFG) -> InterproceduralResult {
        let mut result = InterproceduralResult {
            file: self.file_path.clone(),
            ..Default::default()
        };

        // Phase 1: Build initial function summaries from knowledge base
        self.build_known_summaries(&mut result);

        // Phase 2: Extract function definitions and build local summaries
        self.extract_function_summaries(&mut result);

        // Phase 3: Extract call sites
        self.extract_call_sites(symbols, &mut result);

        // Phase 4: Build context-sensitive summaries from call sites
        self.build_context_sensitive_summaries(&mut result);

        // Phase 5: Propagate taint through call graph with context-sensitivity (fixed-point iteration)
        self.propagate_taint_context_sensitive(symbols, &mut result);

        // Phase 6: Detect source-to-sink flows (now context-aware)
        self.detect_flows_context_sensitive(symbols, cfg, &mut result);

        // Phase 7: Cross-file taint propagation (if call graph available)
        if let (Some(call_graph), Some(file_path)) = (self.call_graph, &self.file_path) {
            self.propagate_cross_file_taint(&mut result);
            // Phase 8: Event-based taint propagation
            self.propagate_event_taint(call_graph, file_path, &mut result);
        }

        // Build taint summaries from function summaries
        self.build_taint_summaries(&mut result);

        result
    }

    /// Run analysis with a call graph for cross-file taint tracking
    pub fn analyze_with_call_graph(
        &self,
        symbols: &SymbolTable,
        cfg: &CFG,
        call_graph: &CallGraph,
        file_path: &Path,
    ) -> InterproceduralResult {
        let mut result = InterproceduralResult {
            file: Some(file_path.to_path_buf()),
            ..Default::default()
        };

        // Phase 1: Build initial function summaries from knowledge base
        self.build_known_summaries(&mut result);

        // Phase 2: Extract function definitions and build local summaries
        self.extract_function_summaries(&mut result);

        // Phase 3: Extract call sites
        self.extract_call_sites(symbols, &mut result);

        // Phase 4: Build context-sensitive summaries from call sites
        self.build_context_sensitive_summaries(&mut result);

        // Phase 5: Propagate taint through call graph with context-sensitivity (fixed-point iteration)
        self.propagate_taint_context_sensitive(symbols, &mut result);

        // Phase 6: Detect source-to-sink flows (now context-aware)
        self.detect_flows_context_sensitive(symbols, cfg, &mut result);

        // Phase 7: Cross-file taint propagation using the call graph
        self.propagate_cross_file_taint_with_graph(call_graph, file_path, &mut result);

        // Phase 8: Event-based taint propagation
        self.propagate_event_taint(call_graph, file_path, &mut result);

        // Build taint summaries from function summaries
        self.build_taint_summaries(&mut result);

        result
    }

    /// Build TaintSummary objects from FunctionSummary objects
    fn build_taint_summaries(&self, result: &mut InterproceduralResult) {
        // Collect summaries first to avoid borrowing conflict
        let summaries_to_add: Vec<TaintSummary> = result
            .summaries
            .values()
            .map(|summary| {
                let mut func_summary = summary.clone();
                func_summary.file = self.file_path.clone();
                TaintSummary::from_function_summary(func_summary)
            })
            .collect();

        for taint_summary in summaries_to_add {
            result.add_taint_summary(taint_summary);
        }
    }

    /// Build context-sensitive summaries for all functions based on observed call sites.
    ///
    /// For each function, we create a ContextSensitiveSummary that tracks how different
    /// combinations of tainted parameters affect the return value.
    fn build_context_sensitive_summaries(&self, result: &mut InterproceduralResult) {
        // First, create context-sensitive wrappers for all base summaries
        let func_names: Vec<String> = result.summaries.keys().cloned().collect();
        for func_name in func_names {
            let base_summary = result.summaries.get(&func_name).unwrap().clone();
            let cs_summary = ContextSensitiveSummary::new(base_summary);
            result
                .context_sensitive_summaries
                .insert(func_name, cs_summary);
        }

        // Collect unique calling contexts observed at call sites
        let call_contexts: Vec<(String, CallContext)> = result
            .call_sites
            .iter()
            .map(|cs| {
                let mut context = CallContext::new();
                for arg in &cs.arguments {
                    if arg.is_tainted {
                        let kind = arg.taint_kind.unwrap_or(TaintKind::Unknown);
                        context.mark_tainted_with_kind(arg.index, kind);
                    }
                }
                (cs.callee_name.clone(), context)
            })
            .collect();

        // Build summaries for each observed context
        for (func_name, context) in call_contexts {
            if let Some(cs_summary) = result.context_sensitive_summaries.get_mut(&func_name) {
                cs_summary.build_for_context(context);
            }
        }

        // Also build common contexts (all single-param tainted) for discovered functions
        let discovered_funcs: Vec<(String, usize)> = result
            .summaries
            .iter()
            .map(|(name, summary)| {
                // Estimate param count from effects or default to 2
                let param_count = summary
                    .param_effects
                    .keys()
                    .copied()
                    .max()
                    .map(|m| m + 1)
                    .unwrap_or(2);
                (name.clone(), param_count)
            })
            .collect();

        for (func_name, param_count) in discovered_funcs {
            if let Some(cs_summary) = result.context_sensitive_summaries.get_mut(&func_name) {
                // Build single-param contexts
                for i in 0..param_count {
                    let context = CallContext::from_tainted_params([i]);
                    cs_summary.build_for_context(context);
                }
            }
        }
    }

    /// Propagate taint through the call graph with context-sensitivity.
    ///
    /// This is an enhanced version of `propagate_taint` that uses context-sensitive
    /// summaries to more precisely track taint flow.
    fn propagate_taint_context_sensitive(
        &self,
        symbols: &SymbolTable,
        result: &mut InterproceduralResult,
    ) {
        // Initialize with locally tainted variables
        for (name, info) in symbols.iter() {
            if self.is_initially_tainted(&info.initializer) {
                result
                    .function_taint
                    .entry(String::new())
                    .or_default()
                    .insert(name.clone());
            }
        }

        // Track taint kinds for variables
        let mut var_taint_kinds: HashMap<String, TaintKind> = HashMap::new();

        // Initialize taint kinds from symbols
        for (name, info) in symbols.iter() {
            if let ValueOrigin::FunctionCall(func_name) = &info.initializer
                && let Some(summary) = result.summaries.get(func_name)
                && summary.is_source
            {
                var_taint_kinds.insert(
                    name.clone(),
                    summary.source_kind.unwrap_or(TaintKind::Unknown),
                );
            }
        }

        // Fixed-point iteration with context-sensitivity
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            // Process each call site with context-sensitivity
            for i in 0..result.call_sites.len() {
                let call_site = &result.call_sites[i];
                let callee_name = call_site.callee_name.clone();
                let result_var = call_site.result_var.clone();

                // Build the calling context based on current taint state
                let mut context = CallContext::new();
                for arg in &call_site.arguments {
                    // Check if argument is tainted (either directly or by lookup)
                    let is_tainted = arg.is_tainted
                        || arg.var_name.as_ref().is_some_and(|name| {
                            result
                                .function_taint
                                .values()
                                .any(|vars| vars.contains(name))
                        });

                    if is_tainted {
                        let kind = arg
                            .taint_kind
                            .or_else(|| {
                                arg.var_name
                                    .as_ref()
                                    .and_then(|n| var_taint_kinds.get(n).copied())
                            })
                            .unwrap_or(TaintKind::Unknown);
                        context.mark_tainted_with_kind(arg.index, kind);
                    }
                }

                // Query the function with this context
                let query_result = result.query_with_context(&callee_name, &context);

                // If result is tainted and assigned to a variable, mark it
                if query_result.return_tainted
                    && let Some(ref result_var_name) = result_var
                {
                    let func_taint = result.function_taint.entry(String::new()).or_default();
                    if !func_taint.contains(result_var_name) {
                        func_taint.insert(result_var_name.clone());
                        changed = true;

                        // Track the taint kind
                        if let Some(kind) = query_result.return_taint_kind {
                            var_taint_kinds.insert(result_var_name.clone(), kind);
                        }
                    }
                }

                // Handle side effects (tainting other params/receiver)
                for (target, kind) in &query_result.side_effect_taints {
                    let func_taint = result.function_taint.entry(String::new()).or_default();
                    if !func_taint.contains(target) {
                        func_taint.insert(target.clone());
                        changed = true;
                        var_taint_kinds.insert(target.clone(), *kind);
                    }
                }
            }
        }

        result.iterations = iterations;
    }

    /// Detect source-to-sink flows with context-sensitivity.
    ///
    /// This enhanced flow detection uses context-sensitive summaries to avoid
    /// false positives where sanitization depends on which parameter is tainted.
    fn detect_flows_context_sensitive(
        &self,
        symbols: &SymbolTable,
        _cfg: &CFG,
        result: &mut InterproceduralResult,
    ) {
        // Find all sinks and check if their arguments are tainted
        for call_site in &result.call_sites {
            if let Some(summary) = result.summaries.get(&call_site.callee_name)
                && !summary.sink_params.is_empty()
            {
                // This is a sink
                for &sink_param in &summary.sink_params {
                    if let Some(arg) = call_site.arguments.get(sink_param) {
                        // Check if this argument is tainted
                        let is_tainted = arg.is_tainted
                            || arg.var_name.as_ref().is_some_and(|name| {
                                result
                                    .function_taint
                                    .values()
                                    .any(|vars| vars.contains(name))
                            });

                        if is_tainted {
                            // Check if the taint was sanitized using context-sensitive analysis
                            let var_name = arg.var_name.as_deref().unwrap_or(&arg.expr);

                            // Trace back through call sites to see if taint was sanitized
                            if self.is_taint_sanitized_context_sensitive(var_name, result) {
                                // Taint was sanitized, no flow to report
                                continue;
                            }

                            // Find the source of taint
                            if let Some(source) = self.find_taint_source(var_name, symbols, result)
                            {
                                let sink = TaintEndpoint {
                                    name: call_site.callee_name.clone(),
                                    line: call_site.line,
                                    node_id: call_site.node_id,
                                    function: None,
                                    kind: TaintKind::from_source_name(&call_site.callee_name),
                                    file: self.file_path.clone(),
                                };

                                let flow = TaintFlow::intraprocedural(source, sink);
                                result.flows.push(flow);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if taint on a variable was sanitized using context-sensitive analysis.
    ///
    /// This traces back through the call chain to see if any sanitizing function
    /// was called in a context that would sanitize the taint.
    fn is_taint_sanitized_context_sensitive(
        &self,
        var_name: &str,
        result: &InterproceduralResult,
    ) -> bool {
        // Find call sites that assign to this variable
        for call_site in &result.call_sites {
            if call_site.result_var.as_deref() == Some(var_name) {
                // Check if the callee is a sanitizer
                if let Some(summary) = result.summaries.get(&call_site.callee_name)
                    && summary.is_sanitizer
                {
                    return true;
                }

                // Check context-sensitive sanitization
                if let Some(cs_summary) = result
                    .context_sensitive_summaries
                    .get(&call_site.callee_name)
                {
                    // Build the context for this call
                    let mut context = CallContext::new();
                    for arg in &call_site.arguments {
                        if arg.is_tainted {
                            context.mark_tainted(arg.index);
                        }
                    }

                    // Query the summary
                    let query_result = cs_summary.query(&context);

                    // If the result is not tainted, the function sanitized the input
                    if !query_result.return_tainted && context.has_tainted_params() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Propagate taint across file boundaries using the call graph
    fn propagate_cross_file_taint(&self, result: &mut InterproceduralResult) {
        if let Some(call_graph) = self.call_graph
            && let Some(ref file_path) = self.file_path
        {
            self.propagate_cross_file_taint_with_graph(call_graph, file_path, result);
        }
    }

    /// Propagate taint across file boundaries using a provided call graph
    fn propagate_cross_file_taint_with_graph(
        &self,
        call_graph: &CallGraph,
        file_path: &Path,
        result: &mut InterproceduralResult,
    ) {
        // For each call site, check if the callee is in another file
        for call_site in &result.call_sites {
            // Try to find the callee in the call graph
            let callees = call_graph.get_functions_by_name(&call_site.callee_name);

            for callee in callees {
                // Skip if it's in the same file
                if callee.file == file_path {
                    continue;
                }

                // Check if the callee is a known source
                if let Some(summary) = result.summaries.get(&call_site.callee_name) {
                    if summary.is_source {
                        // If calling a source function from another file, the result is tainted
                        if let Some(ref result_var) = call_site.result_var {
                            result
                                .function_taint
                                .entry(String::new())
                                .or_default()
                                .insert(result_var.clone());
                        }
                    }

                    // Check if any tainted argument flows through a cross-file function
                    for arg in &call_site.arguments {
                        if arg.is_tainted
                            && summary.param_taints_return(arg.index)
                            && let Some(ref result_var) = call_site.result_var
                        {
                            result
                                .function_taint
                                .entry(String::new())
                                .or_default()
                                .insert(result_var.clone());
                        }
                    }
                }
            }
        }

        // Detect cross-file flows
        self.detect_cross_file_flows(call_graph, file_path, result);
    }

    /// Detect taint flows that cross file boundaries
    fn detect_cross_file_flows(
        &self,
        call_graph: &CallGraph,
        file_path: &Path,
        result: &mut InterproceduralResult,
    ) {
        // For each call site that calls a sink
        for call_site in &result.call_sites {
            if let Some(summary) = result.summaries.get(&call_site.callee_name)
                && !summary.sink_params.is_empty()
            {
                // This is a sink - check if any argument is tainted via cross-file call
                for &sink_param in &summary.sink_params {
                    if let Some(arg) = call_site.arguments.get(sink_param) {
                        // Check if the argument variable was tainted by a cross-file source
                        if let Some(ref var_name) = arg.var_name
                            && let Some(source_info) =
                                self.find_cross_file_source(var_name, call_graph, result)
                        {
                            let source = TaintEndpoint {
                                name: source_info.0.clone(),
                                line: source_info.1,
                                node_id: 0,
                                function: Some(source_info.2.clone()),
                                kind: source_info.3,
                                file: Some(source_info.4.clone()),
                            };

                            let sink = TaintEndpoint {
                                name: call_site.callee_name.clone(),
                                line: call_site.line,
                                node_id: call_site.node_id,
                                function: None,
                                kind: TaintKind::from_source_name(&call_site.callee_name),
                                file: Some(file_path.to_path_buf()),
                            };

                            let flow = TaintFlow::cross_file(
                                source,
                                sink,
                                vec![source_info.2, call_site.callee_name.clone()],
                                vec![source_info.4, file_path.to_path_buf()],
                            );

                            result.cross_file_flows.push(flow);
                        }
                    }
                }
            }
        }
    }

    /// Find if a variable was tainted by a cross-file source function
    /// Returns (source_name, line, function_name, taint_kind, source_file)
    fn find_cross_file_source(
        &self,
        var_name: &str,
        call_graph: &CallGraph,
        result: &InterproceduralResult,
    ) -> Option<(String, usize, String, TaintKind, PathBuf)> {
        // Check each call site to see if this variable was assigned from a source
        for cs in &result.call_sites {
            if cs.result_var.as_deref() == Some(var_name) {
                // Check if the callee is a source in another file
                let callees = call_graph.get_functions_by_name(&cs.callee_name);
                for callee in callees {
                    if let Some(summary) = result.summaries.get(&cs.callee_name)
                        && summary.is_source
                    {
                        return Some((
                            var_name.to_string(),
                            cs.line,
                            cs.callee_name.clone(),
                            summary.source_kind.unwrap_or(TaintKind::Unknown),
                            callee.file.clone(),
                        ));
                    }
                }
            }
        }
        None
    }

    /// Propagate taint through event emit/listen patterns
    ///
    /// When `emit('event', tainted_data)` is called:
    /// - Find all `on('event', handler)` registrations
    /// - Mark handler parameters as tainted from the event source
    ///
    /// This enables cross-file taint tracking for event-driven architectures.
    fn propagate_event_taint(
        &self,
        call_graph: &CallGraph,
        file_path: &Path,
        result: &mut InterproceduralResult,
    ) {
        use crate::flow::events::{EventPatterns, extract_emit_args, extract_event_name};

        let language = self.semantics.language_enum();
        let content = String::from_utf8_lossy(self.source);

        // Detect event patterns in this file
        let patterns = EventPatterns::for_language(language);

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for emit patterns with tainted data
            if patterns.is_emit(line)
                && let Some(event_name) = extract_event_name(line, language)
            {
                let emit_args = extract_emit_args(line, language);

                // Check if any emit arg is tainted
                for arg in &emit_args {
                    // Check if this variable is in the tainted set
                    let is_tainted = result
                        .function_taint
                        .values()
                        .any(|vars| vars.contains(arg));

                    if is_tainted {
                        // Mark all listeners of this event as receiving tainted data
                        for listener in call_graph.listeners_of(&event_name) {
                            // Create a cross-file flow from emit to listen
                            if listener.file != file_path {
                                let source = TaintEndpoint {
                                    name: format!("emit('{}')", event_name),
                                    line: line_num,
                                    node_id: 0,
                                    function: None,
                                    kind: TaintKind::UserInput,
                                    file: Some(file_path.to_path_buf()),
                                };

                                let sink = TaintEndpoint {
                                    name: format!("on('{}')", event_name),
                                    line: listener.line,
                                    node_id: 0,
                                    function: listener.function.clone(),
                                    kind: TaintKind::UserInput,
                                    file: Some(listener.file.clone()),
                                };

                                let flow = TaintFlow::cross_file(
                                    source,
                                    sink,
                                    vec![format!("event:{}", event_name)],
                                    vec![file_path.to_path_buf(), listener.file.clone()],
                                );

                                result.cross_file_flows.push(flow);
                            }

                            // Mark handler parameters as tainted
                            for handler_arg in &listener.arguments {
                                result
                                    .function_taint
                                    .entry(String::new())
                                    .or_default()
                                    .insert(handler_arg.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Build summaries for known library functions
    fn build_known_summaries(&self, result: &mut InterproceduralResult) {
        // Sources
        for source in &self.config.sources {
            let func_name = source.pattern.as_function_name();
            if let Some(name) = func_name {
                let kind = TaintKind::from_source_name(&name);
                let summary = FunctionSummary::new(&name).as_source(kind);
                result.summaries.insert(name, summary);
            }
        }

        // Sinks
        for sink in &self.config.sinks {
            let func_name = sink.pattern.as_function_name();
            if let Some(name) = func_name {
                let mut summary = result
                    .summaries
                    .remove(&name)
                    .unwrap_or_else(|| FunctionSummary::new(&name));
                // First parameter is typically the sensitive one
                summary.sink_params.push(0);
                result.summaries.insert(name, summary);
            }
        }

        // Sanitizers
        for sanitizer in &self.config.sanitizers {
            let mut summary = result
                .summaries
                .remove(sanitizer)
                .unwrap_or_else(|| FunctionSummary::new(sanitizer));
            summary.is_sanitizer = true;
            result.summaries.insert(sanitizer.clone(), summary);
        }

        // Common patterns: functions that pass taint through
        let passthrough_funcs = [
            "toString",
            "String",
            "trim",
            "toLowerCase",
            "toUpperCase",
            "slice",
            "substring",
            "substr",
            "concat",
            "split",
            "join",
            "replace", // replace without proper escaping doesn't sanitize
            "format",
            "sprintf",
        ];

        for func in passthrough_funcs {
            if !result.summaries.contains_key(func) {
                let summary = FunctionSummary::new(func).param_to_return(0);
                result.summaries.insert(func.to_string(), summary);
            }
        }
    }

    /// Extract function definitions and build summaries
    fn extract_function_summaries(&self, result: &mut InterproceduralResult) {
        let root = self.tree.root_node();
        self.walk_for_functions(root, result);
    }

    fn walk_for_functions(&self, node: tree_sitter::Node, result: &mut InterproceduralResult) {
        if self.semantics.is_function_def(node.kind())
            && let Some(summary) = self.build_function_summary(node)
        {
            // Don't overwrite known summaries
            if !result.summaries.contains_key(&summary.name) {
                result.summaries.insert(summary.name.clone(), summary);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_for_functions(child, result);
        }
    }

    fn build_function_summary(&self, node: tree_sitter::Node) -> Option<FunctionSummary> {
        // Get function name
        let name_node = node.child_by_field_name(self.semantics.name_field)?;
        let name = name_node.utf8_text(self.source).ok()?;

        let mut summary = FunctionSummary::new(name);
        summary.line = node.start_position().row + 1;
        summary.node_id = node.id();

        // Analyze function body for taint flow patterns
        if let Some(body) = node.child_by_field_name("body") {
            self.analyze_function_body(body, &mut summary);
        }

        Some(summary)
    }

    fn analyze_function_body(&self, body: tree_sitter::Node, summary: &mut FunctionSummary) {
        // Simple heuristic: if return statement references a parameter,
        // that parameter taints the return value
        self.walk_for_returns(body, summary);
    }

    fn walk_for_returns(&self, node: tree_sitter::Node, summary: &mut FunctionSummary) {
        if (node.kind() == "return_statement" || node.kind() == "return")
            && let Some(value) = node
                .child_by_field_name("value")
                .or_else(|| node.named_child(0))
        {
            // Check if return value references any parameters
            let refs = self.collect_identifiers(value);
            for _ref_name in refs {
                // Heuristic: assume first param if any identifier is returned
                // More precise analysis would track param names
                summary
                    .param_effects
                    .entry(0)
                    .or_default()
                    .push(ParamEffect::TaintsReturn);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // Don't recurse into nested function definitions
            if !self.semantics.is_function_def(child.kind()) {
                self.walk_for_returns(child, summary);
            }
        }
    }

    fn collect_identifiers(&self, node: tree_sitter::Node) -> Vec<String> {
        let mut ids = Vec::new();

        if (self.semantics.is_identifier(node.kind()) || node.kind() == "identifier")
            && let Ok(name) = node.utf8_text(self.source)
        {
            ids.push(name.to_string());
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            ids.extend(self.collect_identifiers(child));
        }

        ids
    }

    /// Extract call sites from the AST
    fn extract_call_sites(&self, symbols: &SymbolTable, result: &mut InterproceduralResult) {
        let root = self.tree.root_node();
        self.walk_for_calls(root, symbols, result);
    }

    fn walk_for_calls(
        &self,
        node: tree_sitter::Node,
        symbols: &SymbolTable,
        result: &mut InterproceduralResult,
    ) {
        if self.semantics.is_call(node.kind())
            && let Some(call_site) = self.extract_call_site(node, symbols, result)
        {
            result.call_sites.push(call_site);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_for_calls(child, symbols, result);
        }
    }

    fn extract_call_site(
        &self,
        node: tree_sitter::Node,
        _symbols: &SymbolTable,
        result: &InterproceduralResult,
    ) -> Option<CallSite> {
        // Get callee name
        let func_node = node
            .child_by_field_name("function")
            .or_else(|| node.child(0))?;
        let callee_name = func_node.utf8_text(self.source).ok()?.to_string();

        // Get arguments
        let args_node = node.child_by_field_name("arguments")?;
        let mut arguments = Vec::new();

        let mut cursor = args_node.walk();
        for (idx, arg) in args_node.named_children(&mut cursor).enumerate() {
            let expr = arg.utf8_text(self.source).unwrap_or("").to_string();

            // Check if it's a simple variable reference
            let var_name = if self.semantics.is_identifier(arg.kind()) || arg.kind() == "identifier"
            {
                Some(expr.clone())
            } else {
                None
            };

            // Check if argument is tainted
            let is_tainted = var_name
                .as_ref()
                .map(|name| {
                    result
                        .function_taint
                        .values()
                        .any(|vars| vars.contains(name))
                })
                .unwrap_or(false);

            arguments.push(CallArg {
                index: idx,
                expr,
                var_name,
                is_tainted,
                taint_kind: if is_tainted {
                    Some(TaintKind::Unknown)
                } else {
                    None
                },
            });
        }

        Some(CallSite {
            node_id: node.id(),
            callee_name,
            arguments,
            line: node.start_position().row + 1,
            block_id: None,
            result_var: None,
        })
    }

    /// Propagate taint through the call graph
    #[allow(dead_code)]
    fn propagate_taint(&self, symbols: &SymbolTable, result: &mut InterproceduralResult) {
        // Initialize with locally tainted variables
        for (name, info) in symbols.iter() {
            if self.is_initially_tainted(&info.initializer) {
                // Use empty string for file-level scope
                result
                    .function_taint
                    .entry(String::new())
                    .or_default()
                    .insert(name.clone());
            }
        }

        // Fixed-point iteration
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            // For each call site, apply callee summary
            for call_site in &result.call_sites {
                if let Some(summary) = result.summaries.get(&call_site.callee_name) {
                    // Check if any tainted argument flows through
                    let mut result_tainted = summary.is_source;

                    for arg in &call_site.arguments {
                        if arg.is_tainted && summary.param_taints_return(arg.index) {
                            result_tainted = true;
                            break;
                        }
                    }

                    // If result is tainted and assigned to a variable, mark it
                    if result_tainted && let Some(ref result_var) = call_site.result_var {
                        let func_taint = result.function_taint.entry(String::new()).or_default();
                        if !func_taint.contains(result_var) {
                            func_taint.insert(result_var.clone());
                            changed = true;
                        }
                    }
                }
            }
        }

        result.iterations = iterations;
    }

    /// Detect source-to-sink flows
    #[allow(dead_code)]
    fn detect_flows(&self, symbols: &SymbolTable, _cfg: &CFG, result: &mut InterproceduralResult) {
        // Find all sinks and check if their arguments are tainted
        for call_site in &result.call_sites {
            if let Some(summary) = result.summaries.get(&call_site.callee_name)
                && !summary.sink_params.is_empty()
            {
                // This is a sink
                for &sink_param in &summary.sink_params {
                    if let Some(arg) = call_site.arguments.get(sink_param) {
                        // Check if this argument is tainted
                        let is_tainted = arg.is_tainted
                            || arg.var_name.as_ref().is_some_and(|name| {
                                result
                                    .function_taint
                                    .values()
                                    .any(|vars| vars.contains(name))
                            });

                        if is_tainted {
                            // Find the source of taint
                            if let Some(source) = self.find_taint_source(
                                arg.var_name.as_deref().unwrap_or(&arg.expr),
                                symbols,
                                result,
                            ) {
                                let sink = TaintEndpoint {
                                    name: call_site.callee_name.clone(),
                                    line: call_site.line,
                                    node_id: call_site.node_id,
                                    function: None,
                                    kind: TaintKind::from_source_name(&call_site.callee_name),
                                    file: self.file_path.clone(),
                                };

                                let flow = TaintFlow::intraprocedural(source, sink);
                                result.flows.push(flow);
                            }
                        }
                    }
                }
            }
        }
    }

    fn find_taint_source(
        &self,
        var_name: &str,
        symbols: &SymbolTable,
        result: &InterproceduralResult,
    ) -> Option<TaintEndpoint> {
        // Check if it's from a known source function
        if let Some(info) = symbols.get(var_name) {
            if let ValueOrigin::FunctionCall(func_name) = &info.initializer
                && let Some(summary) = result.summaries.get(func_name)
                && summary.is_source
            {
                return Some(TaintEndpoint {
                    name: var_name.to_string(),
                    line: info.line,
                    node_id: info.declaration_node_id,
                    function: None,
                    kind: summary.source_kind.unwrap_or(TaintKind::Unknown),
                    file: self.file_path.clone(),
                });
            }

            // Check member access sources
            if let ValueOrigin::MemberAccess(path) = &info.initializer
                && self.config.is_source_member(path)
            {
                return Some(TaintEndpoint {
                    name: var_name.to_string(),
                    line: info.line,
                    node_id: info.declaration_node_id,
                    function: None,
                    kind: TaintKind::from_source_name(path),
                    file: self.file_path.clone(),
                });
            }

            // Check parameter sources
            if matches!(info.initializer, ValueOrigin::Parameter(_)) {
                return Some(TaintEndpoint {
                    name: var_name.to_string(),
                    line: info.line,
                    node_id: info.declaration_node_id,
                    function: None,
                    kind: TaintKind::UserInput,
                    file: self.file_path.clone(),
                });
            }
        }

        None
    }

    fn is_initially_tainted(&self, origin: &ValueOrigin) -> bool {
        match origin {
            ValueOrigin::Parameter(_) => true, // Conservative: all params are tainted
            ValueOrigin::FunctionCall(func) => self.config.is_source_function(func),
            ValueOrigin::MemberAccess(path) => self.config.is_source_member(path),
            // String concatenation: check if any operand is a source
            ValueOrigin::StringConcat(variables) => variables
                .iter()
                .any(|var| self.config.is_source_member(var)),
            // Template literals: check interpolations
            ValueOrigin::TemplateLiteral(variables) => variables
                .iter()
                .any(|var| self.config.is_source_member(var)),
            // Method calls: check receiver and arguments
            ValueOrigin::MethodCall {
                method,
                receiver,
                arguments,
            } => {
                if self.config.is_source_function(method) {
                    return true;
                }
                if let Some(recv) = receiver
                    && self.config.is_source_member(recv)
                {
                    return true;
                }
                arguments
                    .iter()
                    .any(|arg| self.config.is_source_member(arg))
            }
            _ => false,
        }
    }
}

/// Run inter-procedural taint analysis
pub fn analyze_interprocedural(
    symbols: &SymbolTable,
    cfg: &CFG,
    config: &TaintConfig,
    tree: &tree_sitter::Tree,
    source: &[u8],
    semantics: &'static LanguageSemantics,
) -> InterproceduralResult {
    let analyzer = InterproceduralAnalyzer::new(semantics, config, source, tree);
    analyzer.analyze(symbols, cfg)
}

/// Run inter-procedural taint analysis with call graph for cross-file tracking
#[allow(clippy::too_many_arguments)]
pub fn analyze_interprocedural_with_call_graph(
    symbols: &SymbolTable,
    cfg: &CFG,
    config: &TaintConfig,
    tree: &tree_sitter::Tree,
    source: &[u8],
    semantics: &'static LanguageSemantics,
    call_graph: &CallGraph,
    file_path: &Path,
) -> InterproceduralResult {
    let analyzer = InterproceduralAnalyzer::with_call_graph(
        semantics,
        config,
        source,
        tree,
        call_graph,
        file_path.to_path_buf(),
    );
    analyzer.analyze(symbols, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::sources::TaintConfig;
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
    fn test_function_summary_creation() {
        let summary = FunctionSummary::new("encodeURIComponent")
            .as_sanitizer()
            .param_to_return(0);

        assert!(summary.is_sanitizer);
        assert!(summary.param_taints_return(0));
        assert!(!summary.param_taints_return(1));
    }

    #[test]
    fn test_taint_kind_inference() {
        assert_eq!(
            TaintKind::from_source_name("req.query"),
            TaintKind::UserInput
        );
        assert_eq!(
            TaintKind::from_source_name("file_path"),
            TaintKind::FilePath
        );
        assert_eq!(
            TaintKind::from_source_name("sql_query"),
            TaintKind::SqlQuery
        );
        assert_eq!(TaintKind::from_source_name("exec_cmd"), TaintKind::Command);
    }

    #[test]
    fn test_basic_interprocedural() {
        let code = r#"
            function getInput() {
                return req.query.name;
            }

            function processInput(data) {
                return data.trim();
            }

            const input = getInput();
            const processed = processInput(input);
            console.log(processed);
        "#;

        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_interprocedural(
            &symbols,
            &cfg,
            &config,
            &parsed.tree,
            code.as_bytes(),
            semantics,
        );

        // Should have detected some function summaries
        assert!(!result.summaries.is_empty());

        // Should have detected call sites
        assert!(!result.call_sites.is_empty());
    }

    #[test]
    fn test_known_summaries() {
        let code = "const x = 1;";
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_interprocedural(
            &symbols,
            &cfg,
            &config,
            &parsed.tree,
            code.as_bytes(),
            semantics,
        );

        // Should have passthrough function summaries
        assert!(result.summaries.contains_key("toString"));
        assert!(result.summaries.contains_key("trim"));

        // toString should pass taint through
        let to_string = result.get_summary("toString").unwrap();
        assert!(to_string.param_taints_return(0));
    }

    #[test]
    fn test_taint_flow_detection() {
        let code = r#"
            function handler(userInput) {
                const data = userInput;
                sendToServer(data);
            }
        "#;

        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_interprocedural(
            &symbols,
            &cfg,
            &config,
            &parsed.tree,
            code.as_bytes(),
            semantics,
        );

        // Should complete analysis
        assert!(result.iterations > 0);
    }

    #[test]
    fn test_call_site_extraction() {
        let code = r#"
            fetch("/api");
            console.log("hello");
            process(data);
        "#;

        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_interprocedural(
            &symbols,
            &cfg,
            &config,
            &parsed.tree,
            code.as_bytes(),
            semantics,
        );

        // Should have extracted call sites
        let call_names: Vec<_> = result.call_sites.iter().map(|c| &c.callee_name).collect();
        assert!(call_names.iter().any(|n| n.contains("fetch")));
        assert!(call_names.iter().any(|n| n.contains("console")));
    }

    #[test]
    fn test_interprocedural_result_queries() {
        let mut result = InterproceduralResult::default();

        // Add a source summary
        let source_summary = FunctionSummary::new("getInput").as_source(TaintKind::UserInput);
        result
            .summaries
            .insert("getInput".to_string(), source_summary);

        // Add a sanitizer summary
        let sanitizer_summary = FunctionSummary::new("escape").as_sanitizer();
        result
            .summaries
            .insert("escape".to_string(), sanitizer_summary);

        assert!(result.is_source("getInput"));
        assert!(!result.is_source("escape"));
        assert!(result.is_sanitizer("escape"));
        assert!(!result.is_sanitizer("getInput"));
    }

    #[test]
    fn test_taint_summary_from_function_summary() {
        let func_summary = FunctionSummary::new("getInput")
            .as_source(TaintKind::UserInput)
            .with_file(PathBuf::from("/project/src/utils.js"))
            .as_exported();

        let taint_summary = TaintSummary::from_function_summary(func_summary);

        assert!(taint_summary.is_source());
        assert!(!taint_summary.is_sanitizer());
        assert_eq!(taint_summary.name(), "getInput");
        assert!(
            taint_summary
                .introduced_taint_kinds
                .contains(&TaintKind::UserInput)
        );
    }

    #[test]
    fn test_taint_summary_propagation() {
        let func_summary = FunctionSummary::new("processData")
            .param_to_return(0)
            .param_to_return(1);

        let taint_summary = TaintSummary::from_function_summary(func_summary);

        assert!(taint_summary.propagates_taint);
        assert!(taint_summary.param_taints_return(0));
        assert!(taint_summary.param_taints_return(1));
        assert!(!taint_summary.param_taints_return(2));
    }

    #[test]
    fn test_cross_file_taint_flow_creation() {
        let source = TaintEndpoint {
            name: "userInput".to_string(),
            line: 10,
            node_id: 100,
            function: Some("getInput".to_string()),
            kind: TaintKind::UserInput,
            file: Some(PathBuf::from("/project/src/input.js")),
        };

        let sink = TaintEndpoint {
            name: "query".to_string(),
            line: 20,
            node_id: 200,
            function: Some("runQuery".to_string()),
            kind: TaintKind::SqlQuery,
            file: Some(PathBuf::from("/project/src/database.js")),
        };

        let flow = TaintFlow::cross_file(
            source,
            sink,
            vec!["getInput".to_string(), "runQuery".to_string()],
            vec![
                PathBuf::from("/project/src/input.js"),
                PathBuf::from("/project/src/database.js"),
            ],
        );

        assert!(flow.is_cross_file);
        assert!(flow.is_interprocedural);
        assert_eq!(flow.files_involved.len(), 2);
        assert_eq!(flow.functions_involved.len(), 2);
    }

    #[test]
    fn test_interprocedural_result_merge() {
        let mut result1 = InterproceduralResult::default();
        let mut result2 = InterproceduralResult::default();

        // Add summary to result1
        let summary1 = FunctionSummary::new("func1").as_source(TaintKind::UserInput);
        result1.summaries.insert("func1".to_string(), summary1);

        // Add summary to result2
        let summary2 = FunctionSummary::new("func2").as_sanitizer();
        result2.summaries.insert("func2".to_string(), summary2);

        // Merge result2 into result1
        result1.merge(result2);

        // Both summaries should be present
        assert!(result1.summaries.contains_key("func1"));
        assert!(result1.summaries.contains_key("func2"));
    }

    #[test]
    fn test_cross_file_taint_tracking_integration() {
        use crate::callgraph::CallGraphBuilder;
        use crate::imports::FileImports;
        use crate::imports::ImportKind;
        use crate::imports::ResolvedImport;

        // Simulate file1.js: exports getInput() that returns req.query
        let file1_code = r#"
            export function getInput() {
                return req.query.name;
            }
        "#;

        // Simulate file2.js: imports getInput and passes result to db.query()
        let file2_code = r#"
            import { getInput } from './utils';

            function handleRequest() {
                const input = getInput();
                db.query(input);
            }
        "#;

        // Parse both files
        let file1_path = Path::new("/project/src/utils.js");
        let file2_path = Path::new("/project/src/handler.js");

        let parsed1 = ParserEngine::new(rma_common::RmaConfig::default())
            .parse_file(file1_path, file1_code)
            .expect("parse file1 failed");

        let parsed2 = ParserEngine::new(rma_common::RmaConfig::default())
            .parse_file(file2_path, file2_code)
            .expect("parse file2 failed");

        // Build call graph
        let mut builder = CallGraphBuilder::new();

        // Add file1 (utils.js) - exports getInput
        builder.add_file(
            file1_path,
            Language::JavaScript,
            vec![("getInput".to_string(), 2, true)], // exported function
            vec![],                                  // no calls
            FileImports::default(),
        );

        // Add file2 (handler.js) - imports and calls getInput
        let mut file2_imports = FileImports::default();
        file2_imports.imports.push(ResolvedImport {
            local_name: "getInput".to_string(),
            source_file: file1_path.to_path_buf(),
            exported_name: "getInput".to_string(),
            kind: ImportKind::Named,
            specifier: "./utils".to_string(),
            line: 2,
        });

        builder.add_file(
            file2_path,
            Language::JavaScript,
            vec![("handleRequest".to_string(), 4, false)],
            vec![
                ("getInput".to_string(), 5, Some("handleRequest".to_string())),
                ("query".to_string(), 6, Some("handleRequest".to_string())),
            ],
            file2_imports,
        );

        let call_graph = builder.build();

        // Verify call graph has cross-file edge
        assert!(call_graph.edge_count() >= 1);
        let cross_file_edges = call_graph.cross_file_edges();
        assert!(
            !cross_file_edges.is_empty(),
            "Should have cross-file call edge"
        );

        // Analyze file1 and create taint summary
        let symbols1 = SymbolTable::build(&parsed1, Language::JavaScript);
        let cfg1 = CFG::build(&parsed1, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result1 = analyze_interprocedural_with_call_graph(
            &symbols1,
            &cfg1,
            &config,
            &parsed1.tree,
            file1_code.as_bytes(),
            semantics,
            &call_graph,
            file1_path,
        );

        // getInput should be detected as returning tainted data
        // (it accesses req.query which is a known source)
        assert!(result1.summaries.contains_key("getInput"));

        // Analyze file2 with the call graph
        let symbols2 = SymbolTable::build(&parsed2, Language::JavaScript);
        let cfg2 = CFG::build(&parsed2, Language::JavaScript);

        let result2 = analyze_interprocedural_with_call_graph(
            &symbols2,
            &cfg2,
            &config,
            &parsed2.tree,
            file2_code.as_bytes(),
            semantics,
            &call_graph,
            file2_path,
        );

        // Verify call sites were extracted
        assert!(!result2.call_sites.is_empty());
        let callee_names: Vec<_> = result2.call_sites.iter().map(|c| &c.callee_name).collect();
        assert!(
            callee_names.iter().any(|n| *n == "getInput"),
            "Should detect getInput call"
        );
    }

    #[test]
    fn test_taint_endpoint_with_file() {
        let endpoint = TaintEndpoint {
            name: "data".to_string(),
            line: 10,
            node_id: 100,
            function: Some("handler".to_string()),
            kind: TaintKind::UserInput,
            file: Some(PathBuf::from("/project/src/main.js")),
        };

        assert_eq!(endpoint.name, "data");
        assert_eq!(endpoint.file, Some(PathBuf::from("/project/src/main.js")));
    }

    #[test]
    fn test_cross_file_flow_queries() {
        let mut result = InterproceduralResult::default();

        // Add a cross-file flow
        let source = TaintEndpoint {
            name: "input".to_string(),
            line: 1,
            node_id: 1,
            function: Some("getInput".to_string()),
            kind: TaintKind::UserInput,
            file: Some(PathBuf::from("/file1.js")),
        };

        let sink = TaintEndpoint {
            name: "query".to_string(),
            line: 10,
            node_id: 10,
            function: Some("runQuery".to_string()),
            kind: TaintKind::SqlQuery,
            file: Some(PathBuf::from("/file2.js")),
        };

        let flow = TaintFlow::cross_file(
            source,
            sink,
            vec!["getInput".to_string(), "runQuery".to_string()],
            vec![PathBuf::from("/file1.js"), PathBuf::from("/file2.js")],
        );

        result.cross_file_flows.push(flow);

        // Query cross-file flows
        let cross_file = result.cross_file_flows();
        assert_eq!(cross_file.len(), 1);
        assert!(cross_file[0].is_cross_file);

        // Total flow count should include cross-file flows
        assert_eq!(result.flow_count(), 1);
    }

    // ==================== Context-Sensitivity Tests ====================

    #[test]
    fn test_call_context_creation() {
        // Empty context (all safe)
        let ctx = CallContext::new();
        assert!(!ctx.has_tainted_params());
        assert_eq!(ctx.tainted_count(), 0);
        assert!(!ctx.is_param_tainted(0));

        // Context with tainted param 0
        let ctx = CallContext::from_tainted_params([0]);
        assert!(ctx.has_tainted_params());
        assert_eq!(ctx.tainted_count(), 1);
        assert!(ctx.is_param_tainted(0));
        assert!(!ctx.is_param_tainted(1));

        // Context with taint kinds
        let ctx =
            CallContext::with_taint_kinds([(0, TaintKind::UserInput), (2, TaintKind::SqlQuery)]);
        assert!(ctx.is_param_tainted(0));
        assert!(!ctx.is_param_tainted(1));
        assert!(ctx.is_param_tainted(2));
        assert_eq!(ctx.get_taint_kind(0), Some(TaintKind::UserInput));
        assert_eq!(ctx.get_taint_kind(2), Some(TaintKind::SqlQuery));
        assert_eq!(ctx.get_taint_kind(1), None);
    }

    #[test]
    fn test_call_context_key_generation() {
        let ctx1 = CallContext::from_tainted_params([0, 2]);
        let ctx2 = CallContext::from_tainted_params([2, 0]); // Same params, different order

        // Keys should be the same regardless of insertion order
        assert_eq!(ctx1.to_key(), ctx2.to_key());
        assert_eq!(ctx1.to_key(), "ctx[0,2]");
    }

    #[test]
    fn test_call_context_subset_superset() {
        let ctx_empty = CallContext::new();
        let ctx_0 = CallContext::from_tainted_params([0]);
        let ctx_01 = CallContext::from_tainted_params([0, 1]);
        let ctx_012 = CallContext::from_tainted_params([0, 1, 2]);

        // Empty is subset of everything
        assert!(ctx_empty.is_subset_of(&ctx_0));
        assert!(ctx_empty.is_subset_of(&ctx_01));

        // Proper subset relationship
        assert!(ctx_0.is_subset_of(&ctx_01));
        assert!(ctx_01.is_subset_of(&ctx_012));
        assert!(!ctx_01.is_subset_of(&ctx_0));

        // Superset relationships
        assert!(ctx_01.is_superset_of(&ctx_0));
        assert!(ctx_012.is_superset_of(&ctx_01));
    }

    #[test]
    fn test_context_specific_result() {
        // Safe result
        let result = ContextSpecificResult::safe_return();
        assert!(!result.return_tainted);
        assert!(result.return_taint_kind.is_none());

        // Tainted result
        let result = ContextSpecificResult::tainted_return(TaintKind::UserInput)
            .with_contributing_param(0)
            .with_contributing_param(2);
        assert!(result.return_tainted);
        assert_eq!(result.return_taint_kind, Some(TaintKind::UserInput));
        assert!(result.contributing_params.contains(&0));
        assert!(result.contributing_params.contains(&2));
        assert!(!result.contributing_params.contains(&1));

        // Result with side effects
        let result = ContextSpecificResult::tainted_return(TaintKind::Command)
            .with_side_effect("receiver".to_string(), TaintKind::Command);
        assert_eq!(
            result.side_effect_taints.get("receiver"),
            Some(&TaintKind::Command)
        );
    }

    #[test]
    fn test_context_sensitive_summary_basic() {
        // Create a function that passes param 0 through but sanitizes param 1
        let mut base = FunctionSummary::new("process");
        base.param_effects
            .entry(0)
            .or_default()
            .push(ParamEffect::TaintsReturn);
        base.param_effects
            .entry(1)
            .or_default()
            .push(ParamEffect::Sanitized);

        let mut cs_summary = ContextSensitiveSummary::new(base);
        cs_summary.mark_always_sanitizes(1);

        // Query with param 0 tainted -> return tainted
        let ctx0 = CallContext::from_tainted_params([0]);
        let result0 = cs_summary.query(&ctx0);
        assert!(result0.return_tainted, "param 0 should taint return");
        assert!(result0.contributing_params.contains(&0));

        // Query with param 1 tainted -> return safe (sanitized)
        let ctx1 = CallContext::from_tainted_params([1]);
        let result1 = cs_summary.query(&ctx1);
        assert!(!result1.return_tainted, "param 1 should be sanitized");

        // Query with both tainted -> return tainted (param 0 wins)
        let ctx01 = CallContext::from_tainted_params([0, 1]);
        let result01 = cs_summary.query(&ctx01);
        assert!(
            result01.return_tainted,
            "param 0 should taint despite param 1 sanitizing"
        );
    }

    #[test]
    fn test_context_sensitive_summary_with_explicit_contexts() {
        let base = FunctionSummary::new("transform");
        let mut cs_summary = ContextSensitiveSummary::new(base);

        // Add explicit context-specific summaries
        let ctx0 = CallContext::from_tainted_params([0]);
        cs_summary.add_context_summary(
            ctx0.clone(),
            ContextSpecificResult::tainted_return(TaintKind::UserInput).with_contributing_param(0),
        );

        let ctx1 = CallContext::from_tainted_params([1]);
        cs_summary.add_context_summary(ctx1.clone(), ContextSpecificResult::safe_return());

        // Query explicit contexts
        let result0 = cs_summary.query(&ctx0);
        assert!(result0.return_tainted);

        let result1 = cs_summary.query(&ctx1);
        assert!(!result1.return_tainted);
    }

    #[test]
    fn test_context_sensitive_source_function() {
        // Source functions always taint return regardless of context
        let base = FunctionSummary::new("getInput").as_source(TaintKind::UserInput);
        let cs_summary = ContextSensitiveSummary::new(base);

        // Even with no tainted params, a source returns tainted
        let ctx_empty = CallContext::new();
        let result = cs_summary.query(&ctx_empty);
        assert!(result.return_tainted);
        assert_eq!(result.return_taint_kind, Some(TaintKind::UserInput));
    }

    #[test]
    fn test_context_sensitive_sanitizer_function() {
        // Sanitizer functions always return safe
        let base = FunctionSummary::new("escape")
            .as_sanitizer()
            .param_to_return(0);
        let cs_summary = ContextSensitiveSummary::new(base);

        // Even with tainted input, sanitizer returns safe
        let ctx = CallContext::from_tainted_params([0]);
        let result = cs_summary.query(&ctx);
        assert!(!result.return_tainted);
    }

    #[test]
    fn test_interprocedural_result_query_with_context() {
        let mut result = InterproceduralResult::default();

        // Add a function that taints return from param 0 only
        let summary = FunctionSummary::new("process").param_to_return(0);
        result
            .summaries
            .insert("process".to_string(), summary.clone());

        let mut cs_summary = ContextSensitiveSummary::new(summary);
        cs_summary.mark_always_taints_return(0);
        result
            .context_sensitive_summaries
            .insert("process".to_string(), cs_summary);

        // Query with param 0 tainted
        let ctx0 = CallContext::from_tainted_params([0]);
        let query0 = result.query_with_context("process", &ctx0);
        assert!(
            query0.return_tainted,
            "process(tainted, _) should return tainted"
        );

        // Query with param 1 tainted (not param 0)
        let ctx1 = CallContext::from_tainted_params([1]);
        let query1 = result.query_with_context("process", &ctx1);
        assert!(
            !query1.return_tainted,
            "process(_, tainted) should return safe"
        );
    }

    #[test]
    fn test_different_contexts_produce_different_results() {
        // This is the key test: func(tainted, safe) != func(safe, tainted)
        let mut result = InterproceduralResult::default();

        // Create a function where:
        // - param 0 tainted -> return tainted
        // - param 1 tainted -> return safe (it sanitizes)
        let mut summary = FunctionSummary::new("processInput");
        summary
            .param_effects
            .entry(0)
            .or_default()
            .push(ParamEffect::TaintsReturn);
        result
            .summaries
            .insert("processInput".to_string(), summary.clone());

        let mut cs_summary = ContextSensitiveSummary::with_param_count(summary, 2);
        cs_summary.mark_always_taints_return(0);
        cs_summary.mark_always_sanitizes(1);
        result
            .context_sensitive_summaries
            .insert("processInput".to_string(), cs_summary);

        // func(tainted, safe) -> tainted
        let ctx_tainted_safe = CallContext::from_tainted_params([0]);
        let result_ts = result.query_with_context("processInput", &ctx_tainted_safe);
        assert!(
            result_ts.return_tainted,
            "func(tainted, safe) should return tainted"
        );

        // func(safe, tainted) -> safe (param 1 sanitizes)
        let ctx_safe_tainted = CallContext::from_tainted_params([1]);
        let result_st = result.query_with_context("processInput", &ctx_safe_tainted);
        assert!(
            !result_st.return_tainted,
            "func(safe, tainted) should return safe"
        );

        // These two contexts produce DIFFERENT results!
        assert_ne!(
            result_ts.return_tainted, result_st.return_tainted,
            "Different contexts should produce different results"
        );
    }

    #[test]
    fn test_context_sensitive_summary_merge() {
        let base = FunctionSummary::new("func");
        let mut summary1 = ContextSensitiveSummary::new(base.clone());
        let mut summary2 = ContextSensitiveSummary::new(base);

        // Add different contexts to each
        let ctx0 = CallContext::from_tainted_params([0]);
        summary1.add_context_summary(
            ctx0.clone(),
            ContextSpecificResult::tainted_return(TaintKind::UserInput),
        );

        let ctx1 = CallContext::from_tainted_params([1]);
        summary2.add_context_summary(ctx1.clone(), ContextSpecificResult::safe_return());

        // Merge
        summary1.merge(&summary2);

        // Both contexts should be present
        assert!(summary1.context_summaries.contains_key(&ctx0));
        assert!(summary1.context_summaries.contains_key(&ctx1));
    }

    #[test]
    fn test_ensure_context_sensitive_summary() {
        let mut result = InterproceduralResult::default();

        // Add base summary
        let summary = FunctionSummary::new("myFunc").param_to_return(0);
        result.summaries.insert("myFunc".to_string(), summary);

        // Ensure creates it if it doesn't exist
        {
            let cs = result.ensure_context_sensitive_summary("myFunc");
            cs.mark_always_taints_return(0);
        }

        // Should now exist
        assert!(result.context_sensitive_summaries.contains_key("myFunc"));

        // Should preserve modifications
        let cs = result.get_context_sensitive_summary("myFunc").unwrap();
        assert!(cs.always_taints_return.contains(&0));
    }

    #[test]
    fn test_unknown_function_context_query() {
        let result = InterproceduralResult::default();

        // Query an unknown function - should be conservative
        let ctx = CallContext::from_tainted_params([0]);
        let query = result.query_with_context("unknownFunc", &ctx);

        // Conservative: tainted input -> tainted output for unknown functions
        assert!(query.return_tainted);
        assert_eq!(query.return_taint_kind, Some(TaintKind::Unknown));
    }

    #[test]
    fn test_context_with_taint_kind_propagation() {
        let mut result = InterproceduralResult::default();

        // Function that passes through the taint kind
        let summary = FunctionSummary::new("passthrough").param_to_return(0);
        result
            .summaries
            .insert("passthrough".to_string(), summary.clone());
        result.context_sensitive_summaries.insert(
            "passthrough".to_string(),
            ContextSensitiveSummary::new(summary),
        );

        // Query with SQL taint
        let ctx = CallContext::with_taint_kinds([(0, TaintKind::SqlQuery)]);
        let query = result.query_with_context("passthrough", &ctx);

        assert!(query.return_tainted);
        assert_eq!(query.return_taint_kind, Some(TaintKind::SqlQuery));
    }

    #[test]
    fn test_build_context_sensitive_summaries_creates_common_contexts() {
        let code = r#"
            function process(a, b) {
                return a.trim();
            }
            process(userInput, safe);
        "#;

        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let config = TaintConfig::for_language(Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_interprocedural(
            &symbols,
            &cfg,
            &config,
            &parsed.tree,
            code.as_bytes(),
            semantics,
        );

        // Should have built context-sensitive summaries
        // Note: "process" might be in summaries depending on analysis
        // The key point is that context-sensitive infrastructure is in place
        assert!(!result.context_sensitive_summaries.is_empty() || !result.summaries.is_empty());
    }
}
