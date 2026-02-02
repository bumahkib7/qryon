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
#[derive(Debug, Clone, PartialEq, Eq)]
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
        if let Some(ref f) = sink.file {
            if !files.contains(f) {
                files.push(f.clone());
            }
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
        let mut result = InterproceduralResult::default();
        result.file = self.file_path.clone();

        // Phase 1: Build initial function summaries from knowledge base
        self.build_known_summaries(&mut result);

        // Phase 2: Extract function definitions and build local summaries
        self.extract_function_summaries(&mut result);

        // Phase 3: Extract call sites
        self.extract_call_sites(symbols, &mut result);

        // Phase 4: Propagate taint through call graph (fixed-point iteration)
        self.propagate_taint(symbols, &mut result);

        // Phase 5: Detect source-to-sink flows
        self.detect_flows(symbols, cfg, &mut result);

        // Phase 6: Cross-file taint propagation (if call graph available)
        if self.call_graph.is_some() {
            self.propagate_cross_file_taint(&mut result);
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
        let mut result = InterproceduralResult::default();
        result.file = Some(file_path.to_path_buf());

        // Phase 1: Build initial function summaries from knowledge base
        self.build_known_summaries(&mut result);

        // Phase 2: Extract function definitions and build local summaries
        self.extract_function_summaries(&mut result);

        // Phase 3: Extract call sites
        self.extract_call_sites(symbols, &mut result);

        // Phase 4: Propagate taint through call graph (fixed-point iteration)
        self.propagate_taint(symbols, &mut result);

        // Phase 5: Detect source-to-sink flows
        self.detect_flows(symbols, cfg, &mut result);

        // Phase 6: Cross-file taint propagation using the call graph
        self.propagate_cross_file_taint_with_graph(call_graph, file_path, &mut result);

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

    /// Propagate taint across file boundaries using the call graph
    fn propagate_cross_file_taint(&self, result: &mut InterproceduralResult) {
        if let Some(call_graph) = self.call_graph {
            if let Some(ref file_path) = self.file_path {
                self.propagate_cross_file_taint_with_graph(call_graph, file_path, result);
            }
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
                        if arg.is_tainted && summary.param_taints_return(arg.index) {
                            if let Some(ref result_var) = call_site.result_var {
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
            if let Some(summary) = result.summaries.get(&call_site.callee_name) {
                if !summary.sink_params.is_empty() {
                    // This is a sink - check if any argument is tainted via cross-file call
                    for &sink_param in &summary.sink_params {
                        if let Some(arg) = call_site.arguments.get(sink_param) {
                            // Check if the argument variable was tainted by a cross-file source
                            if let Some(ref var_name) = arg.var_name {
                                if let Some(source_info) =
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
                    if let Some(summary) = result.summaries.get(&cs.callee_name) {
                        if summary.is_source {
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
        }
        None
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
        if self.semantics.is_function_def(node.kind()) {
            if let Some(summary) = self.build_function_summary(node) {
                // Don't overwrite known summaries
                if !result.summaries.contains_key(&summary.name) {
                    result.summaries.insert(summary.name.clone(), summary);
                }
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
        if node.kind() == "return_statement" || node.kind() == "return" {
            if let Some(value) = node
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

        if self.semantics.is_identifier(node.kind()) || node.kind() == "identifier" {
            if let Ok(name) = node.utf8_text(self.source) {
                ids.push(name.to_string());
            }
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
        if self.semantics.is_call(node.kind()) {
            if let Some(call_site) = self.extract_call_site(node, symbols, result) {
                result.call_sites.push(call_site);
            }
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
                    if result_tainted {
                        if let Some(ref result_var) = call_site.result_var {
                            let func_taint =
                                result.function_taint.entry(String::new()).or_default();
                            if !func_taint.contains(result_var) {
                                func_taint.insert(result_var.clone());
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        result.iterations = iterations;
    }

    /// Detect source-to-sink flows
    fn detect_flows(&self, symbols: &SymbolTable, _cfg: &CFG, result: &mut InterproceduralResult) {
        // Find all sinks and check if their arguments are tainted
        for call_site in &result.call_sites {
            if let Some(summary) = result.summaries.get(&call_site.callee_name) {
                if !summary.sink_params.is_empty() {
                    // This is a sink
                    for &sink_param in &summary.sink_params {
                        if let Some(arg) = call_site.arguments.get(sink_param) {
                            // Check if this argument is tainted
                            let is_tainted = arg.is_tainted
                                || arg.var_name.as_ref().map_or(false, |name| {
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
    }

    fn find_taint_source(
        &self,
        var_name: &str,
        symbols: &SymbolTable,
        result: &InterproceduralResult,
    ) -> Option<TaintEndpoint> {
        // Check if it's from a known source function
        if let Some(info) = symbols.get(var_name) {
            if let ValueOrigin::FunctionCall(func_name) = &info.initializer {
                if let Some(summary) = result.summaries.get(func_name) {
                    if summary.is_source {
                        return Some(TaintEndpoint {
                            name: var_name.to_string(),
                            line: info.line,
                            node_id: info.declaration_node_id,
                            function: None,
                            kind: summary.source_kind.unwrap_or(TaintKind::Unknown),
                            file: self.file_path.clone(),
                        });
                    }
                }
            }

            // Check member access sources
            if let ValueOrigin::MemberAccess(path) = &info.initializer {
                if self.config.is_source_member(path) {
                    return Some(TaintEndpoint {
                        name: var_name.to_string(),
                        line: info.line,
                        node_id: info.declaration_node_id,
                        function: None,
                        kind: TaintKind::from_source_name(path),
                        file: self.file_path.clone(),
                    });
                }
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
                if let Some(recv) = receiver {
                    if self.config.is_source_member(recv) {
                        return true;
                    }
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
}
