//! Cross-File Call Graph with Security Classification
//!
//! Builds a project-wide call graph by:
//! 1. Collecting function definitions from all files
//! 2. Classifying functions as sources/sinks/sanitizers using knowledge system
//! 3. Resolving imports to connect callers to callees across files
//! 4. Tracking call relationships for cross-file taint analysis
//!
//! # Security Classification
//!
//! Functions are classified based on what APIs they call internally,
//! not just their names. This enables language-agnostic taint analysis
//! that works across all 28+ supported languages.
//!
//! # Usage
//!
//! ```ignore
//! let builder = CallGraphBuilder::new();
//! builder.add_file(&parsed_file, &file_imports);
//! let graph = builder.build();
//!
//! // Find callers of a function
//! let callers = graph.callers_of("sanitize", Path::new("src/utils.js"));
//!
//! // Find all source functions
//! let sources = graph.source_functions();
//!
//! // Find all sink functions
//! let sinks = graph.sink_functions();
//! ```

pub mod classifier;

use crate::imports::FileImports;
use rma_common::Language;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub use classifier::FunctionClassifier;

// =============================================================================
// Function Security Classification
// =============================================================================
// This is the bridge between the call graph and the knowledge system.
// Functions are classified based on what APIs they call internally,
// not just their names. This enables language-agnostic taint analysis.

/// Security-relevant classification of a function
#[derive(Debug, Clone, Default)]
pub struct FunctionClassification {
    /// Is this function a taint source? (receives external input)
    pub is_source: bool,
    /// Type of source if applicable
    pub source_kind: Option<SourceClassification>,
    /// Does this function contain sink calls? (dangerous operations)
    pub contains_sinks: bool,
    /// Types of sinks contained
    pub sink_kinds: Vec<SinkClassification>,
    /// Does this function call sanitizers?
    pub calls_sanitizers: bool,
    /// What types of taint does it sanitize?
    pub sanitizes: Vec<String>,
    /// Confidence of this classification (0.0 - 1.0)
    pub confidence: f32,
}

impl PartialEq for FunctionClassification {
    fn eq(&self, other: &Self) -> bool {
        self.is_source == other.is_source
            && self.source_kind == other.source_kind
            && self.contains_sinks == other.contains_sinks
            && self.sink_kinds == other.sink_kinds
            && self.calls_sanitizers == other.calls_sanitizers
            && self.sanitizes == other.sanitizes
        // Ignore confidence for equality
    }
}

impl Eq for FunctionClassification {}

impl std::hash::Hash for FunctionClassification {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.is_source.hash(state);
        self.source_kind.hash(state);
        self.contains_sinks.hash(state);
        self.sink_kinds.hash(state);
        self.calls_sanitizers.hash(state);
        self.sanitizes.hash(state);
        // Ignore confidence for hashing
    }
}

/// Classification of a taint source
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceClassification {
    /// HTTP request handler (servlet, controller, handler)
    HttpHandler,
    /// HTTP parameter/header/cookie access
    HttpInput,
    /// File/stream input
    FileInput,
    /// Environment variable access
    EnvironmentVariable,
    /// Database result (for stored XSS)
    DatabaseResult,
    /// Message queue / event input
    MessageInput,
    /// Command line arguments
    CommandLineArgs,
    /// Other user-controlled input
    Other(String),
}

/// Classification of a taint sink
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SinkClassification {
    /// SQL query execution (CWE-89)
    SqlInjection,
    /// OS command execution (CWE-78)
    CommandInjection,
    /// Path/file operations (CWE-22)
    PathTraversal,
    /// Cross-site scripting (CWE-79)
    CrossSiteScripting,
    /// Deserialization (CWE-502)
    Deserialization,
    /// LDAP injection (CWE-90)
    LdapInjection,
    /// Template injection (SSTI)
    TemplateInjection,
    /// XML injection / XXE
    XmlInjection,
    /// Log injection (CWE-117)
    LogInjection,
    /// Open redirect (CWE-601)
    OpenRedirect,
    /// Generic injection (CWE-74) - used when specific type can't be proven
    GenericInjection,
    /// Other dangerous operation
    Other(String),
}

/// Evidence type for sink classification
///
/// Higher-quality evidence = higher confidence in classification.
/// Without evidence, sinks should be downgraded to GenericInjection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkEvidenceKind {
    /// Callee resolves to known fully-qualified target (e.g., database/sql.(*DB).Query)
    /// This is the strongest evidence
    CalleeEvidence {
        /// Fully qualified callee name (e.g., "database/sql.(*DB).Query")
        qualified_name: String,
    },
    /// File imports a known sink package (e.g., database/sql)
    ImportEvidence {
        /// Import path (e.g., "database/sql")
        import_path: String,
    },
    /// Receiver/argument type matches known sink type (e.g., *sql.DB)
    TypeEvidence {
        /// Type name (e.g., "*sql.DB")
        type_name: String,
    },
    /// Pattern-based match only (function name matches sink pattern)
    /// This is weak evidence - should trigger downgrade to GenericInjection
    PatternOnly {
        /// Pattern that matched
        pattern: String,
    },
    /// No evidence available
    None,
}

/// Evidence for a sink classification
#[derive(Debug, Clone, PartialEq)]
pub struct SinkEvidence {
    /// Kind of evidence
    pub kind: SinkEvidenceKind,
    /// Confidence from this evidence (0.0 - 1.0)
    pub confidence: f32,
    /// Details/description
    pub details: String,
}

impl SinkEvidence {
    /// Create evidence from callee resolution
    pub fn from_callee(qualified_name: impl Into<String>) -> Self {
        let qn = qualified_name.into();
        Self {
            details: format!("callee: {}", qn),
            kind: SinkEvidenceKind::CalleeEvidence { qualified_name: qn },
            confidence: 0.95,
        }
    }

    /// Create evidence from import
    pub fn from_import(import_path: impl Into<String>) -> Self {
        let ip = import_path.into();
        Self {
            details: format!("imports: {}", ip),
            kind: SinkEvidenceKind::ImportEvidence { import_path: ip },
            confidence: 0.8,
        }
    }

    /// Create evidence from type
    pub fn from_type(type_name: impl Into<String>) -> Self {
        let tn = type_name.into();
        Self {
            details: format!("type: {}", tn),
            kind: SinkEvidenceKind::TypeEvidence { type_name: tn },
            confidence: 0.85,
        }
    }

    /// Create pattern-only evidence (weak)
    pub fn from_pattern(pattern: impl Into<String>) -> Self {
        let p = pattern.into();
        Self {
            details: format!("pattern: {}", p),
            kind: SinkEvidenceKind::PatternOnly { pattern: p },
            confidence: 0.3,
        }
    }

    /// No evidence
    pub fn none() -> Self {
        Self {
            kind: SinkEvidenceKind::None,
            confidence: 0.0,
            details: "no evidence".to_string(),
        }
    }

    /// Is this strong evidence (callee, type, or import)?
    pub fn is_strong(&self) -> bool {
        matches!(
            self.kind,
            SinkEvidenceKind::CalleeEvidence { .. }
                | SinkEvidenceKind::TypeEvidence { .. }
                | SinkEvidenceKind::ImportEvidence { .. }
        )
    }
}

impl std::fmt::Display for SourceClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceClassification::HttpHandler => write!(f, "HTTP Handler"),
            SourceClassification::HttpInput => write!(f, "HTTP Input"),
            SourceClassification::FileInput => write!(f, "File Input"),
            SourceClassification::EnvironmentVariable => write!(f, "Environment Variable"),
            SourceClassification::DatabaseResult => write!(f, "Database Result"),
            SourceClassification::MessageInput => write!(f, "Message Input"),
            SourceClassification::CommandLineArgs => write!(f, "Command Line Args"),
            SourceClassification::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::fmt::Display for SinkClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkClassification::SqlInjection => write!(f, "SQL Injection"),
            SinkClassification::CommandInjection => write!(f, "Command Injection"),
            SinkClassification::PathTraversal => write!(f, "Path Traversal"),
            SinkClassification::CrossSiteScripting => write!(f, "XSS"),
            SinkClassification::Deserialization => write!(f, "Deserialization"),
            SinkClassification::LdapInjection => write!(f, "LDAP Injection"),
            SinkClassification::TemplateInjection => write!(f, "Template Injection"),
            SinkClassification::XmlInjection => write!(f, "XML Injection"),
            SinkClassification::LogInjection => write!(f, "Log Injection"),
            SinkClassification::OpenRedirect => write!(f, "Open Redirect"),
            SinkClassification::GenericInjection => write!(f, "Injection"),
            SinkClassification::Other(s) => write!(f, "{}", s),
        }
    }
}

// =============================================================================
// Strict Sink Validation
// =============================================================================
// These functions validate that a sink classification has proper evidence.
// Without strong evidence, sinks are downgraded to GenericInjection.

/// Validate SQL sink evidence for Go files
///
/// Returns strong evidence only if we can prove this is a real database/sql sink:
/// - File imports "database/sql" OR
/// - Callee is a known sql package method (Query, Exec, Prepare)
pub fn validate_go_sql_sink(file_content: &str, sink_call: &str) -> SinkEvidence {
    // Check for database/sql import
    let has_sql_import = file_content.contains("\"database/sql\"")
        || file_content.contains("\"github.com/jmoiron/sqlx\"")
        || file_content.contains("\"gorm.io/gorm\"")
        || file_content.contains("\"github.com/jinzhu/gorm\"");

    if !has_sql_import {
        return SinkEvidence::from_pattern(sink_call);
    }

    // Known SQL sink methods
    let sql_methods = [
        "Query",
        "QueryContext",
        "QueryRow",
        "QueryRowContext",
        "Exec",
        "ExecContext",
        "Prepare",
        "PrepareContext",
        "Raw", // gorm
    ];

    for method in &sql_methods {
        if sink_call.contains(method) {
            return SinkEvidence::from_import("database/sql");
        }
    }

    SinkEvidence::from_pattern(sink_call)
}

/// Validate XSS sink evidence for Go files
///
/// Returns strong evidence only if this is a real HTML context:
/// - File imports "html/template" and calls Execute
/// - Direct HTML string construction sent to response writer
pub fn validate_go_xss_sink(file_content: &str, sink_call: &str) -> SinkEvidence {
    // Check for html/template import (strong evidence)
    if file_content.contains("\"html/template\"")
        && (sink_call.contains("Execute") || sink_call.contains("ExecuteTemplate"))
    {
        return SinkEvidence::from_import("html/template");
    }

    // Check for text/template (potential XSS if used for HTML)
    if file_content.contains("\"text/template\"") && sink_call.contains("Execute") {
        return SinkEvidence::from_import("text/template (warning: no auto-escaping)");
    }

    // JSON serialization is NOT XSS
    if file_content.contains("\"encoding/json\"")
        && (sink_call.contains("Encode") || sink_call.contains("Marshal"))
    {
        // This is JSON, not HTML - no XSS risk
        return SinkEvidence::none();
    }

    // Logging/tracing is NOT XSS
    if sink_call.contains("log") || sink_call.contains("trace") || sink_call.contains("debug") {
        return SinkEvidence::none();
    }

    SinkEvidence::from_pattern(sink_call)
}

/// Apply strict sink validation based on language
///
/// Returns (validated_classification, evidence)
/// If evidence is weak, classification may be downgraded to GenericInjection
pub fn validate_sink_classification(
    classification: SinkClassification,
    language: Language,
    file_content: &str,
    sink_call: &str,
) -> (SinkClassification, SinkEvidence) {
    match language {
        Language::Go => {
            match &classification {
                SinkClassification::SqlInjection => {
                    let evidence = validate_go_sql_sink(file_content, sink_call);
                    if evidence.is_strong() {
                        (classification, evidence)
                    } else {
                        // Downgrade to generic injection
                        (SinkClassification::GenericInjection, evidence)
                    }
                }
                SinkClassification::CrossSiteScripting => {
                    let evidence = validate_go_xss_sink(file_content, sink_call);
                    if evidence.is_strong() {
                        (classification, evidence)
                    } else if matches!(evidence.kind, SinkEvidenceKind::None) {
                        // Not a real XSS sink (e.g., JSON, logging)
                        (
                            SinkClassification::Other("non-html-output".to_string()),
                            evidence,
                        )
                    } else {
                        (SinkClassification::GenericInjection, evidence)
                    }
                }
                _ => {
                    // For other sink types, use pattern evidence for now
                    (classification, SinkEvidence::from_pattern(sink_call))
                }
            }
        }
        _ => {
            // For other languages, use pattern evidence (TODO: add language-specific validation)
            (classification, SinkEvidence::from_pattern(sink_call))
        }
    }
}

/// A function definition in the call graph
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionDef {
    /// Name of the function
    pub name: String,
    /// File containing the function
    pub file: PathBuf,
    /// Line number of the definition
    pub line: usize,
    /// Whether this is an exported function
    pub is_exported: bool,
    /// Language of the file
    pub language: Language,
    /// Security classification based on function contents
    pub classification: FunctionClassification,
}

/// A call site in the code
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallSite {
    /// The function being called
    pub callee_name: String,
    /// File containing the call
    pub caller_file: PathBuf,
    /// Function containing the call (if known)
    pub caller_function: Option<String>,
    /// Line number of the call
    pub line: usize,
    /// The resolved target file (if known)
    pub resolved_target: Option<PathBuf>,
}

/// An edge in the call graph
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// The calling function
    pub caller: FunctionDef,
    /// The called function
    pub callee: FunctionDef,
    /// Call site information
    pub call_site: CallSite,
    /// Whether this is a cross-file call
    pub is_cross_file: bool,
}

/// A detected taint flow from source to sink
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// The source function (where tainted data enters)
    pub source: FunctionDef,
    /// The sink function (where dangerous operation occurs)
    pub sink: FunctionDef,
    /// Path of functions between source and sink
    pub path: Vec<FunctionDef>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
}

impl TaintFlow {
    /// Get the primary sink type (first one if multiple)
    pub fn sink_type(&self) -> Option<&SinkClassification> {
        self.sink.classification.sink_kinds.first()
    }

    /// Get the source type
    pub fn source_type(&self) -> Option<&SourceClassification> {
        self.source.classification.source_kind.as_ref()
    }

    /// Format the flow path for display
    pub fn format_path(&self) -> String {
        let mut parts = Vec::new();

        // Source
        let source_file = self
            .source
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");
        parts.push(format!(
            "{} ({}:{})",
            self.source.name, source_file, self.source.line
        ));

        // Intermediate path
        let mut last_file = &self.source.file;
        for func in &self.path {
            let file = func
                .file
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("?");

            if &func.file != last_file {
                parts.push(format!("[{}] {} ({}:{})", file, func.name, file, func.line));
            } else {
                parts.push(format!("{} ({}:{})", func.name, file, func.line));
            }
            last_file = &func.file;
        }

        // Sink
        let sink_file = self
            .sink
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");
        if &self.sink.file != last_file {
            parts.push(format!(
                "[{}] {} ({}:{})",
                sink_file, self.sink.name, sink_file, self.sink.line
            ));
        } else {
            parts.push(format!(
                "{} ({}:{})",
                self.sink.name, sink_file, self.sink.line
            ));
        }

        parts.join(" -> ")
    }
}

/// Calculate confidence for a taint flow
fn calculate_flow_confidence(source: &FunctionDef, sink: &FunctionDef) -> f32 {
    let mut confidence = 0.5; // Base confidence

    // Higher confidence for HTTP sources
    if matches!(
        source.classification.source_kind,
        Some(SourceClassification::HttpHandler) | Some(SourceClassification::HttpInput)
    ) {
        confidence += 0.2;
    }

    // Higher confidence for critical sinks
    let has_critical_sink = source.classification.sink_kinds.iter().any(|s| {
        matches!(
            s,
            SinkClassification::SqlInjection
                | SinkClassification::CommandInjection
                | SinkClassification::Deserialization
        )
    });
    if has_critical_sink {
        confidence += 0.2;
    }

    // Use classification confidence
    confidence += (source.classification.confidence + sink.classification.confidence) / 4.0;

    confidence.min(1.0)
}

use crate::flow::events::{EventBinding, EventRegistry, EventSite};

/// The complete call graph for a project
#[derive(Debug, Default, Clone)]
pub struct CallGraph {
    /// All function definitions indexed by (file, name)
    functions: HashMap<(PathBuf, String), FunctionDef>,
    /// Function definitions indexed by name only (for cross-file lookup)
    functions_by_name: HashMap<String, Vec<FunctionDef>>,
    /// Edges from caller to callees
    caller_to_callees: HashMap<(PathBuf, String), Vec<CallEdge>>,
    /// Edges from callee to callers (reverse index)
    callee_to_callers: HashMap<(PathBuf, String), Vec<CallEdge>>,
    /// All call sites
    call_sites: Vec<CallSite>,
    /// Unresolved calls (couldn't find target)
    unresolved_calls: Vec<CallSite>,
    /// Event bindings for event-driven data flow
    event_bindings: HashMap<String, EventBinding>,
}

impl CallGraph {
    /// Create a new empty call graph
    pub fn new() -> Self {
        Self::default()
    }

    /// Get all functions in the graph
    pub fn functions(&self) -> impl Iterator<Item = &FunctionDef> {
        self.functions.values()
    }

    /// Get a function by file and name
    pub fn get_function(&self, file: &Path, name: &str) -> Option<&FunctionDef> {
        self.functions.get(&(file.to_path_buf(), name.to_string()))
    }

    /// Get all functions with a given name (across all files)
    pub fn get_functions_by_name(&self, name: &str) -> &[FunctionDef] {
        self.functions_by_name
            .get(name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get all callers of a function
    pub fn callers_of(&self, file: &Path, name: &str) -> Vec<&CallEdge> {
        self.callee_to_callers
            .get(&(file.to_path_buf(), name.to_string()))
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get all callees of a function
    pub fn callees_of(&self, file: &Path, name: &str) -> Vec<&CallEdge> {
        self.caller_to_callees
            .get(&(file.to_path_buf(), name.to_string()))
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Check if a function is reachable from another
    pub fn is_reachable(
        &self,
        from_file: &Path,
        from_name: &str,
        to_file: &Path,
        to_name: &str,
    ) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![(from_file.to_path_buf(), from_name.to_string())];

        while let Some((file, name)) = stack.pop() {
            if file == to_file && name == to_name {
                return true;
            }

            if !visited.insert((file.clone(), name.clone())) {
                continue;
            }

            for edge in self.callees_of(&file, &name) {
                stack.push((edge.callee.file.clone(), edge.callee.name.clone()));
            }
        }

        false
    }

    /// Get all cross-file edges
    pub fn cross_file_edges(&self) -> Vec<&CallEdge> {
        self.caller_to_callees
            .values()
            .flatten()
            .filter(|e| e.is_cross_file)
            .collect()
    }

    /// Get all edges in the call graph
    pub fn all_edges(&self) -> Vec<&CallEdge> {
        self.caller_to_callees.values().flatten().collect()
    }

    /// Get all unresolved calls
    pub fn unresolved_calls(&self) -> &[CallSite] {
        &self.unresolved_calls
    }

    /// Get total number of functions
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Get total number of edges
    pub fn edge_count(&self) -> usize {
        self.caller_to_callees.values().map(|v| v.len()).sum()
    }

    // =========================================================================
    // Security Classification Queries
    // =========================================================================

    /// Get all functions classified as sources
    pub fn source_functions(&self) -> Vec<&FunctionDef> {
        self.functions
            .values()
            .filter(|f| f.classification.is_source)
            .collect()
    }

    /// Get all functions that contain sink calls
    pub fn sink_functions(&self) -> Vec<&FunctionDef> {
        self.functions
            .values()
            .filter(|f| f.classification.contains_sinks)
            .collect()
    }

    /// Get all functions that call sanitizers
    pub fn sanitizer_functions(&self) -> Vec<&FunctionDef> {
        self.functions
            .values()
            .filter(|f| f.classification.calls_sanitizers)
            .collect()
    }

    /// Check if there's a sanitizer on the path between two functions
    pub fn has_sanitizer_on_path(
        &self,
        from_file: &Path,
        from_name: &str,
        to_file: &Path,
        to_name: &str,
    ) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![(from_file.to_path_buf(), from_name.to_string())];

        while let Some((file, name)) = stack.pop() {
            if file == to_file && name == to_name {
                return false; // Reached target without sanitizer
            }

            if !visited.insert((file.clone(), name.clone())) {
                continue;
            }

            // Check if current function calls sanitizers
            if let Some(func) = self.get_function(&file, &name)
                && func.classification.calls_sanitizers
            {
                return true;
            }

            for edge in self.callees_of(&file, &name) {
                stack.push((edge.callee.file.clone(), edge.callee.name.clone()));
            }
        }

        false
    }

    /// Find all paths from sources to sinks with classifications
    pub fn find_taint_flows(&self) -> Vec<TaintFlow> {
        let sources = self.source_functions();
        let sinks = self.sink_functions();
        let mut flows = Vec::new();

        for source in &sources {
            for sink in &sinks {
                // Only report cross-file flows
                if source.file == sink.file {
                    continue;
                }

                // Check if there's a path from source to sink
                if let Some(path) =
                    self.find_path(&source.file, &source.name, &sink.file, &sink.name)
                {
                    // Check for sanitizers on path
                    let has_sanitizer = self.has_sanitizer_on_path(
                        &source.file,
                        &source.name,
                        &sink.file,
                        &sink.name,
                    );

                    if !has_sanitizer {
                        flows.push(TaintFlow {
                            source: (*source).clone(),
                            sink: (*sink).clone(),
                            path,
                            confidence: calculate_flow_confidence(source, sink),
                        });
                    }
                }
            }
        }

        flows
    }

    /// Find a path between two functions (BFS)
    fn find_path(
        &self,
        from_file: &Path,
        from_name: &str,
        to_file: &Path,
        to_name: &str,
    ) -> Option<Vec<FunctionDef>> {
        use std::collections::VecDeque;

        let mut visited = HashSet::new();
        let mut queue: VecDeque<(PathBuf, String, Vec<FunctionDef>)> = VecDeque::new();

        queue.push_back((from_file.to_path_buf(), from_name.to_string(), vec![]));
        visited.insert((from_file.to_path_buf(), from_name.to_string()));

        let max_depth = 15; // Limit search depth
        let mut depth = 0;
        let mut nodes_at_depth = 1;
        let mut nodes_next_depth = 0;

        while let Some((file, name, path)) = queue.pop_front() {
            if depth > max_depth {
                break;
            }

            if file == to_file && name == to_name {
                return Some(path);
            }

            for edge in self.callees_of(&file, &name) {
                let key = (edge.callee.file.clone(), edge.callee.name.clone());
                if !visited.contains(&key) {
                    visited.insert(key);
                    let mut new_path = path.clone();
                    new_path.push(edge.caller.clone());
                    queue.push_back((edge.callee.file.clone(), edge.callee.name.clone(), new_path));
                    nodes_next_depth += 1;
                }
            }

            nodes_at_depth -= 1;
            if nodes_at_depth == 0 {
                depth += 1;
                nodes_at_depth = nodes_next_depth;
                nodes_next_depth = 0;
            }
        }

        None
    }

    /// Update classifications for all functions using parsed files (parallel with Rayon)
    pub fn update_classifications(
        &mut self,
        classifier: &FunctionClassifier,
        parsed_files: &[rma_parser::ParsedFile],
    ) {
        // Classify all functions in all files in parallel using Rayon
        let all_classifications = classifier.classify_files_parallel(parsed_files);

        // Update function definitions with classifications
        for ((file, name), func_def) in self.functions.iter_mut() {
            if let Some(classification) = all_classifications.get(&(file.clone(), name.clone())) {
                func_def.classification = classification.clone();
            }
        }
    }

    // =========================================================================
    // Event Binding Queries
    // =========================================================================

    /// Get all listeners for an event
    pub fn listeners_of(&self, event_name: &str) -> Vec<&EventSite> {
        self.event_bindings
            .get(event_name)
            .map(|b| b.listen_sites.iter().collect())
            .unwrap_or_default()
    }

    /// Get all emitters for an event
    pub fn emitters_of(&self, event_name: &str) -> Vec<&EventSite> {
        self.event_bindings
            .get(event_name)
            .map(|b| b.emit_sites.iter().collect())
            .unwrap_or_default()
    }

    /// Get an event binding by name
    pub fn get_event_binding(&self, event_name: &str) -> Option<&EventBinding> {
        self.event_bindings.get(event_name)
    }

    /// Get all event names
    pub fn event_names(&self) -> impl Iterator<Item = &String> {
        self.event_bindings.keys()
    }

    /// Get all event bindings
    pub fn all_event_bindings(&self) -> impl Iterator<Item = &EventBinding> {
        self.event_bindings.values()
    }

    /// Check if an event has any emitters
    pub fn has_event_emitters(&self, event_name: &str) -> bool {
        self.event_bindings
            .get(event_name)
            .map(|b| !b.emit_sites.is_empty())
            .unwrap_or(false)
    }

    /// Check if an event has any listeners
    pub fn has_event_listeners(&self, event_name: &str) -> bool {
        self.event_bindings
            .get(event_name)
            .map(|b| !b.listen_sites.is_empty())
            .unwrap_or(false)
    }

    /// Add an event binding
    pub fn add_event_binding(&mut self, event_name: String, binding: EventBinding) {
        self.event_bindings.insert(event_name, binding);
    }

    /// Register an emit site for an event
    pub fn register_event_emit(&mut self, event_name: &str, site: EventSite) {
        self.event_bindings
            .entry(event_name.to_string())
            .or_insert_with(|| EventBinding::new(event_name.to_string()))
            .add_emit_site(site);
    }

    /// Register a listen site for an event
    pub fn register_event_listen(&mut self, event_name: &str, site: EventSite) {
        self.event_bindings
            .entry(event_name.to_string())
            .or_insert_with(|| EventBinding::new(event_name.to_string()))
            .add_listen_site(site);
    }

    /// Merge event registry into call graph
    pub fn merge_event_registry(&mut self, registry: EventRegistry) {
        for binding in registry.all_bindings() {
            let entry = self
                .event_bindings
                .entry(binding.event_name.clone())
                .or_insert_with(|| EventBinding::new(binding.event_name.clone()));

            for site in &binding.emit_sites {
                entry.add_emit_site(site.clone());
            }
            for site in &binding.listen_sites {
                entry.add_listen_site(site.clone());
            }
        }
    }
}

/// Builder for constructing a call graph from multiple files
#[derive(Debug, Default)]
pub struct CallGraphBuilder {
    /// Function definitions collected from files
    functions: HashMap<(PathBuf, String), FunctionDef>,
    /// Call sites collected from files
    call_sites: Vec<CallSite>,
    /// Import resolution information per file
    imports_by_file: HashMap<PathBuf, FileImports>,
}

impl CallGraphBuilder {
    /// Create a new call graph builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file's function definitions and call sites to the builder
    pub fn add_file(
        &mut self,
        file_path: &Path,
        language: Language,
        functions: Vec<(String, usize, bool)>, // (name, line, is_exported)
        calls: Vec<(String, usize, Option<String>)>, // (callee_name, line, caller_function)
        imports: FileImports,
    ) {
        // Add function definitions (with default classification - use add_classified_file for full classification)
        for (name, line, is_exported) in functions {
            let def = FunctionDef {
                name: name.clone(),
                file: file_path.to_path_buf(),
                line,
                is_exported,
                language,
                classification: FunctionClassification::default(),
            };
            self.functions.insert((file_path.to_path_buf(), name), def);
        }

        // Add call sites
        for (callee_name, line, caller_function) in calls {
            self.call_sites.push(CallSite {
                callee_name,
                caller_file: file_path.to_path_buf(),
                caller_function,
                line,
                resolved_target: None,
            });
        }

        // Store imports for resolution
        self.imports_by_file
            .insert(file_path.to_path_buf(), imports);
    }

    /// Build the complete call graph
    pub fn build(mut self) -> CallGraph {
        let mut graph = CallGraph {
            functions: self.functions.clone(),
            functions_by_name: HashMap::new(),
            caller_to_callees: HashMap::new(),
            callee_to_callers: HashMap::new(),
            call_sites: Vec::new(),
            unresolved_calls: Vec::new(),
            event_bindings: HashMap::new(),
        };

        // Build functions_by_name index
        for ((_, name), def) in &self.functions {
            graph
                .functions_by_name
                .entry(name.clone())
                .or_default()
                .push(def.clone());
        }

        // Resolve call sites to build edges
        let call_sites = std::mem::take(&mut self.call_sites);
        for mut call_site in call_sites {
            let resolved = self.resolve_call(&call_site);

            match resolved {
                Some(callee_def) => {
                    call_site.resolved_target = Some(callee_def.file.clone());

                    // Find or create caller function def
                    let caller_def = if let Some(ref caller_name) = call_site.caller_function {
                        self.functions
                            .get(&(call_site.caller_file.clone(), caller_name.clone()))
                            .cloned()
                    } else {
                        None
                    };

                    let caller_def = caller_def.unwrap_or_else(|| FunctionDef {
                        name: call_site
                            .caller_function
                            .clone()
                            .unwrap_or_else(|| "<module>".to_string()),
                        file: call_site.caller_file.clone(),
                        line: call_site.line,
                        is_exported: false,
                        language: Language::Unknown,
                        classification: FunctionClassification::default(),
                    });

                    let is_cross_file = caller_def.file != callee_def.file;

                    let edge = CallEdge {
                        caller: caller_def.clone(),
                        callee: callee_def.clone(),
                        call_site: call_site.clone(),
                        is_cross_file,
                    };

                    // Add to caller -> callees index
                    graph
                        .caller_to_callees
                        .entry((caller_def.file.clone(), caller_def.name.clone()))
                        .or_default()
                        .push(edge.clone());

                    // Add to callee -> callers index
                    graph
                        .callee_to_callers
                        .entry((callee_def.file.clone(), callee_def.name.clone()))
                        .or_default()
                        .push(edge);

                    graph.call_sites.push(call_site);
                }
                None => {
                    graph.unresolved_calls.push(call_site);
                }
            }
        }

        graph
    }

    /// Resolve a call site to its target function
    fn resolve_call(&self, call_site: &CallSite) -> Option<FunctionDef> {
        // First, check if it's a local function in the same file
        if let Some(def) = self
            .functions
            .get(&(call_site.caller_file.clone(), call_site.callee_name.clone()))
        {
            return Some(def.clone());
        }

        // Check imports to find the source file
        if let Some(imports) = self.imports_by_file.get(&call_site.caller_file) {
            for import in &imports.imports {
                if import.local_name == call_site.callee_name {
                    // Found an import matching the call
                    // Look up the function in the source file
                    if let Some(def) = self
                        .functions
                        .get(&(import.source_file.clone(), import.exported_name.clone()))
                    {
                        return Some(def.clone());
                    }
                }
            }
        }

        // Try to find any function with this name (less precise)
        if let Some(defs) = self
            .functions
            .iter()
            .filter(|((_, name), _)| name == &call_site.callee_name)
            .map(|(_, def)| def)
            .next()
        {
            return Some(defs.clone());
        }

        None
    }
}

/// Extract function definitions from a parsed file
pub fn extract_function_definitions(
    tree: &tree_sitter::Tree,
    source: &[u8],
    language: Language,
) -> Vec<(String, usize, bool)> {
    let mut functions = Vec::new();
    let root = tree.root_node();

    extract_functions_recursive(root, source, language, &mut functions);

    functions
}

fn extract_functions_recursive(
    node: tree_sitter::Node,
    source: &[u8],
    language: Language,
    functions: &mut Vec<(String, usize, bool)>,
) {
    let is_function = match language {
        Language::JavaScript | Language::TypeScript => matches!(
            node.kind(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ),
        Language::Python => node.kind() == "function_definition",
        Language::Rust => node.kind() == "function_item",
        Language::Go => {
            matches!(node.kind(), "function_declaration" | "method_declaration")
        }
        Language::Java => node.kind() == "method_declaration",
        _ => false,
    };

    if is_function && let Some(name) = extract_function_name(node, source, language) {
        let line = node.start_position().row + 1;
        let is_exported = is_function_exported(node, source, language);
        functions.push((name, line, is_exported));
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_functions_recursive(child, source, language, functions);
    }
}

fn extract_function_name(
    node: tree_sitter::Node,
    source: &[u8],
    language: Language,
) -> Option<String> {
    match language {
        Language::JavaScript | Language::TypeScript => {
            // Try name field first
            if let Some(name_node) = node.child_by_field_name("name") {
                return name_node.utf8_text(source).ok().map(|s| s.to_string());
            }
            // For arrow functions in assignments, check parent
            if node.kind() == "arrow_function"
                && let Some(parent) = node.parent()
                && parent.kind() == "variable_declarator"
                && let Some(name_node) = parent.child_by_field_name("name")
            {
                return name_node.utf8_text(source).ok().map(|s| s.to_string());
            }
            None
        }
        Language::Python | Language::Rust | Language::Go | Language::Java => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn is_function_exported(node: tree_sitter::Node, source: &[u8], language: Language) -> bool {
    match language {
        Language::JavaScript | Language::TypeScript => {
            // Check if function is in an export statement
            if let Some(parent) = node.parent()
                && parent.kind() == "export_statement"
            {
                return true;
            }
            false
        }
        Language::Python => {
            // In Python, functions not starting with _ are exported
            if let Some(name_node) = node.child_by_field_name("name")
                && let Ok(name) = name_node.utf8_text(source)
            {
                return !name.starts_with('_');
            }
            false
        }
        Language::Rust => {
            // Check for pub visibility
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "visibility_modifier"
                    && let Ok(text) = child.utf8_text(source)
                {
                    return text.starts_with("pub");
                }
            }
            false
        }
        Language::Go => {
            // Go exports are uppercase
            if let Some(name_node) = node.child_by_field_name("name")
                && let Ok(name) = name_node.utf8_text(source)
            {
                return name.chars().next().is_some_and(|c| c.is_uppercase());
            }
            false
        }
        Language::Java => {
            // Check for public modifier
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "modifiers"
                    && let Ok(text) = child.utf8_text(source)
                {
                    return text.contains("public");
                }
            }
            false
        }
        _ => false,
    }
}

/// Extract function calls from a parsed file
pub fn extract_function_calls(
    tree: &tree_sitter::Tree,
    source: &[u8],
    language: Language,
) -> Vec<(String, usize, Option<String>)> {
    let mut calls = Vec::new();
    let root = tree.root_node();

    extract_calls_recursive(root, source, language, &mut calls, None);

    calls
}

fn extract_calls_recursive(
    node: tree_sitter::Node,
    source: &[u8],
    language: Language,
    calls: &mut Vec<(String, usize, Option<String>)>,
    current_function: Option<String>,
) {
    // Track current function context
    let new_function = match language {
        Language::JavaScript | Language::TypeScript => {
            if matches!(
                node.kind(),
                "function_declaration" | "function_expression" | "method_definition"
            ) {
                extract_function_name(node, source, language)
            } else {
                None
            }
        }
        Language::Python => {
            if node.kind() == "function_definition" {
                extract_function_name(node, source, language)
            } else {
                None
            }
        }
        Language::Rust => {
            if node.kind() == "function_item" {
                extract_function_name(node, source, language)
            } else {
                None
            }
        }
        Language::Go => {
            if matches!(node.kind(), "function_declaration" | "method_declaration") {
                extract_function_name(node, source, language)
            } else {
                None
            }
        }
        Language::Java => {
            if node.kind() == "method_declaration" {
                extract_function_name(node, source, language)
            } else {
                None
            }
        }
        _ => None,
    };

    let func_context = new_function.or(current_function);

    // Check for call expressions
    let is_call = matches!(
        node.kind(),
        "call_expression" | "member_expression" | "method_invocation"
    );

    if is_call && let Some(callee_name) = extract_callee_name(node, source, language) {
        let line = node.start_position().row + 1;
        calls.push((callee_name, line, func_context.clone()));
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_calls_recursive(child, source, language, calls, func_context.clone());
    }
}

fn extract_callee_name(
    node: tree_sitter::Node,
    source: &[u8],
    language: Language,
) -> Option<String> {
    match language {
        Language::JavaScript | Language::TypeScript => {
            if let Some(func_node) = node.child_by_field_name("function") {
                match func_node.kind() {
                    "identifier" => {
                        return func_node.utf8_text(source).ok().map(|s| s.to_string());
                    }
                    "member_expression" => {
                        // Get the property name (method being called)
                        if let Some(prop) = func_node.child_by_field_name("property") {
                            return prop.utf8_text(source).ok().map(|s| s.to_string());
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        Language::Python => {
            if let Some(func_node) = node.child_by_field_name("function") {
                match func_node.kind() {
                    "identifier" => {
                        return func_node.utf8_text(source).ok().map(|s| s.to_string());
                    }
                    "attribute" => {
                        if let Some(attr) = func_node.child_by_field_name("attribute") {
                            return attr.utf8_text(source).ok().map(|s| s.to_string());
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        Language::Rust => {
            if let Some(func_node) = node.child_by_field_name("function") {
                match func_node.kind() {
                    "identifier" => {
                        return func_node.utf8_text(source).ok().map(|s| s.to_string());
                    }
                    "scoped_identifier" | "field_expression" => {
                        // Get the last identifier in the path
                        if let Some(name) = func_node.child_by_field_name("name") {
                            return name.utf8_text(source).ok().map(|s| s.to_string());
                        }
                        // Try field
                        if let Some(field) = func_node.child_by_field_name("field") {
                            return field.utf8_text(source).ok().map(|s| s.to_string());
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        Language::Go | Language::Java => {
            // Get the function/method name
            if let Some(name_node) = node.child_by_field_name("name") {
                return name_node.utf8_text(source).ok().map(|s| s.to_string());
            }
            if let Some(func_node) = node.child_by_field_name("function")
                && func_node.kind() == "identifier"
            {
                return func_node.utf8_text(source).ok().map(|s| s.to_string());
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::ResolvedImport;

    #[test]
    fn test_call_graph_builder() {
        let mut builder = CallGraphBuilder::new();

        // Add file1 with a function
        builder.add_file(
            Path::new("/project/src/utils.js"),
            Language::JavaScript,
            vec![("sanitize".to_string(), 1, true)],
            vec![],
            FileImports::default(),
        );

        // Add file2 that calls the function
        let mut imports = FileImports::default();
        imports.imports.push(ResolvedImport {
            local_name: "sanitize".to_string(),
            source_file: PathBuf::from("/project/src/utils.js"),
            exported_name: "sanitize".to_string(),
            kind: crate::imports::ImportKind::Named,
            specifier: "./utils".to_string(),
            line: 1,
        });

        builder.add_file(
            Path::new("/project/src/handler.js"),
            Language::JavaScript,
            vec![("handleRequest".to_string(), 5, true)],
            vec![(
                "sanitize".to_string(),
                10,
                Some("handleRequest".to_string()),
            )],
            imports,
        );

        let graph = builder.build();

        // Check that edge was created
        assert_eq!(graph.function_count(), 2);
        assert_eq!(graph.edge_count(), 1);

        let edges = graph.cross_file_edges();
        assert_eq!(edges.len(), 1);
        assert!(edges[0].is_cross_file);
    }

    #[test]
    fn test_reachability() {
        let mut builder = CallGraphBuilder::new();

        // A -> B -> C
        builder.add_file(
            Path::new("/a.js"),
            Language::JavaScript,
            vec![("funcA".to_string(), 1, true)],
            vec![("funcB".to_string(), 2, Some("funcA".to_string()))],
            FileImports::default(),
        );

        builder.add_file(
            Path::new("/b.js"),
            Language::JavaScript,
            vec![("funcB".to_string(), 1, true)],
            vec![("funcC".to_string(), 2, Some("funcB".to_string()))],
            FileImports::default(),
        );

        builder.add_file(
            Path::new("/c.js"),
            Language::JavaScript,
            vec![("funcC".to_string(), 1, true)],
            vec![],
            FileImports::default(),
        );

        let graph = builder.build();

        // funcA can reach funcC through funcB
        assert!(graph.is_reachable(Path::new("/a.js"), "funcA", Path::new("/c.js"), "funcC"));

        // funcC cannot reach funcA (no reverse edge)
        assert!(!graph.is_reachable(Path::new("/c.js"), "funcC", Path::new("/a.js"), "funcA"));
    }
}
