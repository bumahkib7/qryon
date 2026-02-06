//! Project-Level Analysis Coordinator
//!
//! Orchestrates multi-file analysis by:
//! 1. Parsing all files in parallel
//! 2. Extracting imports and building a dependency graph
//! 3. Running cross-file analysis (call graph, taint tracking)
//! 4. Aggregating results
//!
//! # Usage
//!
//! ```ignore
//! let coordinator = ProjectAnalyzer::new(config);
//! let result = coordinator.analyze_project(Path::new("./my-project"))?;
//!
//! println!("Files analyzed: {}", result.files_analyzed);
//! println!("Cross-file taint flows: {}", result.cross_file_taints.len());
//! ```

use crate::cache::AnalysisCache;
use crate::callgraph::{
    CallGraph, CallGraphBuilder, FunctionClassifier, SinkEvidence, extract_function_calls,
    extract_function_definitions, validate_sink_classification,
};
use crate::flow::sink_args::{
    SinkVerdict as ArgSinkVerdict, analyze_rust_command, evaluate_command_sink,
};
use crate::imports::{FileImports, extract_file_imports};
use crate::knowledge::SinkContext;
use crate::{AnalysisSummary, AnalyzerEngine, FileAnalysis};
use anyhow::Result;
use rayon::prelude::*;
use rma_common::{RmaConfig, Severity};
use rma_parser::{ParsedFile, ParserEngine};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info, instrument, warn};

/// Result type for cross-file analysis: (call graph, dependency map, cross-file taints)
type CrossFileAnalysisResult = (
    Option<CallGraph>,
    HashMap<PathBuf, Vec<PathBuf>>,
    Vec<CrossFileTaint>,
);

/// Results from project-wide analysis
#[derive(Debug, Default)]
pub struct ProjectAnalysisResult {
    /// Number of files analyzed
    pub files_analyzed: usize,
    /// Per-file analysis results
    pub file_results: Vec<FileAnalysis>,
    /// Cross-file taint flows detected
    pub cross_file_taints: Vec<CrossFileTaint>,
    /// The call graph for the project
    pub call_graph: Option<CallGraph>,
    /// Import graph (file dependencies)
    pub import_graph: HashMap<PathBuf, Vec<PathBuf>>,
    /// Analysis summary
    pub summary: AnalysisSummary,
    /// Analysis duration in milliseconds
    pub duration_ms: u64,
}

/// Confidence level for a taint flow detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintConfidence {
    /// Direct call chain, no dynamic dispatch, known APIs
    High,
    /// Some uncertainty (reflection, callbacks, dynamic dispatch)
    Medium,
    /// Heuristic match, possible false positive
    Low,
}

impl std::fmt::Display for TaintConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaintConfidence::High => write!(f, "High"),
            TaintConfidence::Medium => write!(f, "Medium"),
            TaintConfidence::Low => write!(f, "Low"),
        }
    }
}

/// Type of taint sink (vulnerability category)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SinkType {
    /// SQL injection (sql.execute, jdbc.query, etc.)
    SqlInjection,
    /// Command injection (cmd.exec, subprocess, etc.)
    CommandInjection,
    /// Path traversal (file operations with user input)
    PathTraversal,
    /// XSS (response.write, innerHTML, etc.)
    CrossSiteScripting,
    /// LDAP injection
    LdapInjection,
    /// Deserialization (readObject, JSON.parse of untrusted, etc.)
    Deserialization,
    /// Template injection (SSTI)
    TemplateInjection,
    /// Generic injection - downgraded from specific type due to weak evidence
    GenericInjection,
    /// Other/generic dangerous operation
    Other(String),
}

impl std::fmt::Display for SinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkType::SqlInjection => write!(f, "SQL Injection"),
            SinkType::CommandInjection => write!(f, "Command Injection"),
            SinkType::PathTraversal => write!(f, "Path Traversal"),
            SinkType::CrossSiteScripting => write!(f, "XSS"),
            SinkType::LdapInjection => write!(f, "LDAP Injection"),
            SinkType::Deserialization => write!(f, "Deserialization"),
            SinkType::TemplateInjection => write!(f, "Template Injection"),
            SinkType::GenericInjection => write!(f, "Generic Injection"),
            SinkType::Other(s) => write!(f, "{}", s),
        }
    }
}

impl SinkType {
    /// Get the default SinkContext for this sink type.
    /// This provides a reasonable default when AST-level context inference isn't available.
    pub fn default_context(&self) -> SinkContext {
        match self {
            SinkType::SqlInjection => SinkContext::Sql,
            SinkType::CommandInjection => SinkContext::Command,
            SinkType::PathTraversal => SinkContext::FilePath, // File path context for CWE-22
            SinkType::CrossSiteScripting => SinkContext::HtmlRaw, // Conservative default
            SinkType::LdapInjection => SinkContext::Unknown,
            SinkType::Deserialization => SinkContext::Unknown,
            SinkType::TemplateInjection => SinkContext::Template,
            SinkType::GenericInjection => SinkContext::Unknown, // Downgraded - context unclear
            SinkType::Other(_) => SinkContext::Unknown,
        }
    }
}

/// Type of taint source
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// HTTP request handler (doGet, doPost, handler, etc.)
    HttpHandler,
    /// HTTP parameter access (getParameter, req.query, etc.)
    HttpParameter,
    /// File/stream input
    FileInput,
    /// Environment variable
    EnvironmentVariable,
    /// Database result (can be tainted if DB has user content)
    DatabaseResult,
    /// Other/generic data source
    Other(String),
}

impl std::fmt::Display for SourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceType::HttpHandler => write!(f, "HTTP Handler"),
            SourceType::HttpParameter => write!(f, "HTTP Parameter"),
            SourceType::FileInput => write!(f, "File Input"),
            SourceType::EnvironmentVariable => write!(f, "Environment Variable"),
            SourceType::DatabaseResult => write!(f, "Database Result"),
            SourceType::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Evidence type for cross-language data flow boundaries
///
/// Cross-language flows are only valid if there's explicit boundary evidence.
/// Without bridge evidence, cross-language edges should be filtered out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeType {
    /// Same language - no bridge needed
    SameLanguage,
    /// HTTP boundary: client fetch → server endpoint
    Http,
    /// File artifact: one language writes, another reads
    File,
    /// Template rendering: server injects data into HTML/JS
    Template,
    /// Shared database: writer → reader
    Database,
    /// Message queue / event bus
    MessageQueue,
    /// No bridge evidence found (flow should be filtered in strict mode)
    None,
}

impl std::fmt::Display for BridgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeType::SameLanguage => write!(f, "same-language"),
            BridgeType::Http => write!(f, "HTTP"),
            BridgeType::File => write!(f, "file"),
            BridgeType::Template => write!(f, "template"),
            BridgeType::Database => write!(f, "database"),
            BridgeType::MessageQueue => write!(f, "message-queue"),
            BridgeType::None => write!(f, "none"),
        }
    }
}

/// Reachability classification for findings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    /// Source is real external input in production code
    ProdReachable,
    /// Source comes from test/benchmark files only
    TestOnly,
    /// Source reachability is unknown/internal
    Unknown,
}

impl std::fmt::Display for Reachability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reachability::ProdReachable => write!(f, "prod"),
            Reachability::TestOnly => write!(f, "test-only"),
            Reachability::Unknown => write!(f, "unknown"),
        }
    }
}

/// A taint flow that crosses file boundaries
#[derive(Debug, Clone)]
pub struct CrossFileTaint {
    /// Source of the taint (file, function, line)
    pub source: TaintLocation,
    /// Sink where tainted data arrives
    pub sink: TaintLocation,
    /// Path of functions the taint flows through (with file boundaries shown)
    pub path: Vec<TaintLocation>,
    /// Severity of the issue
    pub severity: Severity,
    /// Confidence level of the detection
    pub confidence: TaintConfidence,
    /// Type of source (HTTP handler, parameter, etc.)
    pub source_type: SourceType,
    /// Type of sink (SQL, Command, XSS, etc.)
    pub sink_type: SinkType,
    /// Specific security context at the sink site (granular context for sanitization)
    pub sink_context: SinkContext,
    /// Description of the vulnerability
    pub description: String,
    /// Role that is tainted at the sink (e.g., Program, ShellString, ArgList)
    pub sink_role: Option<String>,
    /// Argument index that is tainted
    pub sink_arg_index: Option<usize>,
    /// Actual line of the sink callsite (may differ from function start line)
    pub sink_callsite_line: Option<usize>,
    /// Bridge type for cross-language flows (None = no evidence, should filter)
    pub bridge_type: BridgeType,
    /// Reachability: is this finding from production code or test-only?
    pub reachability: Reachability,
    /// Evidence for sink classification (strong evidence = higher confidence)
    pub sink_evidence: SinkEvidence,
}

impl CrossFileTaint {
    /// Format the flow path as a string showing file boundaries
    /// e.g., "handleRequest (A.java:10) -> process (A.java:25) -> [B.java] execute (B.java:42)"
    pub fn format_path(&self) -> String {
        let mut parts = Vec::new();

        // Start with source
        let source_filename = self
            .source
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");
        parts.push(format!(
            "{} ({}:{})",
            self.source.function, source_filename, self.source.line
        ));
        let mut last_file: Option<&PathBuf> = Some(&self.source.file);

        // Add intermediate path with file boundary markers
        for loc in &self.path {
            let filename = loc.file.file_name().and_then(|f| f.to_str()).unwrap_or("?");

            if last_file.map(|f| f != &loc.file).unwrap_or(true) {
                // File boundary crossed - highlight it
                parts.push(format!(
                    "[{}] {} ({}:{})",
                    filename, loc.function, filename, loc.line
                ));
            } else {
                parts.push(format!("{} ({}:{})", loc.function, filename, loc.line));
            }
            last_file = Some(&loc.file);
        }

        // End with sink
        let sink_filename = self
            .sink
            .file
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("?");

        if last_file.map(|f| f != &self.sink.file).unwrap_or(true) {
            // File boundary crossed - highlight it
            parts.push(format!(
                "[{}] {} ({}:{})",
                sink_filename, self.sink.function, sink_filename, self.sink.line
            ));
        } else {
            parts.push(format!(
                "{} ({}:{})",
                self.sink.function, sink_filename, self.sink.line
            ));
        }

        parts.join(" -> ")
    }

    /// Get a fingerprint for deduplication (source + sink + type)
    pub fn fingerprint(&self) -> String {
        format!(
            "{}:{}->{}:{}:{}",
            self.source.function,
            self.source_type,
            self.sink.function,
            self.sink_type,
            self.severity
        )
    }
}

/// A location in the taint flow
#[derive(Debug, Clone)]
pub struct TaintLocation {
    /// File path
    pub file: PathBuf,
    /// Function name
    pub function: String,
    /// Line number
    pub line: usize,
    /// Variable or expression name
    pub name: String,
}

/// Project analyzer that coordinates multi-file analysis
pub struct ProjectAnalyzer {
    config: std::sync::Arc<RmaConfig>,
    parser: ParserEngine,
    analyzer: AnalyzerEngine,
    /// Enable cross-file analysis
    cross_file_enabled: bool,
    /// Enable parallel processing
    parallel_enabled: bool,
    /// Enable analysis caching
    cache_enabled: bool,
}

impl ProjectAnalyzer {
    /// Create a new project analyzer
    pub fn new(config: RmaConfig) -> Self {
        let parser = ParserEngine::new(config.clone());
        let analyzer = AnalyzerEngine::new(config.clone());

        Self {
            config: std::sync::Arc::new(config),
            parser,
            analyzer,
            cross_file_enabled: false,
            parallel_enabled: true,
            cache_enabled: false,
        }
    }

    /// Enable cross-file analysis
    pub fn with_cross_file(mut self, enabled: bool) -> Self {
        self.cross_file_enabled = enabled;
        self
    }

    /// Enable/disable parallel processing
    pub fn with_parallel(mut self, enabled: bool) -> Self {
        self.parallel_enabled = enabled;
        self
    }

    /// Enable/disable analysis caching
    pub fn with_cache(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    /// Analyze a project directory
    #[instrument(skip(self), fields(path = %path.display()))]
    pub fn analyze_project(&self, path: &Path) -> Result<ProjectAnalysisResult> {
        let start = Instant::now();
        info!("Starting project analysis for {}", path.display());

        // Step 1: Discover files
        let files = discover_files(path, &self.config)?;
        info!("Discovered {} source files", files.len());

        if files.is_empty() {
            return Ok(ProjectAnalysisResult::default());
        }

        // Create cache if enabled
        let mut cache = if self.cache_enabled {
            AnalysisCache::new(path)
        } else {
            AnalysisCache::disabled()
        };

        // Step 2: Parse all files in parallel, collecting content and mtime for cache
        let file_data: Vec<(PathBuf, String, std::time::SystemTime)> = if self.parallel_enabled {
            files
                .par_iter()
                .filter_map(|f| match std::fs::read_to_string(f) {
                    Ok(content) => {
                        let mtime = std::fs::metadata(f)
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                        Some((f.clone(), content, mtime))
                    }
                    Err(e) => {
                        warn!("Failed to read {}: {}", f.display(), e);
                        None
                    }
                })
                .collect()
        } else {
            files
                .iter()
                .filter_map(|f| match std::fs::read_to_string(f) {
                    Ok(content) => {
                        let mtime = std::fs::metadata(f)
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                        Some((f.clone(), content, mtime))
                    }
                    Err(e) => {
                        warn!("Failed to read {}: {}", f.display(), e);
                        None
                    }
                })
                .collect()
        };

        // Partition files: those needing analysis vs those with cached results
        let mut files_to_analyze = Vec::new();
        let mut cached_results = Vec::new();

        for (path, content, mtime) in &file_data {
            if cache.needs_analysis(path, content, *mtime) {
                files_to_analyze.push((path.clone(), content.clone(), *mtime));
            } else {
                // Try to load cached analysis
                if let Some(analysis) = cache.load_analysis(path, content) {
                    cached_results.push(analysis);
                } else {
                    // Cache entry exists but no results file - need to re-analyze
                    files_to_analyze.push((path.clone(), content.clone(), *mtime));
                }
            }
        }

        let cached_count = cached_results.len();
        if cached_count > 0 {
            info!(
                "Loaded {} cached results, analyzing {} files",
                cached_count,
                files_to_analyze.len()
            );
        }

        // Parse files that need analysis
        let parsed_files: Vec<ParsedFile> = if self.parallel_enabled {
            files_to_analyze
                .par_iter()
                .filter_map(|(path, content, _)| self.parser.parse_file(path, content).ok())
                .collect()
        } else {
            files_to_analyze
                .iter()
                .filter_map(|(path, content, _)| self.parser.parse_file(path, content).ok())
                .collect()
        };

        info!("Parsed {} files successfully", parsed_files.len());

        // Step 3: Run per-file analysis on new files
        let (mut file_results, _) = self.analyzer.analyze_files(&parsed_files)?;

        // Save fresh analysis results to cache and mark as analyzed
        for result in &file_results {
            if let Some((path, content, mtime)) = files_to_analyze
                .iter()
                .find(|(p, _, _)| p.to_string_lossy() == result.path)
            {
                let hash = crate::cache::hash_content(content);
                if let Err(e) = cache.save_analysis(path, hash, result) {
                    debug!("Failed to cache analysis for {}: {}", path.display(), e);
                }
                cache.mark_analyzed(path.clone(), content, *mtime);
            }
        }

        // Combine cached and fresh results
        file_results.extend(cached_results);

        // Recalculate summary with all results
        let summary = crate::AnalysisSummary {
            files_analyzed: file_results.len(),
            total_findings: file_results.iter().map(|r| r.findings.len()).sum(),
            critical_count: file_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            error_count: file_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Error)
                .count(),
            warning_count: file_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Warning)
                .count(),
            info_count: file_results
                .iter()
                .flat_map(|r| r.findings.iter())
                .filter(|f| f.severity == Severity::Info)
                .count(),
            total_loc: file_results.iter().map(|r| r.metrics.lines_of_code).sum(),
            total_complexity: file_results
                .iter()
                .map(|r| r.metrics.cyclomatic_complexity)
                .sum(),
        };

        // Step 4: Cross-file analysis (if enabled)
        let (call_graph, import_graph, cross_file_taints) = if self.cross_file_enabled {
            self.run_cross_file_analysis(&parsed_files, path)?
        } else {
            (None, HashMap::new(), Vec::new())
        };

        // Save cache to disk
        if let Err(e) = cache.save() {
            warn!("Failed to save analysis cache: {}", e);
        }

        let duration = start.elapsed();
        info!(
            "Project analysis complete in {:?}: {} files, {} findings",
            duration,
            file_results.len(),
            summary.total_findings
        );

        Ok(ProjectAnalysisResult {
            files_analyzed: file_results.len(),
            file_results,
            cross_file_taints,
            call_graph,
            import_graph,
            summary,
            duration_ms: duration.as_millis() as u64,
        })
    }

    /// Run cross-file analysis
    fn run_cross_file_analysis(
        &self,
        parsed_files: &[ParsedFile],
        project_root: &Path,
    ) -> Result<CrossFileAnalysisResult> {
        info!("Running cross-file analysis...");

        // Step 1: Extract imports from all files
        let file_imports: HashMap<PathBuf, FileImports> = if self.parallel_enabled {
            parsed_files
                .par_iter()
                .map(|parsed| {
                    let imports = extract_file_imports(
                        &parsed.tree,
                        parsed.content.as_bytes(),
                        &parsed.path,
                        parsed.language,
                        project_root,
                    );
                    (parsed.path.clone(), imports)
                })
                .collect()
        } else {
            parsed_files
                .iter()
                .map(|parsed| {
                    let imports = extract_file_imports(
                        &parsed.tree,
                        parsed.content.as_bytes(),
                        &parsed.path,
                        parsed.language,
                        project_root,
                    );
                    (parsed.path.clone(), imports)
                })
                .collect()
        };

        // Step 2: Build import graph
        let import_graph = build_import_graph(&file_imports);
        debug!("Built import graph with {} nodes", import_graph.len());

        // Step 3: Build call graph (parallel extraction with Rayon)
        // Extract function definitions and calls in parallel
        let file_data: Vec<_> = if self.parallel_enabled {
            parsed_files
                .par_iter()
                .map(|parsed| {
                    let source = parsed.content.as_bytes();
                    let functions =
                        extract_function_definitions(&parsed.tree, source, parsed.language);
                    let calls = extract_function_calls(&parsed.tree, source, parsed.language);
                    let imports = file_imports.get(&parsed.path).cloned().unwrap_or_default();
                    (
                        parsed.path.clone(),
                        parsed.language,
                        functions,
                        calls,
                        imports,
                    )
                })
                .collect()
        } else {
            parsed_files
                .iter()
                .map(|parsed| {
                    let source = parsed.content.as_bytes();
                    let functions =
                        extract_function_definitions(&parsed.tree, source, parsed.language);
                    let calls = extract_function_calls(&parsed.tree, source, parsed.language);
                    let imports = file_imports.get(&parsed.path).cloned().unwrap_or_default();
                    (
                        parsed.path.clone(),
                        parsed.language,
                        functions,
                        calls,
                        imports,
                    )
                })
                .collect()
        };

        // Add all extracted data to the builder
        let mut call_graph_builder = CallGraphBuilder::new();
        for (path, language, functions, calls, imports) in file_data {
            call_graph_builder.add_file(&path, language, functions, calls, imports);
        }

        let mut call_graph = call_graph_builder.build();
        info!(
            "Built call graph: {} functions, {} edges",
            call_graph.function_count(),
            call_graph.edge_count()
        );

        // Step 4: Classify functions using knowledge-based AST analysis (parallel with Rayon)
        // Pre-build knowledge for all languages in the project for maximum parallelism
        let languages: Vec<_> = parsed_files
            .iter()
            .map(|f| f.language)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let classifier = FunctionClassifier::with_languages(&languages);
        call_graph.update_classifications(&classifier, parsed_files);

        let sources = call_graph.source_functions();
        let sinks = call_graph.sink_functions();
        info!(
            "Classified functions: {} sources, {} sinks",
            sources.len(),
            sinks.len()
        );

        // Step 5: Detect cross-file taint flows using both classification and reachability
        let cross_file_taints = detect_cross_file_taints(&call_graph, parsed_files);
        if !cross_file_taints.is_empty() {
            info!(
                "Detected {} cross-file taint flows",
                cross_file_taints.len()
            );
        }

        Ok((Some(call_graph), import_graph, cross_file_taints))
    }

    /// Get the analyzer engine
    pub fn analyzer(&self) -> &AnalyzerEngine {
        &self.analyzer
    }

    /// Get the parser engine
    pub fn parser(&self) -> &ParserEngine {
        &self.parser
    }
}

/// Discover source files in a directory
fn discover_files(path: &Path, config: &RmaConfig) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    discover_files_recursive(path, config, &mut files)?;
    Ok(files)
}

fn discover_files_recursive(
    path: &Path,
    config: &RmaConfig,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_file() {
        if should_include_file(path, config) {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }

    if path.is_dir() {
        // Skip excluded directories
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let excluded_dirs = [
                "node_modules",
                ".git",
                "target",
                "build",
                "dist",
                "__pycache__",
                ".venv",
                "venv",
                "vendor",
            ];
            if excluded_dirs.contains(&name) || name.starts_with('.') {
                return Ok(());
            }
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            discover_files_recursive(&entry.path(), config, files)?;
        }
    }

    Ok(())
}

fn should_include_file(path: &Path, _config: &RmaConfig) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    let supported_extensions = [
        "rs", "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "go", "java", "kt", "kts", "scala",
        "sc", "rb", "php", "cs", "swift", "sh", "bash", "ex", "exs", "ml", "mli", "sol", "tf",
        "hcl", "yaml", "yml", "json",
    ];

    supported_extensions.contains(&ext)
}

/// Build an import graph from file imports
fn build_import_graph(
    file_imports: &HashMap<PathBuf, FileImports>,
) -> HashMap<PathBuf, Vec<PathBuf>> {
    let mut graph = HashMap::new();

    for (file, imports) in file_imports {
        let deps: Vec<PathBuf> = imports
            .imports
            .iter()
            .map(|imp| imp.source_file.clone())
            .collect();

        graph.insert(file.clone(), deps);
    }

    graph
}

// =============================================================================
// Cross-File Taint Detection via Reachability Analysis
// =============================================================================
//
// Strategy: Instead of relying on interprocedural summaries (which don't work
// well across languages), we use a graph-based approach:
//
// 1. Identify SOURCE functions: HTTP handlers, user input handlers, etc.
// 2. Identify SINK functions: SQL execution, command execution, file ops, etc.
// 3. Use the CallGraph to find paths from sources to sinks
// 4. Report these paths as potential taint flows
//
// This approach works because:
// - The CallGraph is already built with 176k+ edges
// - We can do BFS/DFS reachability queries efficiently
// - Uses the Knowledge system for framework-aware source/sink detection

// NOTE: All classification is now done in callgraph/classifier.rs using the knowledge system.
// FunctionDef.classification is populated by FunctionClassifier.classify_function()
// which uses AST analysis and the knowledge base (SourceDef, SinkDef) instead of pattern matching.

/// Convert SinkClassification from callgraph to SinkType for reporting
fn convert_sink_classification(sink: &crate::callgraph::SinkClassification) -> SinkType {
    use crate::callgraph::SinkClassification;
    match sink {
        SinkClassification::SqlInjection => SinkType::SqlInjection,
        SinkClassification::CommandInjection => SinkType::CommandInjection,
        SinkClassification::PathTraversal => SinkType::PathTraversal,
        SinkClassification::CrossSiteScripting => SinkType::CrossSiteScripting,
        SinkClassification::Deserialization => SinkType::Deserialization,
        SinkClassification::LdapInjection => SinkType::LdapInjection,
        SinkClassification::TemplateInjection => SinkType::TemplateInjection,
        SinkClassification::GenericInjection => SinkType::GenericInjection,
        SinkClassification::XmlInjection => SinkType::Other("XML Injection".to_string()),
        SinkClassification::LogInjection => SinkType::Other("Log Injection".to_string()),
        SinkClassification::OpenRedirect => SinkType::Other("Open Redirect".to_string()),
        SinkClassification::Other(s) => SinkType::Other(s.clone()),
    }
}

/// Convert SourceClassification from callgraph to SourceType for reporting
fn convert_source_classification(source: &crate::callgraph::SourceClassification) -> SourceType {
    use crate::callgraph::SourceClassification;
    match source {
        SourceClassification::HttpHandler => SourceType::HttpHandler,
        SourceClassification::HttpInput => SourceType::HttpParameter,
        SourceClassification::FileInput => SourceType::FileInput,
        SourceClassification::EnvironmentVariable => SourceType::EnvironmentVariable,
        SourceClassification::DatabaseResult => SourceType::DatabaseResult,
        SourceClassification::MessageInput => SourceType::Other("Message Queue".to_string()),
        SourceClassification::CommandLineArgs => SourceType::Other("Command Line".to_string()),
        SourceClassification::Other(s) => SourceType::Other(s.clone()),
    }
}

/// Result of command sink validation
pub struct CommandSinkValidation {
    /// Whether the sink is dangerous (not safe-by-construction)
    pub is_dangerous: bool,
    /// The actual callsite line (may differ from function start)
    pub callsite_line: Option<usize>,
    /// The role that is tainted (e.g., "Program", "ShellString")
    pub tainted_role: Option<String>,
    /// The argument index that is tainted
    pub tainted_arg_index: Option<usize>,
    /// The variable/parameter name that is tainted
    pub tainted_param_name: Option<String>,
}

/// Validate a command sink using argument-level analysis
///
/// Returns validation result with details about the sink
fn validate_command_sink(
    sink_file: &Path,
    sink_line: usize,
    parsed_files: &[ParsedFile],
) -> CommandSinkValidation {
    let default_dangerous = CommandSinkValidation {
        is_dangerous: true,
        callsite_line: None,
        tainted_role: None,
        tainted_arg_index: None,
        tainted_param_name: None,
    };
    let safe = CommandSinkValidation {
        is_dangerous: false,
        callsite_line: None,
        tainted_role: None,
        tainted_arg_index: None,
        tainted_param_name: None,
    };

    // Only validate for Rust files
    let is_rust = sink_file
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext == "rs")
        .unwrap_or(false);

    if !is_rust {
        // For non-Rust, we don't have argument-level validation yet
        return default_dangerous;
    }

    // Find the parsed file content - use flexible path matching
    // since paths may be relative or absolute
    let content = parsed_files
        .iter()
        .find(|pf| {
            // Try exact match first
            pf.path == sink_file ||
            // Try filename + parent match for relative vs absolute paths
            pf.path.ends_with(sink_file) ||
            sink_file.ends_with(&pf.path) ||
            // Try matching just the filename as last resort
            pf.path.file_name() == sink_file.file_name()
        })
        .map(|pf| pf.content.as_str());

    let content = match content {
        Some(c) => c,
        None => {
            debug!(
                "validate_command_sink: Could not find content for {}",
                sink_file.display()
            );
            return default_dangerous; // Can't validate, assume dangerous
        }
    };

    // Analyze the command site
    debug!(
        "validate_command_sink: Analyzing {}:{} (content len: {})",
        sink_file.display(),
        sink_line,
        content.len()
    );

    if let Some(site) = analyze_rust_command(content, sink_line, "") {
        debug!(
            "validate_command_sink: Found site at {}:{} - is_shell_context={}, arg_roles={:?}",
            sink_file.display(),
            site.line,
            site.is_shell_context,
            site.arg_roles
        );

        match evaluate_command_sink(&site) {
            ArgSinkVerdict::SafeByConstruction => {
                debug!(
                    "Filtered FP: Command at {}:{} is safe by construction",
                    sink_file.display(),
                    site.line
                );
                safe // Not a real vulnerability
            }
            ArgSinkVerdict::Dangerous { role, arg_index } => {
                debug!(
                    "Confirmed: Command at {}:{} has tainted {:?} at arg {}",
                    sink_file.display(),
                    site.line,
                    role,
                    arg_index
                );
                CommandSinkValidation {
                    is_dangerous: true,
                    callsite_line: Some(site.line),
                    tainted_role: Some(format!("{:?}", role)),
                    tainted_arg_index: Some(arg_index),
                    tainted_param_name: site.tainted_param_name,
                }
            }
            ArgSinkVerdict::NotASink => {
                debug!(
                    "validate_command_sink: NotASink verdict for {}:{}",
                    sink_file.display(),
                    site.line
                );
                default_dangerous // Couldn't determine, treat as dangerous
            }
        }
    } else {
        debug!(
            "validate_command_sink: No command pattern found at {}:{}",
            sink_file.display(),
            sink_line
        );
        default_dangerous // Couldn't analyze, assume dangerous
    }
}

/// Get language from file extension
fn language_from_path(path: &Path) -> Option<rma_common::Language> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| match ext.to_lowercase().as_str() {
            "java" => rma_common::Language::Java,
            "kt" | "kts" => rma_common::Language::Kotlin,
            "js" | "mjs" | "cjs" => rma_common::Language::JavaScript,
            "ts" | "tsx" => rma_common::Language::TypeScript,
            "py" => rma_common::Language::Python,
            "go" => rma_common::Language::Go,
            "rs" => rma_common::Language::Rust,
            "rb" => rma_common::Language::Ruby,
            "php" => rma_common::Language::Php,
            "cs" => rma_common::Language::CSharp,
            "scala" | "sc" => rma_common::Language::Scala,
            "swift" => rma_common::Language::Swift,
            "sh" | "bash" | "zsh" => rma_common::Language::Bash,
            "ex" | "exs" => rma_common::Language::Elixir,
            "ml" | "mli" => rma_common::Language::OCaml,
            "sol" => rma_common::Language::Solidity,
            "tf" | "hcl" => rma_common::Language::Hcl,
            "yaml" | "yml" => rma_common::Language::Yaml,
            "json" => rma_common::Language::Json,
            "html" | "htm" => rma_common::Language::Html,
            _ => rma_common::Language::Unknown,
        })
}

/// Check if two paths are different languages
fn is_cross_language(source_path: &Path, sink_path: &Path) -> bool {
    let source_lang = language_from_path(source_path);
    let sink_lang = language_from_path(sink_path);

    match (source_lang, sink_lang) {
        (Some(a), Some(b)) => {
            // JS and TS are considered the same language family
            let normalize = |l: rma_common::Language| match l {
                rma_common::Language::TypeScript => rma_common::Language::JavaScript,
                other => other,
            };
            normalize(a) != normalize(b)
        }
        _ => false, // Unknown languages - allow conservatively
    }
}

/// Determine bridge type for cross-language flows
///
/// Currently returns None for cross-language flows (no bridge detection implemented).
/// Future: detect HTTP boundaries (fetch → @RequestMapping), file I/O, etc.
fn determine_bridge_type(source_path: &Path, sink_path: &Path) -> BridgeType {
    if !is_cross_language(source_path, sink_path) {
        return BridgeType::SameLanguage;
    }

    // TODO: Implement bridge detection
    // For now, cross-language flows without explicit bridge evidence are marked as None
    // Future work: detect fetch("/api/...") → @RequestMapping("/api/...") patterns
    BridgeType::None
}

/// Check if a file path is a test file (should be excluded by default)
pub fn is_test_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    let path_str = path_str.replace('\\', "/");

    // File name patterns
    if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
        let name_lower = file_name.to_lowercase();

        // Go test files
        if name_lower.ends_with("_test.go") {
            return true;
        }
        // Go benchmark files
        if name_lower.ends_with("_bench.go") || name_lower.contains("benchmark") {
            return true;
        }
        // Java/Kotlin test files
        if name_lower.ends_with("test.java")
            || name_lower.ends_with("tests.java")
            || name_lower.ends_with("test.kt")
            || name_lower.ends_with("tests.kt")
        {
            return true;
        }
        // JS/TS test files
        if name_lower.ends_with(".test.js")
            || name_lower.ends_with(".test.ts")
            || name_lower.ends_with(".spec.js")
            || name_lower.ends_with(".spec.ts")
            || name_lower.ends_with(".test.jsx")
            || name_lower.ends_with(".test.tsx")
        {
            return true;
        }
        // Python test files
        if name_lower.starts_with("test_") || name_lower.ends_with("_test.py") {
            return true;
        }
        // Rust test files (usually inline, but check for test modules)
        if name_lower == "tests.rs" || name_lower.ends_with("_test.rs") {
            return true;
        }
        // PHP test files
        if name_lower.ends_with("test.php") || name_lower.ends_with("tests.php") {
            return true;
        }
        // C# test files
        if name_lower.ends_with("tests.cs") || name_lower.ends_with("test.cs") {
            return true;
        }
        // Elixir test files
        if name_lower.ends_with("_test.exs") {
            return true;
        }
        // Swift test files
        if name_lower.ends_with("tests.swift") || name_lower.ends_with("test.swift") {
            return true;
        }
        // Scala test files
        if name_lower.ends_with("test.scala")
            || name_lower.ends_with("spec.scala")
            || name_lower.ends_with("suite.scala")
        {
            return true;
        }
        // Solidity test files
        if name_lower.ends_with(".t.sol") {
            return true;
        }
    }

    // Directory patterns
    let test_dir_patterns = [
        "/test/",
        "/tests/",
        "/testing/",
        "/__tests__/",
        "/testdata/",
        "/test-fixtures/",
        "/fixtures/",
        "/mock/",
        "/mocks/",
        "/fake/",
        "/fakes/",
        "/stub/",
        "/stubs/",
        "/src/test/", // Maven/Gradle
        "/spec/",     // Ruby/JS
    ];

    for pattern in &test_dir_patterns {
        if path_str.contains(pattern) {
            return true;
        }
    }

    false
}

/// Index for O(1) file content lookups (vs O(n) linear search)
struct FileContentIndex<'a> {
    by_path: HashMap<&'a Path, &'a str>,
}

impl<'a> FileContentIndex<'a> {
    fn new(parsed_files: &'a [ParsedFile]) -> Self {
        let mut by_path = HashMap::with_capacity(parsed_files.len());
        for pf in parsed_files {
            by_path.insert(pf.path.as_path(), pf.content.as_str());
        }
        Self { by_path }
    }

    #[inline]
    fn get_content(&self, path: &Path) -> Option<&'a str> {
        self.by_path.get(path).copied()
    }
}

/// Validate and potentially downgrade a sink classification based on evidence
/// Uses FileContentIndex for O(1) lookups
fn validate_sink_with_index(
    original_classification: &crate::callgraph::SinkClassification,
    language: rma_common::Language,
    file_index: &FileContentIndex,
    sink_path: &Path,
    sink_call: &str,
) -> (SinkType, SinkEvidence) {
    match file_index.get_content(sink_path) {
        Some(content) => {
            let (validated, evidence) = validate_sink_classification(
                original_classification.clone(),
                language,
                content,
                sink_call,
            );
            (convert_sink_classification(&validated), evidence)
        }
        None => (
            convert_sink_classification(original_classification),
            SinkEvidence::from_pattern(sink_call),
        ),
    }
}

/// Detect cross-file taint flows using call graph reachability
///
/// This approach:
/// 1. Uses classification-based detection (AST analysis of function contents)
/// 2. Builds language-specific knowledge bases for source/sink detection
/// 3. Identifies source functions (entry points that handle user input)
/// 4. Identifies sink functions (dangerous operations)
/// 5. Uses BFS to find paths from sources to sinks through cross-file edges
/// 6. Filters cross-language flows without bridge evidence (unless --allow-cross-language)
fn detect_cross_file_taints(
    call_graph: &CallGraph,
    parsed_files: &[ParsedFile],
) -> Vec<CrossFileTaint> {
    let mut taints = Vec::new();
    let mut seen_fingerprints: HashSet<String> = HashSet::new();
    let mut filtered_fps = 0usize;
    let mut filtered_cross_lang = 0usize;

    // Build file content index for O(1) lookups (vs O(n) per lookup)
    let file_index = FileContentIndex::new(parsed_files);

    // Phase 0: Use classification-based taint flows from the CallGraph
    // These are detected via AST analysis of what APIs functions call internally
    let classification_flows = call_graph.find_taint_flows();
    debug!(
        "Phase 0: Processing {} classification flows",
        classification_flows.len()
    );

    for flow in classification_flows {
        // Get original sink classification for validation
        let original_sink_classification = match flow.sink_type() {
            Some(s) => s.clone(),
            None => continue, // Skip unclassified sinks
        };

        // Validate sink classification with API/type evidence (O(1) lookup)
        let (sink_type, sink_evidence) = validate_sink_with_index(
            &original_sink_classification,
            flow.sink.language,
            &file_index,
            &flow.sink.file,
            &flow.sink.name,
        );

        // Skip findings where sink was completely invalidated (e.g., non-html-output)
        if matches!(sink_type, SinkType::Other(ref s) if s == "non-html-output") {
            filtered_fps += 1;
            continue;
        }

        // Validate command sinks using argument-level analysis
        let cmd_validation = if matches!(sink_type, SinkType::CommandInjection) {
            let validation = validate_command_sink(&flow.sink.file, flow.sink.line, parsed_files);
            if !validation.is_dangerous {
                filtered_fps += 1;
                continue; // Skip this - it's a false positive
            }
            Some(validation)
        } else {
            None
        };

        let source_type = flow
            .source_type()
            .map(convert_source_classification)
            .unwrap_or(SourceType::Other("Unknown".to_string()));

        let confidence = if flow.confidence >= 0.8 {
            TaintConfidence::High
        } else if flow.confidence >= 0.5 {
            TaintConfidence::Medium
        } else {
            TaintConfidence::Low
        };

        let severity = determine_severity_typed(&source_type, &sink_type, &confidence);

        let path_locs: Vec<TaintLocation> = flow
            .path
            .iter()
            .map(|f| TaintLocation {
                file: f.file.clone(),
                function: f.name.clone(),
                line: f.line,
                name: "call".to_string(),
            })
            .collect();

        // Extract role info from command validation if available
        let (sink_role, sink_arg_index, sink_callsite_line) = if let Some(ref v) = cmd_validation {
            (v.tainted_role.clone(), v.tainted_arg_index, v.callsite_line)
        } else {
            (None, None, None)
        };

        // Determine bridge type for cross-language flows
        let bridge_type = determine_bridge_type(&flow.source.file, &flow.sink.file);

        // Skip cross-language flows without bridge evidence
        // This prevents fake paths like jquery.validate.js → Java controller
        if bridge_type == BridgeType::None {
            filtered_cross_lang += 1;
            continue;
        }

        // Determine reachability based on whether source is in test code
        let reachability = if is_test_file(&flow.source.file) {
            Reachability::TestOnly
        } else if matches!(
            source_type,
            SourceType::HttpHandler | SourceType::HttpParameter
        ) {
            Reachability::ProdReachable
        } else {
            Reachability::Unknown
        };

        let taint = CrossFileTaint {
            source: TaintLocation {
                file: flow.source.file.clone(),
                function: flow.source.name.clone(),
                line: flow.source.line,
                name: source_type.to_string(),
            },
            sink: TaintLocation {
                file: flow.sink.file.clone(),
                function: flow.sink.name.clone(),
                line: flow.sink.line,
                name: sink_type.to_string(),
            },
            path: path_locs,
            severity,
            confidence,
            source_type: source_type.clone(),
            sink_type: sink_type.clone(),
            sink_context: sink_type.default_context(),
            description: format!(
                "[Classification] {} ({}) -> {} ({})",
                flow.source.name, source_type, flow.sink.name, sink_type
            ),
            sink_role,
            sink_arg_index,
            sink_callsite_line,
            bridge_type,
            reachability,
            sink_evidence,
        };

        let fingerprint = taint.fingerprint();
        if !seen_fingerprints.contains(&fingerprint) {
            seen_fingerprints.insert(fingerprint);
            taints.push(taint);
        }
    }

    // Phase 1: Use FunctionDef.classification (populated by FunctionClassifier)
    // This uses the knowledge system via AST analysis - no pattern matching needed
    let sources: Vec<&FunctionDef> = call_graph.source_functions();
    let sinks: Vec<&FunctionDef> = call_graph.sink_functions();

    // Phase 2: For each source, BFS to find reachable sinks
    for source in sources.iter() {
        let reachable_sinks = find_reachable_sinks(call_graph, source, &sinks);

        for (sink, path) in reachable_sinks {
            // Only report cross-file flows
            if source.file != sink.file {
                // Get typed sink from classification - skip if none
                let original_sink_classification = match sink.classification.sink_kinds.first() {
                    Some(sk) => sk.clone(),
                    None => continue, // Skip unclassified sinks
                };

                // Validate sink classification with API/type evidence (O(1) lookup)
                let (sink_type, sink_evidence) = validate_sink_with_index(
                    &original_sink_classification,
                    sink.language,
                    &file_index,
                    &sink.file,
                    &sink.name,
                );

                // Skip findings where sink was completely invalidated
                if matches!(sink_type, SinkType::Other(ref s) if s == "non-html-output") {
                    filtered_fps += 1;
                    continue;
                }

                // Validate command sinks using argument-level analysis
                let cmd_validation = if matches!(sink_type, SinkType::CommandInjection) {
                    let validation = validate_command_sink(&sink.file, sink.line, parsed_files);
                    if !validation.is_dangerous {
                        filtered_fps += 1;
                        continue; // Skip this - it's a false positive
                    }
                    Some(validation)
                } else {
                    None
                };

                let source_type = source
                    .classification
                    .source_kind
                    .as_ref()
                    .map(convert_source_classification)
                    .unwrap_or(SourceType::Other("Unknown".to_string()));

                let confidence = if source.classification.confidence >= 0.8 {
                    TaintConfidence::High
                } else if source.classification.confidence >= 0.5 {
                    TaintConfidence::Medium
                } else {
                    TaintConfidence::Low
                };

                let severity = determine_severity_typed(&source_type, &sink_type, &confidence);

                let path_locs: Vec<TaintLocation> = path
                    .iter()
                    .map(|f| TaintLocation {
                        file: f.file.clone(),
                        function: f.name.clone(),
                        line: f.line,
                        name: "call".to_string(),
                    })
                    .collect();

                let description = format!(
                    "Data from {} ({}) can reach {} ({})",
                    source.name, source_type, sink.name, sink_type
                );

                // Extract role info from command validation if available
                let (sink_role, sink_arg_index, sink_callsite_line) =
                    if let Some(ref v) = cmd_validation {
                        (v.tainted_role.clone(), v.tainted_arg_index, v.callsite_line)
                    } else {
                        (None, None, None)
                    };

                // Cross-language filtering
                let bridge_type = determine_bridge_type(&source.file, &sink.file);
                if bridge_type == BridgeType::None {
                    filtered_cross_lang += 1;
                    continue;
                }

                // Determine reachability
                let reachability = if is_test_file(&source.file) {
                    Reachability::TestOnly
                } else if source
                    .classification
                    .source_kind
                    .as_ref()
                    .map(|sk| {
                        matches!(
                            sk,
                            crate::callgraph::SourceClassification::HttpHandler
                                | crate::callgraph::SourceClassification::HttpInput
                        )
                    })
                    .unwrap_or(false)
                {
                    Reachability::ProdReachable
                } else {
                    Reachability::Unknown
                };

                let taint = CrossFileTaint {
                    source: TaintLocation {
                        file: source.file.clone(),
                        function: source.name.clone(),
                        line: source.line,
                        name: source_type.to_string(),
                    },
                    sink: TaintLocation {
                        file: sink.file.clone(),
                        function: sink.name.clone(),
                        line: sink.line,
                        name: sink_type.to_string(),
                    },
                    path: path_locs,
                    severity,
                    confidence,
                    source_type,
                    sink_type: sink_type.clone(),
                    sink_context: sink_type.default_context(),
                    description,
                    sink_role,
                    sink_arg_index,
                    sink_callsite_line,
                    bridge_type,
                    reachability,
                    sink_evidence,
                };

                let fingerprint = taint.fingerprint();
                if !seen_fingerprints.contains(&fingerprint) {
                    seen_fingerprints.insert(fingerprint);
                    taints.push(taint);
                }
            }
        }
    }

    // Phase 3: Direct cross-file source->sink edges (high confidence)
    for edge in call_graph.cross_file_edges() {
        // Use classification from FunctionDef
        if edge.caller.classification.is_source && edge.callee.classification.contains_sinks {
            // Get original sink classification for validation
            let original_sink_classification = match edge.callee.classification.sink_kinds.first() {
                Some(sk) => sk.clone(),
                None => continue,
            };

            // Validate sink classification with API/type evidence (O(1) lookup)
            let (sink_type, sink_evidence) = validate_sink_with_index(
                &original_sink_classification,
                edge.callee.language,
                &file_index,
                &edge.callee.file,
                &edge.callee.name,
            );

            // Skip findings where sink was completely invalidated
            if matches!(sink_type, SinkType::Other(ref s) if s == "non-html-output") {
                filtered_fps += 1;
                continue;
            }

            // Validate command sinks using argument-level analysis
            let cmd_validation = if matches!(sink_type, SinkType::CommandInjection) {
                let validation =
                    validate_command_sink(&edge.callee.file, edge.callee.line, parsed_files);
                if !validation.is_dangerous {
                    filtered_fps += 1;
                    continue; // Skip this - it's a false positive
                }
                Some(validation)
            } else {
                None
            };

            let source_type = edge
                .caller
                .classification
                .source_kind
                .as_ref()
                .map(convert_source_classification)
                .unwrap_or(SourceType::Other("Unknown".to_string()));

            // Extract role info from command validation if available
            let (sink_role, sink_arg_index, sink_callsite_line) =
                if let Some(ref v) = cmd_validation {
                    (v.tainted_role.clone(), v.tainted_arg_index, v.callsite_line)
                } else {
                    (None, None, None)
                };

            // Cross-language filtering for direct edges
            let bridge_type = determine_bridge_type(&edge.caller.file, &edge.callee.file);
            if bridge_type == BridgeType::None {
                filtered_cross_lang += 1;
                continue;
            }

            // Determine reachability
            let reachability = if is_test_file(&edge.caller.file) {
                Reachability::TestOnly
            } else if edge
                .caller
                .classification
                .source_kind
                .as_ref()
                .map(|sk| {
                    matches!(
                        sk,
                        crate::callgraph::SourceClassification::HttpHandler
                            | crate::callgraph::SourceClassification::HttpInput
                    )
                })
                .unwrap_or(false)
            {
                Reachability::ProdReachable
            } else {
                Reachability::Unknown
            };

            let taint = CrossFileTaint {
                source: TaintLocation {
                    file: edge.caller.file.clone(),
                    function: edge.caller.name.clone(),
                    line: edge.call_site.line,
                    name: source_type.to_string(),
                },
                sink: TaintLocation {
                    file: edge.callee.file.clone(),
                    function: edge.callee.name.clone(),
                    line: edge.callee.line,
                    name: sink_type.to_string(),
                },
                path: vec![],
                severity: Severity::Critical, // Direct call = high severity
                confidence: TaintConfidence::High, // Direct edge = high confidence
                source_type,
                sink_type: sink_type.clone(),
                sink_context: sink_type.default_context(),
                description: format!(
                    "Direct cross-file call: {} -> {} ({})",
                    edge.caller.name, edge.callee.name, sink_type
                ),
                sink_role,
                sink_arg_index,
                sink_callsite_line,
                bridge_type,
                reachability,
                sink_evidence,
            };

            let fingerprint = taint.fingerprint();
            if !seen_fingerprints.contains(&fingerprint) {
                seen_fingerprints.insert(fingerprint);
                taints.push(taint);
            }
        }
    }

    // Phase 5: Event-based flows
    for event_binding in call_graph.all_event_bindings() {
        if !event_binding.emit_sites.is_empty() && !event_binding.listen_sites.is_empty() {
            for emit_site in &event_binding.emit_sites {
                for listen_site in &event_binding.listen_sites {
                    if emit_site.file == listen_site.file {
                        continue;
                    }

                    // Events ARE bridge evidence - they're a legitimate data flow mechanism
                    let bridge_type = if is_cross_language(&emit_site.file, &listen_site.file) {
                        BridgeType::MessageQueue // Event systems are message-based bridges
                    } else {
                        BridgeType::SameLanguage
                    };

                    // Event sources are typically internal, but check for test files
                    let reachability = if is_test_file(&emit_site.file) {
                        Reachability::TestOnly
                    } else {
                        Reachability::Unknown
                    };

                    let taint = CrossFileTaint {
                        source: TaintLocation {
                            file: emit_site.file.clone(),
                            function: emit_site
                                .function
                                .clone()
                                .unwrap_or_else(|| "<module>".to_string()),
                            line: emit_site.line,
                            name: format!("event:{}", event_binding.event_name),
                        },
                        sink: TaintLocation {
                            file: listen_site.file.clone(),
                            function: listen_site
                                .function
                                .clone()
                                .unwrap_or_else(|| "<handler>".to_string()),
                            line: listen_site.line,
                            name: format!("listener:{}", event_binding.event_name),
                        },
                        path: vec![],
                        severity: Severity::Warning,
                        confidence: TaintConfidence::Medium, // Event flows are less certain
                        source_type: SourceType::Other(format!(
                            "event:{}",
                            event_binding.event_name
                        )),
                        sink_type: SinkType::Other(format!(
                            "listener:{}",
                            event_binding.event_name
                        )),
                        sink_context: SinkContext::Unknown, // Event flows need runtime analysis
                        description: format!(
                            "Event '{}' flows between files",
                            event_binding.event_name
                        ),
                        sink_role: None,
                        sink_arg_index: None,
                        sink_callsite_line: None,
                        bridge_type,
                        reachability,
                        // Event flows don't have specific sink classifications
                        sink_evidence: SinkEvidence::none(),
                    };

                    let fingerprint = taint.fingerprint();
                    if !seen_fingerprints.contains(&fingerprint) {
                        seen_fingerprints.insert(fingerprint);
                        taints.push(taint);
                    }
                }
            }
        }
    }

    // Sort by severity (most severe first) and limit results
    taints.sort_by(|a, b| b.severity.cmp(&a.severity));
    taints.truncate(1000); // Limit to avoid overwhelming output

    if filtered_fps > 0 {
        debug!(
            "Filtered {} false positive command sinks (safe-by-construction)",
            filtered_fps
        );
    }

    if filtered_cross_lang > 0 {
        debug!(
            "Filtered {} cross-language flows (no bridge evidence)",
            filtered_cross_lang
        );
    }

    taints
}

/// Determine severity based on typed source, sink, and confidence
fn determine_severity_typed(
    source_type: &SourceType,
    sink_type: &SinkType,
    confidence: &TaintConfidence,
) -> Severity {
    // HTTP handler -> critical sink with high confidence = Critical
    let is_http_source = matches!(
        source_type,
        SourceType::HttpHandler | SourceType::HttpParameter
    );
    let is_critical_sink = matches!(
        sink_type,
        SinkType::SqlInjection | SinkType::CommandInjection | SinkType::Deserialization
    );

    if is_http_source && is_critical_sink {
        return match confidence {
            TaintConfidence::High => Severity::Critical,
            TaintConfidence::Medium => Severity::Critical,
            TaintConfidence::Low => Severity::Error,
        };
    }

    // Other dangerous sinks
    match sink_type {
        SinkType::SqlInjection | SinkType::CommandInjection => Severity::Critical,
        SinkType::Deserialization | SinkType::LdapInjection => Severity::Critical,
        SinkType::PathTraversal | SinkType::TemplateInjection => Severity::Error,
        SinkType::CrossSiteScripting => Severity::Error,
        // GenericInjection is downgraded from specific types - lower severity
        SinkType::GenericInjection => Severity::Warning,
        SinkType::Other(_) => Severity::Warning,
    }
}

use crate::callgraph::FunctionDef;

/// BFS to find sinks reachable from a source function
fn find_reachable_sinks<'a>(
    call_graph: &'a CallGraph,
    source: &FunctionDef,
    sinks: &[&'a FunctionDef],
) -> Vec<(&'a FunctionDef, Vec<FunctionDef>)> {
    use std::collections::VecDeque;

    let mut results = Vec::new();
    let mut visited: HashSet<(PathBuf, String)> = HashSet::new();
    let mut queue: VecDeque<(FunctionDef, Vec<FunctionDef>)> = VecDeque::new();

    // Start from source
    queue.push_back((source.clone(), vec![]));
    visited.insert((source.file.clone(), source.name.clone()));

    // Limit search depth to avoid infinite loops
    let max_depth = 10;
    let mut current_depth = 0;
    let mut nodes_at_current_depth = 1;
    let mut nodes_at_next_depth = 0;

    while let Some((current, path)) = queue.pop_front() {
        // Check depth limit
        if current_depth >= max_depth {
            break;
        }

        // Check if current is a sink
        for sink in sinks {
            if sink.file == current.file && sink.name == current.name {
                results.push((*sink, path.clone()));
            }
        }

        // Get callees
        for edge in call_graph.callees_of(&current.file, &current.name) {
            let callee_key = (edge.callee.file.clone(), edge.callee.name.clone());
            if !visited.contains(&callee_key) {
                visited.insert(callee_key);

                let mut new_path = path.clone();
                new_path.push(current.clone());
                queue.push_back((edge.callee.clone(), new_path));
                nodes_at_next_depth += 1;
            }
        }

        // Track depth
        nodes_at_current_depth -= 1;
        if nodes_at_current_depth == 0 {
            current_depth += 1;
            nodes_at_current_depth = nodes_at_next_depth;
            nodes_at_next_depth = 0;
        }

        // Limit results per source
        if results.len() >= 10 {
            break;
        }
    }

    results
}

/// Compute topological order of files based on import dependencies
pub fn topological_order(import_graph: &HashMap<PathBuf, Vec<PathBuf>>) -> Vec<PathBuf> {
    let mut in_degree: HashMap<PathBuf, usize> = HashMap::new();
    let mut all_files: HashSet<PathBuf> = HashSet::new();

    // Initialize
    for (file, deps) in import_graph {
        all_files.insert(file.clone());
        for dep in deps {
            all_files.insert(dep.clone());
        }
    }

    for file in &all_files {
        in_degree.insert(file.clone(), 0);
    }

    // Count incoming edges
    for deps in import_graph.values() {
        for dep in deps {
            *in_degree.get_mut(dep).unwrap_or(&mut 0) += 1;
        }
    }

    // Kahn's algorithm
    let mut queue: Vec<PathBuf> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(f, _)| f.clone())
        .collect();

    let mut result = Vec::new();

    while let Some(file) = queue.pop() {
        result.push(file.clone());

        if let Some(deps) = import_graph.get(&file) {
            for dep in deps {
                if let Some(deg) = in_degree.get_mut(dep) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push(dep.clone());
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topological_order_simple() {
        let mut graph = HashMap::new();
        graph.insert(PathBuf::from("a.js"), vec![PathBuf::from("b.js")]);
        graph.insert(PathBuf::from("b.js"), vec![PathBuf::from("c.js")]);
        graph.insert(PathBuf::from("c.js"), vec![]);

        let order = topological_order(&graph);

        // c.js should come before b.js, which should come before a.js
        let c_idx = order.iter().position(|f| f.ends_with("c.js"));
        let b_idx = order.iter().position(|f| f.ends_with("b.js"));
        let a_idx = order.iter().position(|f| f.ends_with("a.js"));

        // All files should be present
        assert!(c_idx.is_some());
        assert!(b_idx.is_some());
        assert!(a_idx.is_some());
    }

    #[test]
    fn test_discover_files() {
        // This would need a temp directory for proper testing
        // For now, just verify the function doesn't panic on non-existent path
        let config = RmaConfig::default();
        let result = discover_files(Path::new("/nonexistent/path"), &config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_build_import_graph() {
        let mut imports = HashMap::new();

        let mut file_a = FileImports::default();
        file_a.imports.push(crate::imports::ResolvedImport {
            local_name: "foo".to_string(),
            source_file: PathBuf::from("b.js"),
            exported_name: "foo".to_string(),
            kind: crate::imports::ImportKind::Named,
            specifier: "./b".to_string(),
            line: 1,
        });

        imports.insert(PathBuf::from("a.js"), file_a);
        imports.insert(PathBuf::from("b.js"), FileImports::default());

        let graph = build_import_graph(&imports);

        assert_eq!(graph.len(), 2);
        assert_eq!(graph.get(&PathBuf::from("a.js")).unwrap().len(), 1);
        assert_eq!(graph.get(&PathBuf::from("b.js")).unwrap().len(), 0);
    }
}
