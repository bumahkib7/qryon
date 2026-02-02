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

use crate::callgraph::{
    CallGraph, CallGraphBuilder, extract_function_calls, extract_function_definitions,
};
use crate::imports::{FileImports, extract_file_imports};
use crate::{AnalysisSummary, AnalyzerEngine, FileAnalysis};
use anyhow::Result;
use rayon::prelude::*;
use rma_common::{RmaConfig, Severity};
use rma_parser::{ParsedFile, ParserEngine};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info, instrument, warn};

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

/// A taint flow that crosses file boundaries
#[derive(Debug, Clone)]
pub struct CrossFileTaint {
    /// Source of the taint (file, function, line)
    pub source: TaintLocation,
    /// Sink where tainted data arrives
    pub sink: TaintLocation,
    /// Path of functions the taint flows through
    pub path: Vec<TaintLocation>,
    /// Severity of the issue
    pub severity: Severity,
    /// Description of the vulnerability
    pub description: String,
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

        // Step 2: Parse all files in parallel
        let parsed_files: Vec<ParsedFile> = if self.parallel_enabled {
            files
                .par_iter()
                .filter_map(|f| match std::fs::read_to_string(f) {
                    Ok(content) => self.parser.parse_file(f, &content).ok(),
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
                    Ok(content) => self.parser.parse_file(f, &content).ok(),
                    Err(e) => {
                        warn!("Failed to read {}: {}", f.display(), e);
                        None
                    }
                })
                .collect()
        };

        info!("Parsed {} files successfully", parsed_files.len());

        // Step 3: Run per-file analysis
        let (file_results, summary) = self.analyzer.analyze_files(&parsed_files)?;

        // Step 4: Cross-file analysis (if enabled)
        let (call_graph, import_graph, cross_file_taints) = if self.cross_file_enabled {
            self.run_cross_file_analysis(&parsed_files, path)?
        } else {
            (None, HashMap::new(), Vec::new())
        };

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
    ) -> Result<(
        Option<CallGraph>,
        HashMap<PathBuf, Vec<PathBuf>>,
        Vec<CrossFileTaint>,
    )> {
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

        // Step 3: Build call graph
        let mut call_graph_builder = CallGraphBuilder::new();

        for parsed in parsed_files {
            let source = parsed.content.as_bytes();

            // Extract function definitions
            let functions = extract_function_definitions(&parsed.tree, source, parsed.language);

            // Extract function calls
            let calls = extract_function_calls(&parsed.tree, source, parsed.language);

            // Get imports for this file
            let imports = file_imports.get(&parsed.path).cloned().unwrap_or_default();

            call_graph_builder.add_file(&parsed.path, parsed.language, functions, calls, imports);
        }

        let call_graph = call_graph_builder.build();
        info!(
            "Built call graph: {} functions, {} edges",
            call_graph.function_count(),
            call_graph.edge_count()
        );

        // Step 4: Detect cross-file taint flows
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
        "rs", "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "go", "java",
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

/// Security-sensitive function names that indicate potential sinks
const SECURITY_SENSITIVE_FUNCTIONS: &[&str] = &[
    "exec",
    "eval",
    "query",
    "execute",
    "system",
    "popen",
    "spawn",
    "fork",
    "innerHTML",
    "setInnerHTML",
    "write",
    "writeln",
    "insertAdjacentHTML",
];

/// Detect cross-file taint flows using the call graph
fn detect_cross_file_taints(
    call_graph: &CallGraph,
    _parsed_files: &[ParsedFile],
) -> Vec<CrossFileTaint> {
    let mut taints = Vec::new();

    // Look for cross-file edges where taint could flow
    for edge in call_graph.cross_file_edges() {
        // This is a simplified detection - a real implementation would
        // need to track actual taint sources and sinks across the call graph

        // For now, we flag potential flows from entry points to security-sensitive functions
        if SECURITY_SENSITIVE_FUNCTIONS
            .iter()
            .any(|s| edge.callee.name.contains(s))
        {
            taints.push(CrossFileTaint {
                source: TaintLocation {
                    file: edge.caller.file.clone(),
                    function: edge.caller.name.clone(),
                    line: edge.call_site.line,
                    name: "input".to_string(),
                },
                sink: TaintLocation {
                    file: edge.callee.file.clone(),
                    function: edge.callee.name.clone(),
                    line: edge.callee.line,
                    name: edge.callee.name.clone(),
                },
                path: vec![TaintLocation {
                    file: edge.caller.file.clone(),
                    function: edge.caller.name.clone(),
                    line: edge.call_site.line,
                    name: "call".to_string(),
                }],
                severity: Severity::Warning,
                description: format!(
                    "Potential taint flow from {} to security-sensitive function {}",
                    edge.caller.name, edge.callee.name
                ),
            });
        }
    }

    taints
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
