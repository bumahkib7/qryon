//! Cross-File Call Graph
//!
//! Builds a project-wide call graph by:
//! 1. Collecting function definitions from all files
//! 2. Resolving imports to connect callers to callees across files
//! 3. Tracking call relationships for cross-file taint analysis
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
//! // Check if a function is reachable from an entry point
//! let reachable = graph.is_reachable_from("handleRequest", "processInput");
//! ```

use crate::imports::FileImports;
use rma_common::Language;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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

/// The complete call graph for a project
#[derive(Debug, Default)]
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
        // Add function definitions
        for (name, line, is_exported) in functions {
            let def = FunctionDef {
                name: name.clone(),
                file: file_path.to_path_buf(),
                line,
                is_exported,
                language,
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

    if is_function {
        if let Some(name) = extract_function_name(node, source, language) {
            let line = node.start_position().row + 1;
            let is_exported = is_function_exported(node, source, language);
            functions.push((name, line, is_exported));
        }
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
            if node.kind() == "arrow_function" {
                if let Some(parent) = node.parent() {
                    if parent.kind() == "variable_declarator" {
                        if let Some(name_node) = parent.child_by_field_name("name") {
                            return name_node.utf8_text(source).ok().map(|s| s.to_string());
                        }
                    }
                }
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
            if let Some(parent) = node.parent() {
                if parent.kind() == "export_statement" {
                    return true;
                }
            }
            false
        }
        Language::Python => {
            // In Python, functions not starting with _ are exported
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source) {
                    return !name.starts_with('_');
                }
            }
            false
        }
        Language::Rust => {
            // Check for pub visibility
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "visibility_modifier" {
                    if let Ok(text) = child.utf8_text(source) {
                        return text.starts_with("pub");
                    }
                }
            }
            false
        }
        Language::Go => {
            // Go exports are uppercase
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(source) {
                    return name.chars().next().map_or(false, |c| c.is_uppercase());
                }
            }
            false
        }
        Language::Java => {
            // Check for public modifier
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "modifiers" {
                    if let Ok(text) = child.utf8_text(source) {
                        return text.contains("public");
                    }
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

    if is_call {
        if let Some(callee_name) = extract_callee_name(node, source, language) {
            let line = node.start_position().row + 1;
            calls.push((callee_name, line, func_context.clone()));
        }
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
            if let Some(func_node) = node.child_by_field_name("function") {
                if func_node.kind() == "identifier" {
                    return func_node.utf8_text(source).ok().map(|s| s.to_string());
                }
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
