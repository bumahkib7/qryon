//! Resource Leak Detection Rule
//!
//! Detects resources that are acquired but not properly closed on all paths
//! to function exit. Uses CFG path analysis to ensure resources are closed
//! on ALL paths, not just the happy path.

use crate::flow::{BlockId, FlowContext, Terminator};
use crate::rules::{Rule, create_finding_at_line};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use std::collections::HashSet;
use tree_sitter::Node;

/// Tracks a resource that was acquired and needs to be released
#[derive(Debug, Clone)]
struct TrackedResource {
    /// Variable name holding the resource
    var_name: String,
    /// Line where the resource was acquired
    line: usize,
    /// CFG block containing the acquisition
    block_id: BlockId,
    /// Type of resource (for better error messages)
    resource_type: String,
}

/// Language-specific patterns for resource acquisition and release
struct ResourcePatterns {
    /// Patterns that acquire resources (function names or constructors)
    acquisition: &'static [&'static str],
    /// Patterns that release resources
    release: &'static [&'static str],
    /// Safe contexts where resource is auto-managed
    safe_contexts: &'static [&'static str],
}

/// Detects resource leaks: resources that are acquired but not properly closed
/// on all paths to function exit.
///
/// Resource leaks can cause:
/// - File descriptor exhaustion
/// - Memory leaks
/// - Database connection pool exhaustion
/// - Network socket exhaustion
///
/// This rule uses CFG path analysis to ensure resources are closed on ALL paths,
/// not just the happy path.
pub struct ResourceLeakRule;

impl ResourceLeakRule {
    // =========================================================================
    // JavaScript/TypeScript Resource Patterns
    // =========================================================================

    const JS_ACQUISITION: &'static [&'static str] = &[
        // File system
        "fs.open",
        "fs.openSync",
        "fs.createReadStream",
        "fs.createWriteStream",
        "createReadStream",
        "createWriteStream",
        // Network
        "net.createServer",
        "net.createConnection",
        "net.connect",
        "http.createServer",
        "https.createServer",
        // Database
        "createConnection",
        "createPool",
        "getConnection",
        // File handles
        "openSync",
    ];

    const JS_RELEASE: &'static [&'static str] = &[
        "close",
        "closeSync",
        "end",
        "destroy",
        "release",
        "disconnect",
        "dispose",
    ];

    const JS_SAFE_CONTEXTS: &'static [&'static str] = &[
        // Promise-based patterns often use finally
        "finally", // Some libraries auto-close
        "using",
    ];

    // =========================================================================
    // Python Resource Patterns
    // =========================================================================

    const PYTHON_ACQUISITION: &'static [&'static str] = &[
        // Database
        "sqlite3.connect",
        "psycopg2.connect",
        "pymysql.connect",
        "mysql.connector.connect",
        // Network
        "socket.socket",
        "create_connection",
        // Other resources
        "Lock",
        "RLock",
        "Semaphore",
        "acquire",
    ];

    const PYTHON_RELEASE: &'static [&'static str] = &["close", "shutdown", "release", "disconnect"];

    const PYTHON_SAFE_CONTEXTS: &'static [&'static str] = &[
        "with",      // Context manager
        "__enter__", // Part of context manager protocol
        "__exit__",  // Part of context manager protocol
    ];

    // =========================================================================
    // Go Resource Patterns
    // =========================================================================

    const GO_ACQUISITION: &'static [&'static str] = &[
        // File system
        "os.Open",
        "os.OpenFile",
        "os.Create",
        // Network
        "net.Dial",
        "net.DialTCP",
        "net.DialUDP",
        "net.Listen",
        "net.ListenTCP",
        // Database
        "sql.Open",
        // HTTP
        "http.Get",
        "http.Post",
        "http.DefaultClient.Do",
        "Client.Do",
        // Locking
        "Lock",
        "RLock",
    ];

    const GO_RELEASE: &'static [&'static str] = &["Close", "Unlock", "RUnlock"];

    const GO_SAFE_CONTEXTS: &'static [&'static str] = &[
        "defer", // Go's defer statement ensures cleanup
    ];

    // =========================================================================
    // Rust Resource Patterns
    // =========================================================================

    const RUST_ACQUISITION: &'static [&'static str] = &[
        // File system
        "File::open",
        "File::create",
        "OpenOptions::open",
        // Network
        "TcpStream::connect",
        "TcpListener::bind",
        "UdpSocket::bind",
        // Database
        "Connection::open",
        "Pool::get",
        // Locks
        "Mutex::lock",
        "RwLock::read",
        "RwLock::write",
    ];

    const RUST_RELEASE: &'static [&'static str] = &[
        // Rust uses RAII - Drop trait handles cleanup
        // These are explicit close methods some types have
        "drop", "close", "shutdown",
    ];

    const RUST_SAFE_CONTEXTS: &'static [&'static str] = &[
        // Rust uses RAII/Drop - most resources are safe by default
        "drop", "?", // Error propagation with ? often works with Drop
    ];

    // =========================================================================
    // Java Resource Patterns
    // =========================================================================

    const JAVA_ACQUISITION: &'static [&'static str] = &[
        // File I/O
        "new FileInputStream",
        "new FileOutputStream",
        "new FileReader",
        "new FileWriter",
        "new BufferedReader",
        "new BufferedWriter",
        "new BufferedInputStream",
        "new BufferedOutputStream",
        "new RandomAccessFile",
        "Files.newInputStream",
        "Files.newOutputStream",
        "Files.newBufferedReader",
        "Files.newBufferedWriter",
        // Network
        "new Socket",
        "new ServerSocket",
        "ServerSocket.accept",
        // Database
        "DriverManager.getConnection",
        "DataSource.getConnection",
        "prepareStatement",
        "createStatement",
        // Other
        "new PrintWriter",
        "new Scanner",
    ];

    const JAVA_RELEASE: &'static [&'static str] = &["close", "disconnect", "shutdown"];

    const JAVA_SAFE_CONTEXTS: &'static [&'static str] = &[
        "try-with-resources",
        "try (",         // Try-with-resources syntax
        "AutoCloseable", // Marker interface
        "@Cleanup",      // Lombok annotation
    ];

    /// Get resource patterns for a specific language
    fn patterns_for_language(language: Language) -> ResourcePatterns {
        match language {
            Language::JavaScript | Language::TypeScript => ResourcePatterns {
                acquisition: Self::JS_ACQUISITION,
                release: Self::JS_RELEASE,
                safe_contexts: Self::JS_SAFE_CONTEXTS,
            },
            Language::Python => ResourcePatterns {
                acquisition: Self::PYTHON_ACQUISITION,
                release: Self::PYTHON_RELEASE,
                safe_contexts: Self::PYTHON_SAFE_CONTEXTS,
            },
            Language::Go => ResourcePatterns {
                acquisition: Self::GO_ACQUISITION,
                release: Self::GO_RELEASE,
                safe_contexts: Self::GO_SAFE_CONTEXTS,
            },
            Language::Rust => ResourcePatterns {
                acquisition: Self::RUST_ACQUISITION,
                release: Self::RUST_RELEASE,
                safe_contexts: Self::RUST_SAFE_CONTEXTS,
            },
            Language::Java => ResourcePatterns {
                acquisition: Self::JAVA_ACQUISITION,
                release: Self::JAVA_RELEASE,
                safe_contexts: Self::JAVA_SAFE_CONTEXTS,
            },
            _ => ResourcePatterns {
                acquisition: &[],
                release: &[],
                safe_contexts: &[],
            },
        }
    }

    /// Check if a node is inside a safe context (with statement, try-with-resources, defer)
    fn is_in_safe_context(&self, node: Node<'_>, source: &[u8], language: Language) -> bool {
        let patterns = Self::patterns_for_language(language);

        // Walk up the tree looking for safe contexts
        let mut current = Some(node);
        while let Some(n) = current {
            let kind = n.kind();

            // Check for language-specific safe patterns
            match language {
                Language::Python => {
                    if kind == "with_statement" || kind == "with_clause" {
                        return true;
                    }
                }
                Language::Java => {
                    // Try-with-resources: try ( Resource r = ... )
                    if kind == "try_with_resources_statement" || kind == "resource_specification" {
                        return true;
                    }
                }
                Language::Go => {
                    // Check for defer in the same function
                    // This is handled separately in has_defer_close
                }
                Language::Rust => {
                    // Rust uses RAII - resources in scopes are auto-closed
                    // Check if we're assigning to a variable (not a temp)
                    if kind == "let_declaration" {
                        // Resource is bound to a variable, RAII will handle it
                        return true;
                    }
                }
                _ => {}
            }

            // Check node text against safe context patterns
            if let Ok(text) = n.utf8_text(source) {
                for pattern in patterns.safe_contexts {
                    if text.contains(pattern) {
                        return true;
                    }
                }
            }

            current = n.parent();
        }
        false
    }

    /// Check if there's a defer statement that closes the resource (Go-specific)
    fn has_defer_close(&self, resource_var: &str, node: Node<'_>, source: &[u8]) -> bool {
        // Look for defer statements in the same function
        let mut current = Some(node);

        // First, find the function body
        while let Some(n) = current {
            if n.kind() == "function_declaration"
                || n.kind() == "method_declaration"
                || n.kind() == "func_literal"
            {
                // Found the function, now search for defer statements
                return self.search_for_defer_close(n, resource_var, source);
            }
            current = n.parent();
        }
        false
    }

    /// Recursively search for defer close statements
    fn search_for_defer_close(&self, node: Node<'_>, resource_var: &str, source: &[u8]) -> bool {
        if node.kind() == "defer_statement" {
            if let Ok(text) = node.utf8_text(source) {
                // Check if defer closes our resource
                if text.contains(resource_var) && (text.contains("Close") || text.contains("close"))
                {
                    return true;
                }
            }
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if self.search_for_defer_close(child, resource_var, source) {
                return true;
            }
        }
        false
    }

    /// Find all resource acquisitions in the AST
    fn find_resource_acquisitions(
        &self,
        node: Node<'_>,
        source: &[u8],
        language: Language,
        flow: &FlowContext,
    ) -> Vec<TrackedResource> {
        let mut resources = Vec::new();
        let patterns = Self::patterns_for_language(language);

        self.find_acquisitions_recursive(node, source, language, &patterns, flow, &mut resources);

        resources
    }

    fn find_acquisitions_recursive(
        &self,
        node: Node<'_>,
        source: &[u8],
        language: Language,
        patterns: &ResourcePatterns,
        flow: &FlowContext,
        resources: &mut Vec<TrackedResource>,
    ) {
        // Check if this node represents a resource acquisition
        if let Ok(text) = node.utf8_text(source) {
            for &pattern in patterns.acquisition {
                if text.contains(pattern) {
                    // Check if we're in a safe context
                    if !self.is_in_safe_context(node, source, language) {
                        // For Go, also check for defer
                        if language == Language::Go {
                            let var_name = self.get_assigned_variable(node, source, language);
                            if let Some(ref var) = var_name {
                                if self.has_defer_close(var, node, source) {
                                    continue; // Skip - defer handles cleanup
                                }
                            }
                        }

                        // For Rust, most resources are RAII-managed
                        if language == Language::Rust {
                            // Only flag if resource is explicitly leaked
                            // e.g., assigned to a field or returned without close
                            // For now, skip Rust as RAII handles most cases
                            continue;
                        }

                        let var_name = self
                            .get_assigned_variable(node, source, language)
                            .unwrap_or_else(|| "anonymous".to_string());

                        let block_id = flow.cfg.block_of(node.id()).unwrap_or(0);

                        resources.push(TrackedResource {
                            var_name,
                            line: node.start_position().row + 1,
                            block_id,
                            resource_type: pattern.to_string(),
                        });
                    }
                    break;
                }
            }
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_acquisitions_recursive(child, source, language, patterns, flow, resources);
        }
    }

    /// Get the variable name a resource is assigned to
    fn get_assigned_variable(
        &self,
        node: Node<'_>,
        source: &[u8],
        language: Language,
    ) -> Option<String> {
        // Look for assignment patterns
        let parent = node.parent()?;

        match language {
            Language::JavaScript | Language::TypeScript => {
                if parent.kind() == "variable_declarator"
                    || parent.kind() == "assignment_expression"
                {
                    // First child is usually the variable name
                    if let Some(name_node) = parent.child(0) {
                        if let Ok(name) = name_node.utf8_text(source) {
                            return Some(name.to_string());
                        }
                    }
                }
            }
            Language::Python => {
                if parent.kind() == "assignment" {
                    if let Some(left) = parent.child_by_field_name("left") {
                        if let Ok(name) = left.utf8_text(source) {
                            return Some(name.to_string());
                        }
                    }
                }
            }
            Language::Go => {
                if parent.kind() == "short_var_declaration"
                    || parent.kind() == "assignment_statement"
                {
                    if let Some(left) = parent.child_by_field_name("left") {
                        if let Ok(name) = left.utf8_text(source) {
                            return Some(name.to_string());
                        }
                    }
                }
            }
            Language::Java => {
                if parent.kind() == "variable_declarator"
                    || parent.kind() == "assignment_expression"
                {
                    if let Some(name_node) = parent.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source) {
                            return Some(name.to_string());
                        }
                    } else if let Some(first) = parent.child(0) {
                        if let Ok(name) = first.utf8_text(source) {
                            return Some(name.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// Find CFG blocks where a resource is released
    fn find_release_blocks(
        &self,
        resource_var: &str,
        root: Node<'_>,
        source: &[u8],
        language: Language,
        flow: &FlowContext,
    ) -> HashSet<BlockId> {
        let mut release_blocks = HashSet::new();
        let patterns = Self::patterns_for_language(language);

        self.find_releases_recursive(
            root,
            source,
            resource_var,
            patterns.release,
            flow,
            &mut release_blocks,
        );

        release_blocks
    }

    fn find_releases_recursive(
        &self,
        node: Node<'_>,
        source: &[u8],
        resource_var: &str,
        release_patterns: &[&str],
        flow: &FlowContext,
        release_blocks: &mut HashSet<BlockId>,
    ) {
        // Check if this node is a release call on our resource
        if node.kind() == "call_expression" || node.kind() == "method_invocation" {
            if let Ok(text) = node.utf8_text(source) {
                // Check if this is a release call on our variable
                let is_release = release_patterns.iter().any(|pattern| {
                    text.contains(&format!("{}.{}", resource_var, pattern))
                        || text.contains(&format!("{}({})", pattern, resource_var))
                        || (text.contains(resource_var) && text.contains(pattern))
                });

                if is_release {
                    if let Some(block_id) = flow.cfg.block_of(node.id()) {
                        release_blocks.insert(block_id);
                    }
                }
            }
        }

        // Recurse
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_releases_recursive(
                child,
                source,
                resource_var,
                release_patterns,
                flow,
                release_blocks,
            );
        }
    }

    /// Find all exit blocks in the CFG
    fn find_exit_blocks(&self, flow: &FlowContext) -> HashSet<BlockId> {
        let mut exits = HashSet::new();

        for block in &flow.cfg.blocks {
            match &block.terminator {
                Terminator::Return | Terminator::Unreachable => {
                    exits.insert(block.id);
                }
                _ => {}
            }
        }

        // Always include the designated exit block
        exits.insert(flow.cfg.exit);

        exits
    }

    /// Check if a resource can be leaked on any path
    fn is_leaked_on_any_path(
        &self,
        resource: &TrackedResource,
        release_blocks: &HashSet<BlockId>,
        exit_blocks: &HashSet<BlockId>,
        flow: &FlowContext,
    ) -> bool {
        // For each exit block, check if all paths from acquisition to exit
        // pass through at least one release block
        for &exit_block in exit_blocks {
            // Check if this exit is reachable from the acquisition
            if !flow.cfg.can_reach(resource.block_id, exit_block) {
                continue; // This exit path isn't reachable from acquisition
            }

            // Check if ANY release block is on all paths to this exit
            let mut has_release_on_all_paths = false;

            for &release_block in release_blocks {
                // Check if all paths from acquisition to exit go through this release
                if flow.cfg.can_reach(resource.block_id, release_block)
                    && flow.cfg.can_reach(release_block, exit_block)
                    && flow.cfg.all_paths_through(exit_block, release_block)
                {
                    has_release_on_all_paths = true;
                    break;
                }
            }

            if !has_release_on_all_paths {
                // This exit can be reached without releasing the resource
                return true;
            }
        }

        false
    }

    /// Get language-specific suggestion for fixing the leak
    fn get_leak_suggestion(&self, language: Language, resource_type: &str) -> String {
        match language {
            Language::JavaScript | Language::TypeScript => {
                format!(
                    "Ensure {} is closed in a finally block, or use try-finally pattern: \
                    try {{ ... }} finally {{ resource.close(); }}",
                    resource_type
                )
            }
            Language::Python => {
                format!(
                    "Use a context manager (with statement) for {}: \
                    with open(...) as f: ...",
                    resource_type
                )
            }
            Language::Go => {
                format!(
                    "Use defer to ensure {} is closed: \
                    defer resource.Close()",
                    resource_type
                )
            }
            Language::Rust => {
                format!(
                    "Ensure {} is properly dropped. Consider using explicit scope \
                    or drop() call if needed.",
                    resource_type
                )
            }
            Language::Java => {
                format!(
                    "Use try-with-resources for {}: \
                    try ({} r = new {}(...)) {{ ... }}",
                    resource_type, resource_type, resource_type
                )
            }
            _ => format!(
                "Ensure {} is properly closed on all execution paths.",
                resource_type
            ),
        }
    }
}

impl Rule for ResourceLeakRule {
    fn id(&self) -> &str {
        "generic/resource-leak"
    }

    fn description(&self) -> &str {
        "Detects resources that may not be closed on all execution paths"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Java
        )
        // Note: Rust uses RAII which handles most cases automatically
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // Requires CFG analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip test files
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        let source = parsed.content.as_bytes();
        let root = parsed.tree.root_node();

        // Find all resource acquisitions
        let resources = self.find_resource_acquisitions(root, source, parsed.language, flow);

        // For each resource, check if it's properly released on all paths
        for resource in resources {
            // Find all blocks where this resource is released
            let release_blocks =
                self.find_release_blocks(&resource.var_name, root, source, parsed.language, flow);

            // If no release calls found at all, it's definitely a leak
            if release_blocks.is_empty() {
                let suggestion = self.get_leak_suggestion(parsed.language, &resource.resource_type);
                let mut finding = create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    resource.line,
                    &resource.var_name,
                    Severity::Warning,
                    &format!(
                        "Resource '{}' ({}) is acquired but never closed. {}",
                        resource.var_name, resource.resource_type, suggestion
                    ),
                    parsed.language,
                );
                finding.confidence = Confidence::High;
                finding.suggestion = Some(suggestion);
                findings.push(finding);
                continue;
            }

            // Find exit blocks
            let exit_blocks = self.find_exit_blocks(flow);

            // Check if resource can leak on any path
            if self.is_leaked_on_any_path(&resource, &release_blocks, &exit_blocks, flow) {
                let suggestion = self.get_leak_suggestion(parsed.language, &resource.resource_type);
                let mut finding = create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    resource.line,
                    &resource.var_name,
                    Severity::Warning,
                    &format!(
                        "Resource '{}' ({}) may not be closed on all execution paths. {}",
                        resource.var_name, resource.resource_type, suggestion
                    ),
                    parsed.language,
                );
                finding.confidence = Confidence::Medium;
                finding.suggestion = Some(suggestion);
                findings.push(finding);
            }
        }

        // Deduplicate findings
        findings.sort_by_key(|f| (f.location.start_line, f.location.start_column));
        findings.dedup_by(|a, b| {
            a.location.start_line == b.location.start_line && a.message == b.message
        });

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_leak_rule_applies_to_languages() {
        let rule = ResourceLeakRule;
        assert!(rule.applies_to(Language::JavaScript));
        assert!(rule.applies_to(Language::TypeScript));
        assert!(rule.applies_to(Language::Python));
        assert!(rule.applies_to(Language::Go));
        assert!(rule.applies_to(Language::Java));
        // Rust uses RAII, so we don't apply this rule
        assert!(!rule.applies_to(Language::Rust));
    }

    #[test]
    fn test_resource_leak_rule_id() {
        let rule = ResourceLeakRule;
        assert_eq!(rule.id(), "generic/resource-leak");
    }

    #[test]
    fn test_resource_leak_rule_uses_flow() {
        let rule = ResourceLeakRule;
        assert!(rule.uses_flow());
    }

    #[test]
    fn test_js_patterns() {
        let patterns = ResourceLeakRule::patterns_for_language(Language::JavaScript);
        assert!(patterns.acquisition.contains(&"fs.open"));
        assert!(patterns.acquisition.contains(&"createReadStream"));
        assert!(patterns.release.contains(&"close"));
        assert!(patterns.release.contains(&"end"));
    }

    #[test]
    fn test_python_patterns() {
        let patterns = ResourceLeakRule::patterns_for_language(Language::Python);
        assert!(patterns.acquisition.contains(&"sqlite3.connect"));
        assert!(patterns.acquisition.contains(&"socket.socket"));
        assert!(patterns.release.contains(&"close"));
        assert!(patterns.safe_contexts.contains(&"with"));
    }

    #[test]
    fn test_go_patterns() {
        let patterns = ResourceLeakRule::patterns_for_language(Language::Go);
        assert!(patterns.acquisition.contains(&"os.Open"));
        assert!(patterns.acquisition.contains(&"net.Dial"));
        assert!(patterns.release.contains(&"Close"));
        assert!(patterns.safe_contexts.contains(&"defer"));
    }

    #[test]
    fn test_java_patterns() {
        let patterns = ResourceLeakRule::patterns_for_language(Language::Java);
        assert!(patterns.acquisition.contains(&"new FileInputStream"));
        assert!(
            patterns
                .acquisition
                .contains(&"DriverManager.getConnection")
        );
        assert!(patterns.release.contains(&"close"));
        assert!(patterns.safe_contexts.contains(&"try ("));
    }

    #[test]
    fn test_leak_suggestions() {
        let rule = ResourceLeakRule;

        let js_suggestion = rule.get_leak_suggestion(Language::JavaScript, "fs.open");
        assert!(js_suggestion.contains("finally"));

        let py_suggestion = rule.get_leak_suggestion(Language::Python, "open");
        assert!(py_suggestion.contains("context manager"));
        assert!(py_suggestion.contains("with"));

        let go_suggestion = rule.get_leak_suggestion(Language::Go, "os.Open");
        assert!(go_suggestion.contains("defer"));

        let java_suggestion = rule.get_leak_suggestion(Language::Java, "FileInputStream");
        assert!(java_suggestion.contains("try-with-resources"));
    }
}
