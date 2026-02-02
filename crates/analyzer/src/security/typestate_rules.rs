//! Typestate Rules for Resource State Machine Analysis
//!
//! This module implements predefined state machines for resources including:
//! - File/IO resources
//! - Iterator/Stream consumption patterns
//! - Cryptographic API usage (Hash, HMAC, Cipher)
//!
//! These track resource lifecycle across different programming languages to detect
//! misuse patterns that could lead to bugs or security vulnerabilities.
//!
//! # File Resources State Machine
//!
//! ```text
//! States: Unopened -> Open -> Closed
//!         Closed is final
//!         Unopened is initial
//!
//! Transitions:
//!   Unopened --[open/create]--> Open
//!   Open --[read/write]--> Open
//!   Open --[close]--> Closed
//!
//! Violations:
//!   - read/write when Closed (UseInErrorState)
//!   - open when Open (InvalidTransition - double open)
//!   - exit when Open (NonFinalStateAtExit - leak)
//! ```
//!
//! # Iterator/Stream State Machine
//!
//! ```text
//! States: Fresh -> Consumed -> Exhausted
//!         Fresh is initial
//!         Exhausted is final (for single-use iterators)
//!
//! Transitions:
//!   Fresh --[next/read]--> Consumed
//!   Consumed --[next/read]--> Consumed
//!   Consumed --[collect/drain]--> Exhausted
//!   Fresh --[collect/drain]--> Exhausted
//!
//! Violations:
//!   - next() after Exhausted (UseInErrorState)
//!   - collect() after partial consumption (possible data loss)
//!   - reusing consumed iterator
//! ```
//!
//! ## Language-specific Iterator/Stream Patterns:
//!
//! **JavaScript/TypeScript:**
//! - Create: .values(), .entries(), .keys(), Symbol.iterator, generators
//! - Consume: .next(), for...of, spread operator
//! - Exhaust: Array.from(), [...iter], .forEach()
//!
//! **Python:**
//! - Create: iter(), generator expressions, yield
//! - Consume: next(), for loop
//! - Exhaust: list(), tuple(), set(), dict()
//! - Warning: Using iterator twice
//!
//! **Go:**
//! - Create: range, channels, bufio.Scanner
//! - Consume: for range, <-channel, .Scan()
//! - Close: close(channel), break
//!
//! **Rust:**
//! - Create: .iter(), .into_iter(), .chars()
//! - Consume: .next(), for loop
//! - Exhaust: .collect(), .for_each(), .count()
//! - Warning: .iter() vs .into_iter() (ownership)
//!
//! **Java:**
//! - Create: .iterator(), .stream(), Stream.of()
//! - Consume: .next(), .hasNext()
//! - Exhaust: .collect(), .forEach(), .toArray()
//! - Warning: Stream reuse (IllegalStateException)
//!
//! # Hash/Digest State Machine
//!
//! ```text
//! States: Created -> Updating -> Finalized
//!         Finalized is final
//!
//! Transitions:
//!   Created --[update/write]--> Updating
//!   Updating --[update/write]--> Updating
//!   Updating --[finalize/digest/finish]--> Finalized
//!   Created --[finalize]--> Finalized (empty hash)
//!
//! Violations:
//!   - update after Finalized (InvalidTransition)
//!   - using digest value before Finalized
//! ```
//!
//! # Cipher State Machine
//!
//! ```text
//! States: Created -> Initialized -> Processing -> Finalized
//!
//! Transitions:
//!   Created --[init/set_key]--> Initialized
//!   Initialized --[encrypt/decrypt]--> Processing
//!   Processing --[encrypt/decrypt]--> Processing
//!   Processing --[finalize/finish]--> Finalized
//!
//! Violations:
//!   - encrypt/decrypt before Initialized (key not set)
//!   - encrypt/decrypt after Finalized
//!   - reusing cipher without reinit
//! ```
//!
//! # Language Support
//!
//! - JavaScript/TypeScript: fs.open, crypto.createHash, crypto.createCipher
//! - Python: open(), hashlib, cryptography
//! - Go: os.Open, sha256.New, aes.NewCipher
//! - Rust: File::open, Sha256::new, Aes::new
//! - Java: FileInputStream, MessageDigest, Cipher

use crate::flow::{BlockId, CFG, FlowContext, Terminator};
use crate::rules::{Rule, create_finding_at_line};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

// =============================================================================
// State Machine Types
// =============================================================================

/// Represents the state of a file resource
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileState {
    /// Initial state - file handle not yet created
    Unopened,
    /// File is open and can be read/written
    Open,
    /// File is closed - final state
    Closed,
    /// Error state - resource is in an invalid state
    Error,
}

impl FileState {
    /// Check if this is a final (valid exit) state
    pub fn is_final(&self) -> bool {
        matches!(self, FileState::Closed | FileState::Unopened)
    }

    /// Check if this is the initial state
    pub fn is_initial(&self) -> bool {
        matches!(self, FileState::Unopened)
    }
}

/// Operations that can be performed on a file resource
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileOperation {
    /// Open or create a file
    Open,
    /// Read from file
    Read,
    /// Write to file
    Write,
    /// Close the file
    Close,
}

impl FileOperation {
    /// Get the operation name for error messages
    pub fn name(&self) -> &'static str {
        match self {
            FileOperation::Open => "open",
            FileOperation::Read => "read",
            FileOperation::Write => "write",
            FileOperation::Close => "close",
        }
    }
}

/// Type of violation detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationType {
    /// Operation on a closed resource
    UseInErrorState {
        operation: FileOperation,
        resource: String,
        line: usize,
    },
    /// Invalid state transition (e.g., double open)
    InvalidTransition {
        operation: FileOperation,
        from_state: FileState,
        resource: String,
        line: usize,
    },
    /// Resource not in final state at function exit
    NonFinalStateAtExit {
        state: FileState,
        resource: String,
        acquisition_line: usize,
    },
}

impl ViolationType {
    /// Convert violation to a finding message
    pub fn message(&self) -> String {
        match self {
            ViolationType::UseInErrorState {
                operation,
                resource,
                ..
            } => {
                format!(
                    "Attempted to {} closed resource '{}'. The file has already been closed.",
                    operation.name(),
                    resource
                )
            }
            ViolationType::InvalidTransition {
                operation,
                from_state,
                resource,
                ..
            } => match (operation, from_state) {
                (FileOperation::Open, FileState::Open) => {
                    format!(
                        "Resource '{}' is already open. Double-open may cause resource leak.",
                        resource
                    )
                }
                (FileOperation::Read, FileState::Unopened) => {
                    format!("Attempted to read from '{}' before opening it.", resource)
                }
                (FileOperation::Write, FileState::Unopened) => {
                    format!("Attempted to write to '{}' before opening it.", resource)
                }
                _ => {
                    format!(
                        "Invalid operation '{}' on resource '{}' in state {:?}.",
                        operation.name(),
                        resource,
                        from_state
                    )
                }
            },
            ViolationType::NonFinalStateAtExit {
                state,
                resource,
                acquisition_line,
            } => {
                format!(
                    "Resource '{}' (opened at line {}) may not be closed on all paths. State at exit: {:?}. This may cause a resource leak.",
                    resource, acquisition_line, state
                )
            }
        }
    }

    /// Get the severity for this violation type
    pub fn severity(&self) -> Severity {
        match self {
            ViolationType::UseInErrorState { .. } => Severity::Error,
            ViolationType::InvalidTransition { .. } => Severity::Warning,
            ViolationType::NonFinalStateAtExit { .. } => Severity::Warning,
        }
    }

    /// Get the line number for this violation
    pub fn line(&self) -> usize {
        match self {
            ViolationType::UseInErrorState { line, .. } => *line,
            ViolationType::InvalidTransition { line, .. } => *line,
            ViolationType::NonFinalStateAtExit {
                acquisition_line, ..
            } => *acquisition_line,
        }
    }
}

// =============================================================================
// State Machine Definition
// =============================================================================

/// A state machine transition
#[derive(Debug, Clone)]
struct Transition {
    from: FileState,
    operation: FileOperation,
    to: FileState,
}

/// File state machine definition with language-specific triggers
#[derive(Debug, Clone)]
pub struct FileStateMachine {
    /// Valid transitions
    transitions: Vec<Transition>,
    /// Patterns that trigger Open operation
    open_patterns: Vec<&'static str>,
    /// Patterns that trigger Read operation
    read_patterns: Vec<&'static str>,
    /// Patterns that trigger Write operation
    write_patterns: Vec<&'static str>,
    /// Patterns that trigger Close operation
    close_patterns: Vec<&'static str>,
    /// Patterns that indicate safe auto-close context
    safe_patterns: Vec<&'static str>,
}

impl FileStateMachine {
    /// Create a new file state machine for a specific language
    pub fn for_language(language: Language) -> Self {
        let transitions = vec![
            // Unopened -> Open (open/create)
            Transition {
                from: FileState::Unopened,
                operation: FileOperation::Open,
                to: FileState::Open,
            },
            // Open -> Open (read/write)
            Transition {
                from: FileState::Open,
                operation: FileOperation::Read,
                to: FileState::Open,
            },
            Transition {
                from: FileState::Open,
                operation: FileOperation::Write,
                to: FileState::Open,
            },
            // Open -> Closed (close)
            Transition {
                from: FileState::Open,
                operation: FileOperation::Close,
                to: FileState::Closed,
            },
        ];

        match language {
            Language::JavaScript | Language::TypeScript => Self {
                transitions,
                open_patterns: vec![
                    "fs.open",
                    "fs.openSync",
                    "fs.createReadStream",
                    "fs.createWriteStream",
                    "new FileHandle",
                    "openSync",
                    "createReadStream",
                    "createWriteStream",
                    "fs.promises.open",
                ],
                read_patterns: vec![
                    "fs.read",
                    "fs.readSync",
                    ".read(",
                    ".pipe(",
                    "fs.readFile",
                    "readFile",
                    "readSync",
                ],
                write_patterns: vec![
                    "fs.write",
                    "fs.writeSync",
                    ".write(",
                    "fs.writeFile",
                    "writeFile",
                    "writeSync",
                ],
                close_patterns: vec![".close(", "fs.close", "fs.closeSync", ".end(", ".destroy("],
                safe_patterns: vec!["finally", ".finally(", "using"],
            },
            Language::Python => Self {
                transitions,
                open_patterns: vec![
                    "open(",
                    "io.open(",
                    "Path.open(",
                    "codecs.open(",
                    "gzip.open(",
                    "bz2.open(",
                    "lzma.open(",
                ],
                read_patterns: vec![".read(", ".readline(", ".readlines(", ".read_text("],
                write_patterns: vec![".write(", ".writelines(", ".write_text("],
                close_patterns: vec![".close("],
                safe_patterns: vec!["with ", "async with ", "__enter__", "__exit__"],
            },
            Language::Go => Self {
                transitions,
                open_patterns: vec![
                    "os.Open(",
                    "os.Create(",
                    "os.OpenFile(",
                    "ioutil.ReadFile(",
                    "os.ReadFile(",
                ],
                read_patterns: vec![
                    ".Read(",
                    "io.ReadAll(",
                    "bufio.NewReader(",
                    "ioutil.ReadAll(",
                    ".ReadString(",
                    ".ReadBytes(",
                ],
                write_patterns: vec![".Write(", ".WriteString(", "io.WriteString("],
                close_patterns: vec![".Close("],
                safe_patterns: vec!["defer ", "defer f.Close(", "defer file.Close("],
            },
            Language::Rust => Self {
                transitions,
                open_patterns: vec![
                    "File::open(",
                    "File::create(",
                    "OpenOptions::new(",
                    "fs::File::open(",
                    "fs::File::create(",
                ],
                read_patterns: vec![
                    ".read(",
                    ".read_to_string(",
                    ".read_to_end(",
                    "BufReader::new(",
                    ".read_line(",
                ],
                write_patterns: vec![".write(", ".write_all(", ".write_fmt(", "BufWriter::new("],
                close_patterns: vec![
                    "drop(", ".flush(", // Rust uses RAII, so explicit close is rare
                ],
                safe_patterns: vec![
                    "?", // Error propagation with Drop
                    "}", // Scope exit (RAII handles cleanup)
                ],
            },
            Language::Java => Self {
                transitions,
                open_patterns: vec![
                    "new FileInputStream(",
                    "new FileOutputStream(",
                    "new FileReader(",
                    "new FileWriter(",
                    "new BufferedReader(",
                    "new BufferedWriter(",
                    "new BufferedInputStream(",
                    "new BufferedOutputStream(",
                    "new RandomAccessFile(",
                    "new PrintWriter(",
                    "new Scanner(",
                    "Files.newInputStream(",
                    "Files.newOutputStream(",
                    "Files.newBufferedReader(",
                    "Files.newBufferedWriter(",
                ],
                read_patterns: vec![
                    ".read(",
                    ".readLine(",
                    ".readAllBytes(",
                    ".readAllLines(",
                    ".lines(",
                ],
                write_patterns: vec![".write(", ".println(", ".print(", ".append("],
                close_patterns: vec![".close("],
                safe_patterns: vec![
                    "try (",
                    "try-with-resources",
                    "@Cleanup",
                    "AutoCloseable",
                    "Closeable",
                ],
            },
            _ => Self {
                transitions,
                open_patterns: vec![],
                read_patterns: vec![],
                write_patterns: vec![],
                close_patterns: vec![],
                safe_patterns: vec![],
            },
        }
    }

    /// Check what operation a piece of code performs (if any)
    pub fn detect_operation(&self, code: &str) -> Option<FileOperation> {
        // Check in order of specificity
        for pattern in &self.close_patterns {
            if code.contains(pattern) {
                return Some(FileOperation::Close);
            }
        }
        for pattern in &self.open_patterns {
            if code.contains(pattern) {
                return Some(FileOperation::Open);
            }
        }
        for pattern in &self.write_patterns {
            if code.contains(pattern) {
                return Some(FileOperation::Write);
            }
        }
        for pattern in &self.read_patterns {
            if code.contains(pattern) {
                return Some(FileOperation::Read);
            }
        }
        None
    }

    /// Check if code is in a safe auto-close context
    pub fn is_safe_context(&self, code: &str) -> bool {
        for pattern in &self.safe_patterns {
            if code.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Apply a transition and return the new state
    pub fn apply_transition(
        &self,
        current: FileState,
        operation: FileOperation,
    ) -> Result<FileState, ViolationType> {
        // Check for invalid operations on closed state
        if current == FileState::Closed {
            if operation != FileOperation::Open {
                return Err(ViolationType::UseInErrorState {
                    operation,
                    resource: String::new(), // Will be filled in by caller
                    line: 0,
                });
            }
        }

        // Find valid transition
        for trans in &self.transitions {
            if trans.from == current && trans.operation == operation {
                return Ok(trans.to);
            }
        }

        // No valid transition found
        Err(ViolationType::InvalidTransition {
            operation,
            from_state: current,
            resource: String::new(),
            line: 0,
        })
    }
}

// =============================================================================
// Tracked Resource
// =============================================================================

/// A file resource being tracked through the state machine
#[derive(Debug, Clone)]
struct TrackedResource {
    /// Variable name holding the resource
    var_name: String,
    /// Current state of the resource
    state: FileState,
    /// Line where the resource was acquired
    acquisition_line: usize,
    /// Block ID where acquired
    acquisition_block: BlockId,
    /// Whether this resource is in a safe auto-close context
    is_safe: bool,
}

// =============================================================================
// Typestate Analyzer
// =============================================================================

/// Analyzer that tracks file resource states through the CFG
pub struct TypestateAnalyzer {
    state_machine: FileStateMachine,
}

impl TypestateAnalyzer {
    /// Create a new analyzer with the given state machine
    pub fn new(state_machine: FileStateMachine) -> Self {
        Self { state_machine }
    }

    /// Analyze a parsed file and return violations
    pub fn analyze(&self, parsed: &ParsedFile, cfg: &CFG) -> Vec<ViolationType> {
        let source = parsed.content.as_bytes();
        let root = parsed.tree.root_node();
        let mut violations = Vec::new();

        // Find all file resource creations
        let resources = self.find_resources(root, source, parsed.language, cfg);

        // For each resource, track state through CFG
        for resource in resources {
            if resource.is_safe {
                continue; // Skip resources in safe contexts
            }

            let resource_violations = self.track_resource(&resource, root, source, cfg);
            violations.extend(resource_violations);
        }

        violations
    }

    /// Find all file resource creations in the AST
    fn find_resources(
        &self,
        node: Node<'_>,
        source: &[u8],
        language: Language,
        cfg: &CFG,
    ) -> Vec<TrackedResource> {
        let mut resources = Vec::new();
        self.find_resources_recursive(node, source, language, cfg, &mut resources);
        resources
    }

    fn find_resources_recursive(
        &self,
        node: Node<'_>,
        source: &[u8],
        language: Language,
        cfg: &CFG,
        resources: &mut Vec<TrackedResource>,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            // Check if this creates a file resource
            if self.state_machine.detect_operation(text) == Some(FileOperation::Open) {
                let var_name = self
                    .get_assigned_variable(node, source, language)
                    .unwrap_or_else(|| "anonymous".to_string());

                let is_safe = self.is_in_safe_context(node, source, language);
                let block_id = cfg.block_of(node.id()).unwrap_or(0);

                resources.push(TrackedResource {
                    var_name,
                    state: FileState::Open,
                    acquisition_line: node.start_position().row + 1,
                    acquisition_block: block_id,
                    is_safe,
                });
            }
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_resources_recursive(child, source, language, cfg, resources);
        }
    }

    /// Check if a node is inside a safe auto-close context
    fn is_in_safe_context(&self, node: Node<'_>, source: &[u8], language: Language) -> bool {
        let mut current = Some(node);

        while let Some(n) = current {
            if let Ok(text) = n.utf8_text(source) {
                if self.state_machine.is_safe_context(text) {
                    return true;
                }
            }

            // Language-specific safe context detection
            match language {
                Language::Python => {
                    if n.kind() == "with_statement" || n.kind() == "with_clause" {
                        return true;
                    }
                }
                Language::Java => {
                    if n.kind() == "try_with_resources_statement"
                        || n.kind() == "resource_specification"
                    {
                        return true;
                    }
                }
                Language::Go => {
                    // Check for defer in same function
                    if self.has_defer_close(n, source) {
                        return true;
                    }
                }
                Language::Rust => {
                    // Rust uses RAII - variables in scope are auto-dropped
                    if n.kind() == "let_declaration" || n.kind() == "let_statement" {
                        return true;
                    }
                }
                _ => {}
            }

            current = n.parent();
        }

        false
    }

    /// Check for defer .Close() in Go code
    fn has_defer_close(&self, node: Node<'_>, source: &[u8]) -> bool {
        let mut current = Some(node);

        // Find the enclosing function
        while let Some(n) = current {
            if n.kind() == "function_declaration"
                || n.kind() == "method_declaration"
                || n.kind() == "func_literal"
            {
                return self.search_for_defer_close(n, source);
            }
            current = n.parent();
        }

        false
    }

    /// Recursively search for defer .Close() statements
    fn search_for_defer_close(&self, node: Node<'_>, source: &[u8]) -> bool {
        if node.kind() == "defer_statement" {
            if let Ok(text) = node.utf8_text(source) {
                if text.contains("Close") || text.contains("close") {
                    return true;
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if self.search_for_defer_close(child, source) {
                return true;
            }
        }

        false
    }

    /// Get the variable name a resource is assigned to
    fn get_assigned_variable(
        &self,
        node: Node<'_>,
        source: &[u8],
        language: Language,
    ) -> Option<String> {
        let parent = node.parent()?;

        match language {
            Language::JavaScript | Language::TypeScript => {
                if parent.kind() == "variable_declarator"
                    || parent.kind() == "assignment_expression"
                {
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
            Language::Rust => {
                if parent.kind() == "let_declaration" || parent.kind() == "let_statement" {
                    if let Some(pattern) = parent.child_by_field_name("pattern") {
                        if let Ok(name) = pattern.utf8_text(source) {
                            return Some(name.to_string());
                        }
                    }
                }
            }
            Language::Java => {
                if parent.kind() == "variable_declarator"
                    || parent.kind() == "local_variable_declaration"
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

    /// Track a resource through the CFG and detect violations
    fn track_resource(
        &self,
        resource: &TrackedResource,
        root: Node<'_>,
        source: &[u8],
        cfg: &CFG,
    ) -> Vec<ViolationType> {
        let mut violations = Vec::new();

        // Find all operations on this resource
        let operations = self.find_operations_on_resource(root, source, &resource.var_name);

        // Track state through operations
        let mut state = resource.state;
        let mut last_close_block: Option<BlockId> = None;

        for (op, line, block_id) in operations.iter().copied() {
            match self.state_machine.apply_transition(state, op) {
                Ok(new_state) => {
                    if op == FileOperation::Close {
                        last_close_block = Some(block_id);
                    }
                    state = new_state;
                }
                Err(mut violation) => {
                    // Fill in resource details
                    match &mut violation {
                        ViolationType::UseInErrorState {
                            resource: r,
                            line: l,
                            ..
                        } => {
                            *r = resource.var_name.clone();
                            *l = line;
                        }
                        ViolationType::InvalidTransition {
                            resource: r,
                            line: l,
                            ..
                        } => {
                            *r = resource.var_name.clone();
                            *l = line;
                        }
                        _ => {}
                    }
                    violations.push(violation);
                }
            }
        }

        // Check if resource is in final state at all exits
        if !state.is_final() && last_close_block.is_none() {
            // Check if any exit is reachable from the acquisition without close
            let exit_blocks = self.find_exit_blocks(cfg);
            let has_leak_path = exit_blocks.iter().any(|&exit| {
                cfg.can_reach(resource.acquisition_block, exit)
                    && !self.has_close_on_all_paths(
                        cfg,
                        resource.acquisition_block,
                        exit,
                        &operations,
                    )
            });

            if has_leak_path {
                violations.push(ViolationType::NonFinalStateAtExit {
                    state,
                    resource: resource.var_name.clone(),
                    acquisition_line: resource.acquisition_line,
                });
            }
        }

        violations
    }

    /// Find all operations on a specific resource variable
    fn find_operations_on_resource(
        &self,
        node: Node<'_>,
        source: &[u8],
        var_name: &str,
    ) -> Vec<(FileOperation, usize, BlockId)> {
        let mut operations = Vec::new();
        self.find_operations_recursive(node, source, var_name, &mut operations);
        operations
    }

    fn find_operations_recursive(
        &self,
        node: Node<'_>,
        source: &[u8],
        var_name: &str,
        operations: &mut Vec<(FileOperation, usize, BlockId)>,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            // Check if this operation is on our variable
            if text.contains(var_name) {
                if let Some(op) = self.state_machine.detect_operation(text) {
                    if op != FileOperation::Open {
                        // Don't count the initial open as an operation
                        operations.push((op, node.start_position().row + 1, node.id()));
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.find_operations_recursive(child, source, var_name, operations);
        }
    }

    /// Find all exit blocks in the CFG
    fn find_exit_blocks(&self, cfg: &CFG) -> HashSet<BlockId> {
        let mut exits = HashSet::new();

        for block in &cfg.blocks {
            match &block.terminator {
                Terminator::Return | Terminator::Unreachable => {
                    exits.insert(block.id);
                }
                _ => {}
            }
        }

        exits.insert(cfg.exit);
        exits
    }

    /// Check if there's a close operation on all paths from acquisition to exit
    fn has_close_on_all_paths(
        &self,
        cfg: &CFG,
        from: BlockId,
        to: BlockId,
        operations: &[(FileOperation, usize, BlockId)],
    ) -> bool {
        // Find blocks with close operations
        let close_blocks: HashSet<BlockId> = operations
            .iter()
            .filter(|(op, _, _)| *op == FileOperation::Close)
            .map(|(_, _, block)| *block)
            .collect();

        // Check if any close block is on all paths from acquisition to exit
        for &close_block in &close_blocks {
            if cfg.can_reach(from, close_block) && cfg.can_reach(close_block, to) {
                if cfg.all_paths_through(to, close_block) {
                    return true;
                }
            }
        }

        false
    }
}

// =============================================================================
// File Typestate Rule
// =============================================================================

/// Rule that detects file resource typestate violations
pub struct FileTypestateRule;

impl FileTypestateRule {
    /// Get the file state machine for a specific language
    fn file_state_machine(language: Language) -> FileStateMachine {
        FileStateMachine::for_language(language)
    }

    /// Convert a violation to a finding
    fn violation_to_finding(&self, violation: &ViolationType, parsed: &ParsedFile) -> Finding {
        let mut finding = create_finding_at_line(
            self.id(),
            &parsed.path,
            violation.line(),
            "",
            violation.severity(),
            &violation.message(),
            parsed.language,
        );

        finding.confidence = match violation {
            ViolationType::UseInErrorState { .. } => Confidence::High,
            ViolationType::InvalidTransition { .. } => Confidence::Medium,
            ViolationType::NonFinalStateAtExit { .. } => Confidence::Medium,
        };

        // Add suggestions
        finding.suggestion = Some(self.get_suggestion(parsed.language, violation));

        finding
    }

    /// Get language-specific suggestion for fixing the violation
    fn get_suggestion(&self, language: Language, violation: &ViolationType) -> String {
        match violation {
            ViolationType::UseInErrorState { .. } => {
                "Ensure the resource is open before performing operations on it.".to_string()
            }
            ViolationType::InvalidTransition { operation, .. } => match operation {
                FileOperation::Open => {
                    "Close the existing file before opening a new one, or use a different variable."
                        .to_string()
                }
                _ => "Check the resource state before performing this operation.".to_string(),
            },
            ViolationType::NonFinalStateAtExit { resource, .. } => match language {
                Language::JavaScript | Language::TypeScript => {
                    format!(
                        "Ensure '{}' is closed in a finally block: try {{ ... }} finally {{ {}.close(); }}",
                        resource, resource
                    )
                }
                Language::Python => {
                    format!("Use a context manager: with open(...) as {}: ...", resource)
                }
                Language::Go => {
                    format!(
                        "Use defer to ensure '{}' is closed: defer {}.Close()",
                        resource, resource
                    )
                }
                Language::Rust => {
                    format!(
                        "Rust uses RAII - ensure '{}' goes out of scope properly or call drop() explicitly.",
                        resource
                    )
                }
                Language::Java => {
                    format!("Use try-with-resources: try ({} = ...) {{ ... }}", resource)
                }
                _ => format!(
                    "Ensure '{}' is properly closed on all execution paths.",
                    resource
                ),
            },
        }
    }
}

impl Rule for FileTypestateRule {
    fn id(&self) -> &str {
        "generic/file-typestate"
    }

    fn description(&self) -> &str {
        "Detects file resource lifecycle violations using typestate analysis"
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
        // Skip test files
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        // Get file state machine for this language
        let sm = Self::file_state_machine(parsed.language);

        // Create analyzer and run typestate analysis
        let analyzer = TypestateAnalyzer::new(sm);
        let violations = analyzer.analyze(parsed, &flow.cfg);

        // Convert violations to findings
        violations
            .iter()
            .map(|v| self.violation_to_finding(v, parsed))
            .collect()
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rma_parser::ParserEngine;
    use std::path::Path;

    #[allow(dead_code)]
    fn parse_file(code: &str, lang: Language) -> ParsedFile {
        let config = rma_common::RmaConfig::default();
        let parser = ParserEngine::new(config);
        let ext = match lang {
            Language::JavaScript => "js",
            Language::TypeScript => "ts",
            Language::Python => "py",
            Language::Go => "go",
            Language::Rust => "rs",
            Language::Java => "java",
            _ => "txt",
        };
        parser
            .parse_file(Path::new(&format!("test.{}", ext)), code)
            .expect("parse failed")
    }

    // =========================================================================
    // State Machine Tests
    // =========================================================================

    #[test]
    fn test_file_state_transitions() {
        let sm = FileStateMachine::for_language(Language::JavaScript);

        // Valid transitions
        assert_eq!(
            sm.apply_transition(FileState::Unopened, FileOperation::Open)
                .unwrap(),
            FileState::Open
        );
        assert_eq!(
            sm.apply_transition(FileState::Open, FileOperation::Read)
                .unwrap(),
            FileState::Open
        );
        assert_eq!(
            sm.apply_transition(FileState::Open, FileOperation::Write)
                .unwrap(),
            FileState::Open
        );
        assert_eq!(
            sm.apply_transition(FileState::Open, FileOperation::Close)
                .unwrap(),
            FileState::Closed
        );
    }

    #[test]
    fn test_invalid_transitions() {
        let sm = FileStateMachine::for_language(Language::JavaScript);

        // Read on closed should fail
        let result = sm.apply_transition(FileState::Closed, FileOperation::Read);
        assert!(matches!(result, Err(ViolationType::UseInErrorState { .. })));

        // Write on closed should fail
        let result = sm.apply_transition(FileState::Closed, FileOperation::Write);
        assert!(matches!(result, Err(ViolationType::UseInErrorState { .. })));

        // Read on unopened should fail
        let result = sm.apply_transition(FileState::Unopened, FileOperation::Read);
        assert!(matches!(
            result,
            Err(ViolationType::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_state_is_final() {
        assert!(FileState::Closed.is_final());
        assert!(FileState::Unopened.is_final());
        assert!(!FileState::Open.is_final());
        assert!(!FileState::Error.is_final());
    }

    // =========================================================================
    // JavaScript/TypeScript Tests
    // =========================================================================

    #[test]
    fn test_js_detect_open_operations() {
        let sm = FileStateMachine::for_language(Language::JavaScript);

        assert_eq!(
            sm.detect_operation("fs.open('file.txt')"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("fs.createReadStream('file.txt')"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("fs.createWriteStream('file.txt')"),
            Some(FileOperation::Open)
        );
    }

    #[test]
    fn test_js_detect_close_operations() {
        let sm = FileStateMachine::for_language(Language::JavaScript);

        assert_eq!(
            sm.detect_operation("file.close()"),
            Some(FileOperation::Close)
        );
        assert_eq!(
            sm.detect_operation("fs.closeSync(fd)"),
            Some(FileOperation::Close)
        );
        assert_eq!(
            sm.detect_operation("stream.end()"),
            Some(FileOperation::Close)
        );
    }

    #[test]
    fn test_js_detect_read_write_operations() {
        let sm = FileStateMachine::for_language(Language::JavaScript);

        assert_eq!(
            sm.detect_operation("fs.read(fd, buffer)"),
            Some(FileOperation::Read)
        );
        assert_eq!(
            sm.detect_operation("stream.pipe(dest)"),
            Some(FileOperation::Read)
        );
        assert_eq!(
            sm.detect_operation("fs.write(fd, data)"),
            Some(FileOperation::Write)
        );
        assert_eq!(
            sm.detect_operation("file.write('data')"),
            Some(FileOperation::Write)
        );
    }

    #[test]
    fn test_js_safe_context() {
        let sm = FileStateMachine::for_language(Language::JavaScript);

        assert!(sm.is_safe_context("stream.finally(() => stream.close())"));
        assert!(!sm.is_safe_context("stream.write('data')"));
    }

    // =========================================================================
    // Python Tests
    // =========================================================================

    #[test]
    fn test_python_detect_operations() {
        let sm = FileStateMachine::for_language(Language::Python);

        assert_eq!(
            sm.detect_operation("open('file.txt')"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("io.open('file.txt')"),
            Some(FileOperation::Open)
        );
        assert_eq!(sm.detect_operation("f.read()"), Some(FileOperation::Read));
        assert_eq!(
            sm.detect_operation("f.write('data')"),
            Some(FileOperation::Write)
        );
        assert_eq!(sm.detect_operation("f.close()"), Some(FileOperation::Close));
    }

    #[test]
    fn test_python_safe_context() {
        let sm = FileStateMachine::for_language(Language::Python);

        assert!(sm.is_safe_context("with open('file.txt') as f:"));
        assert!(sm.is_safe_context("async with aiofiles.open('file.txt') as f:"));
        assert!(!sm.is_safe_context("f = open('file.txt')"));
    }

    // =========================================================================
    // Go Tests
    // =========================================================================

    #[test]
    fn test_go_detect_operations() {
        let sm = FileStateMachine::for_language(Language::Go);

        assert_eq!(
            sm.detect_operation("os.Open(\"file.txt\")"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("os.Create(\"file.txt\")"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("os.OpenFile(\"file.txt\", os.O_RDWR, 0644)"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("f.Read(buf)"),
            Some(FileOperation::Read)
        );
        assert_eq!(
            sm.detect_operation("f.Write(data)"),
            Some(FileOperation::Write)
        );
        assert_eq!(sm.detect_operation("f.Close()"), Some(FileOperation::Close));
    }

    #[test]
    fn test_go_safe_context() {
        let sm = FileStateMachine::for_language(Language::Go);

        assert!(sm.is_safe_context("defer f.Close()"));
        assert!(sm.is_safe_context("defer file.Close()"));
        assert!(!sm.is_safe_context("f.Close()"));
    }

    // =========================================================================
    // Rust Tests
    // =========================================================================

    #[test]
    fn test_rust_detect_operations() {
        let sm = FileStateMachine::for_language(Language::Rust);

        assert_eq!(
            sm.detect_operation("File::open(\"file.txt\")"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("File::create(\"file.txt\")"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("file.read(&mut buffer)"),
            Some(FileOperation::Read)
        );
        assert_eq!(
            sm.detect_operation("file.read_to_string(&mut contents)"),
            Some(FileOperation::Read)
        );
        assert_eq!(
            sm.detect_operation("file.write(data)"),
            Some(FileOperation::Write)
        );
        assert_eq!(
            sm.detect_operation("file.write_all(data)"),
            Some(FileOperation::Write)
        );
    }

    #[test]
    fn test_rust_safe_context() {
        let sm = FileStateMachine::for_language(Language::Rust);

        // Rust uses RAII, so scope exit is safe
        assert!(sm.is_safe_context("}"));
        assert!(sm.is_safe_context("file?"));
    }

    // =========================================================================
    // Java Tests
    // =========================================================================

    #[test]
    fn test_java_detect_operations() {
        let sm = FileStateMachine::for_language(Language::Java);

        assert_eq!(
            sm.detect_operation("new FileInputStream(\"file.txt\")"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("new FileOutputStream(\"file.txt\")"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("new BufferedReader(reader)"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("Files.newInputStream(path)"),
            Some(FileOperation::Open)
        );
        assert_eq!(
            sm.detect_operation("reader.read()"),
            Some(FileOperation::Read)
        );
        assert_eq!(
            sm.detect_operation("reader.readLine()"),
            Some(FileOperation::Read)
        );
        assert_eq!(
            sm.detect_operation("writer.write(data)"),
            Some(FileOperation::Write)
        );
        assert_eq!(
            sm.detect_operation("stream.close()"),
            Some(FileOperation::Close)
        );
    }

    #[test]
    fn test_java_safe_context() {
        let sm = FileStateMachine::for_language(Language::Java);

        assert!(sm.is_safe_context("try (FileInputStream fis = new FileInputStream(\"file\"))"));
        assert!(sm.is_safe_context("implements AutoCloseable"));
        assert!(!sm.is_safe_context("FileInputStream fis = new FileInputStream(\"file\")"));
    }

    // =========================================================================
    // Rule Tests
    // =========================================================================

    #[test]
    fn test_file_typestate_rule_applies_to_languages() {
        let rule = FileTypestateRule;

        assert!(rule.applies_to(Language::JavaScript));
        assert!(rule.applies_to(Language::TypeScript));
        assert!(rule.applies_to(Language::Python));
        assert!(rule.applies_to(Language::Go));
        assert!(rule.applies_to(Language::Java));
        // Rust uses RAII, so we don't apply this rule by default
        assert!(!rule.applies_to(Language::Rust));
    }

    #[test]
    fn test_file_typestate_rule_id() {
        let rule = FileTypestateRule;
        assert_eq!(rule.id(), "generic/file-typestate");
    }

    #[test]
    fn test_file_typestate_rule_uses_flow() {
        let rule = FileTypestateRule;
        assert!(rule.uses_flow());
    }

    // =========================================================================
    // Violation Message Tests
    // =========================================================================

    #[test]
    fn test_violation_messages() {
        let use_error = ViolationType::UseInErrorState {
            operation: FileOperation::Read,
            resource: "file".to_string(),
            line: 10,
        };
        assert!(use_error.message().contains("closed resource"));
        assert!(use_error.message().contains("file"));

        let double_open = ViolationType::InvalidTransition {
            operation: FileOperation::Open,
            from_state: FileState::Open,
            resource: "handle".to_string(),
            line: 20,
        };
        assert!(double_open.message().contains("already open"));
        assert!(double_open.message().contains("Double-open"));

        let leak = ViolationType::NonFinalStateAtExit {
            state: FileState::Open,
            resource: "stream".to_string(),
            acquisition_line: 5,
        };
        assert!(leak.message().contains("may not be closed"));
        assert!(leak.message().contains("resource leak"));
    }

    #[test]
    fn test_violation_severity() {
        let use_error = ViolationType::UseInErrorState {
            operation: FileOperation::Read,
            resource: "file".to_string(),
            line: 10,
        };
        assert_eq!(use_error.severity(), Severity::Error);

        let invalid = ViolationType::InvalidTransition {
            operation: FileOperation::Open,
            from_state: FileState::Open,
            resource: "file".to_string(),
            line: 10,
        };
        assert_eq!(invalid.severity(), Severity::Warning);

        let leak = ViolationType::NonFinalStateAtExit {
            state: FileState::Open,
            resource: "file".to_string(),
            acquisition_line: 5,
        };
        assert_eq!(leak.severity(), Severity::Warning);
    }

    // =========================================================================
    // Suggestion Tests
    // =========================================================================

    #[test]
    fn test_suggestions_by_language() {
        let rule = FileTypestateRule;
        let leak = ViolationType::NonFinalStateAtExit {
            state: FileState::Open,
            resource: "file".to_string(),
            acquisition_line: 5,
        };

        let js_suggestion = rule.get_suggestion(Language::JavaScript, &leak);
        assert!(js_suggestion.contains("finally"));

        let py_suggestion = rule.get_suggestion(Language::Python, &leak);
        assert!(py_suggestion.contains("context manager"));

        let go_suggestion = rule.get_suggestion(Language::Go, &leak);
        assert!(go_suggestion.contains("defer"));

        let rust_suggestion = rule.get_suggestion(Language::Rust, &leak);
        assert!(rust_suggestion.contains("RAII"));

        let java_suggestion = rule.get_suggestion(Language::Java, &leak);
        assert!(java_suggestion.contains("try-with-resources"));
    }
}

// =============================================================================
// Lock Typestate Rule
// =============================================================================

/// Represents the state of a lock resource
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockState {
    /// Lock is available and not held
    Unlocked,
    /// Lock is currently held
    Locked,
    /// Double-lock error state
    DoubleLock,
    /// Double-unlock error state
    DoubleUnlock,
}

impl LockState {
    /// Check if this is a final (valid exit) state
    pub fn is_final(&self) -> bool {
        matches!(self, LockState::Unlocked)
    }
}

/// Operations that can be performed on a lock
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockOperation {
    /// Acquire the lock
    Lock,
    /// Release the lock
    Unlock,
    /// Try to acquire (non-blocking)
    TryLock,
}

/// Lock state machine for different languages
#[derive(Debug, Clone)]
pub struct LockStateMachine {
    /// Patterns that acquire the lock
    lock_patterns: Vec<&'static str>,
    /// Patterns that release the lock
    unlock_patterns: Vec<&'static str>,
    /// Patterns indicating safe contexts (defer, RAII, etc.)
    safe_patterns: Vec<&'static str>,
}

impl LockStateMachine {
    /// Create a lock state machine for a specific language
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self {
                lock_patterns: vec![".acquire(", ".lock(", "mutex.acquire(", "lock.acquire("],
                unlock_patterns: vec![".release(", ".unlock(", "mutex.release(", "lock.unlock("],
                safe_patterns: vec!["finally", ".finally(", "using"],
            },
            Language::Python => Self {
                lock_patterns: vec![".acquire(", "lock.acquire(", "Lock()"],
                unlock_patterns: vec![".release(", "lock.release("],
                safe_patterns: vec!["with ", "async with "],
            },
            Language::Go => Self {
                lock_patterns: vec![".Lock(", ".RLock(", "mutex.Lock(", "RWMutex.Lock("],
                unlock_patterns: vec![".Unlock(", ".RUnlock(", "mutex.Unlock("],
                safe_patterns: vec!["defer ", "defer m.Unlock(", "defer lock.Unlock("],
            },
            Language::Rust => Self {
                lock_patterns: vec![
                    ".lock()",
                    ".read()",
                    ".write()",
                    "Mutex::lock(",
                    "RwLock::read(",
                    "RwLock::write(",
                ],
                unlock_patterns: vec![
                    "drop(", // Rust locks are released via Drop
                ],
                safe_patterns: vec!["}", "?"], // RAII handles cleanup
            },
            Language::Java => Self {
                lock_patterns: vec![".lock()", ".tryLock(", "Lock.lock(", "synchronized("],
                unlock_patterns: vec![".unlock()"],
                safe_patterns: vec!["try (", "finally", "synchronized"],
            },
            _ => Self {
                lock_patterns: vec![],
                unlock_patterns: vec![],
                safe_patterns: vec![],
            },
        }
    }

    /// Detect lock/unlock operations in code
    pub fn detect_operation(&self, code: &str) -> Option<LockOperation> {
        for pattern in &self.unlock_patterns {
            if code.contains(pattern) {
                return Some(LockOperation::Unlock);
            }
        }
        for pattern in &self.lock_patterns {
            if code.contains(pattern) {
                return Some(LockOperation::Lock);
            }
        }
        None
    }

    /// Check if code is in a safe context
    pub fn is_safe_context(&self, code: &str) -> bool {
        self.safe_patterns.iter().any(|p| code.contains(p))
    }
}

/// Rule that detects lock resource typestate violations
pub struct LockTypestateRule;

impl LockTypestateRule {
    /// Get the lock state machine for a specific language
    pub fn state_machine(language: Language) -> LockStateMachine {
        LockStateMachine::for_language(language)
    }
}

impl Rule for LockTypestateRule {
    fn id(&self) -> &str {
        "generic/lock-typestate"
    }

    fn description(&self) -> &str {
        "Detects lock lifecycle violations: double-lock, double-unlock, unlock without lock"
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
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, _flow: &FlowContext) -> Vec<Finding> {
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        let sm = Self::state_machine(parsed.language);
        let mut findings = Vec::new();
        let mut state = LockState::Unlocked;
        let mut lock_line = 0usize;

        // Simple line-by-line analysis for lock patterns
        for (line_num, line) in parsed.content.lines().enumerate() {
            let line_num = line_num + 1;

            if sm.is_safe_context(line) {
                continue;
            }

            if let Some(op) = sm.detect_operation(line) {
                match (state, op) {
                    (LockState::Unlocked, LockOperation::Lock | LockOperation::TryLock) => {
                        state = LockState::Locked;
                        lock_line = line_num;
                    }
                    (LockState::Locked, LockOperation::Unlock) => {
                        state = LockState::Unlocked;
                    }
                    (LockState::Locked, LockOperation::Lock) => {
                        // Double lock
                        let mut finding = create_finding_at_line(
                            self.id(),
                            &parsed.path,
                            line_num,
                            line.trim(),
                            Severity::Warning,
                            &format!(
                                "Potential double-lock: lock already acquired at line {}",
                                lock_line
                            ),
                            parsed.language,
                        );
                        finding.confidence = Confidence::Medium;
                        finding.suggestion =
                            Some("Ensure the lock is released before re-acquiring.".to_string());
                        findings.push(finding);
                    }
                    (LockState::Unlocked, LockOperation::Unlock) => {
                        // Double unlock
                        let mut finding = create_finding_at_line(
                            self.id(),
                            &parsed.path,
                            line_num,
                            line.trim(),
                            Severity::Warning,
                            "Unlock called on already-unlocked lock",
                            parsed.language,
                        );
                        finding.confidence = Confidence::Medium;
                        finding.suggestion =
                            Some("Ensure the lock is acquired before releasing.".to_string());
                        findings.push(finding);
                    }
                    _ => {}
                }
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Crypto Typestate Rule
// =============================================================================
//
// This module implements comprehensive state machines for cryptographic API usage:
//
// ## Hash/Digest State Machine
// ```text
// States: Created -> Updating -> Finalized
//         Created is initial
//         Finalized is final
//
// Transitions:
//   Created --[update/write]--> Updating
//   Updating --[update/write]--> Updating
//   Updating --[digest/finalize]--> Finalized
//   Created --[digest/finalize]--> Finalized (empty hash)
//
// Violations:
//   - update() after Finalized (UseAfterFinalize)
//   - digest() after Finalized (DoubleFinalize)
// ```
//
// ## Cipher State Machine
// ```text
// States: Created -> Initialized -> Processing -> Finalized
//         Created is initial
//         Finalized is final
//
// Transitions:
//   Created --[init/setKey]--> Initialized
//   Initialized --[encrypt/decrypt]--> Processing
//   Processing --[encrypt/decrypt]--> Processing
//   Processing --[final]--> Finalized
//   Initialized --[final]--> Finalized (no data processed)
//
// Violations:
//   - encrypt/decrypt when Created (MissingInitialization)
//   - encrypt/decrypt after Finalized (UseAfterFinalize)
//   - final() after Finalized (DoubleFinalize)
// ```
// =============================================================================

/// Represents the state of a cryptographic object (hash, HMAC, or cipher)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoState {
    /// Object created but not yet initialized (cipher) or ready for input (hash)
    Created,
    /// Cipher is initialized with key/IV and ready for use
    Initialized,
    /// Hash/Cipher is processing data (update called)
    Processing,
    /// Object has been finalized (digest/final called)
    Finalized,
    /// Object is in an error state
    Error,
}

impl CryptoState {
    /// Check if this is an initial state
    pub fn is_initial(&self) -> bool {
        matches!(self, CryptoState::Created)
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, CryptoState::Finalized | CryptoState::Error)
    }

    /// Check if operations are valid in this state
    pub fn can_update(&self) -> bool {
        matches!(
            self,
            CryptoState::Created | CryptoState::Initialized | CryptoState::Processing
        )
    }

    /// Check if finalization is valid in this state
    pub fn can_finalize(&self) -> bool {
        matches!(
            self,
            CryptoState::Created | CryptoState::Initialized | CryptoState::Processing
        )
    }
}

impl std::fmt::Display for CryptoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoState::Created => write!(f, "Created"),
            CryptoState::Initialized => write!(f, "Initialized"),
            CryptoState::Processing => write!(f, "Processing"),
            CryptoState::Finalized => write!(f, "Finalized"),
            CryptoState::Error => write!(f, "Error"),
        }
    }
}

/// Type of cryptographic object being tracked
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoObjectType {
    /// Hash/Digest (SHA, MD5, etc.)
    Hash,
    /// HMAC (Hash-based Message Authentication Code)
    Hmac,
    /// Symmetric Cipher (AES, DES, etc.)
    Cipher,
}

impl std::fmt::Display for CryptoObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoObjectType::Hash => write!(f, "Hash"),
            CryptoObjectType::Hmac => write!(f, "HMAC"),
            CryptoObjectType::Cipher => write!(f, "Cipher"),
        }
    }
}

/// Type of crypto violation detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoViolationType {
    /// Using crypto object after finalization
    UseAfterFinalize,
    /// Finalizing crypto object twice
    DoubleFinalize,
    /// Using cipher without initialization (no key/IV)
    MissingInitialization,
    /// Using a weak algorithm (MD5, SHA1, DES, RC4)
    WeakAlgorithm,
    /// Using unsafe cipher mode (ECB)
    UnsafeMode,
    /// Reusing IV/nonce (detected in some cases)
    IvReuse,
}

impl std::fmt::Display for CryptoViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoViolationType::UseAfterFinalize => write!(f, "UseAfterFinalize"),
            CryptoViolationType::DoubleFinalize => write!(f, "DoubleFinalize"),
            CryptoViolationType::MissingInitialization => write!(f, "MissingInitialization"),
            CryptoViolationType::WeakAlgorithm => write!(f, "WeakAlgorithm"),
            CryptoViolationType::UnsafeMode => write!(f, "UnsafeMode"),
            CryptoViolationType::IvReuse => write!(f, "IvReuse"),
        }
    }
}

/// Crypto state machine for different languages
#[derive(Debug, Clone)]
pub struct CryptoStateMachine {
    /// Patterns that create hash objects
    hash_create: Vec<&'static str>,
    /// Patterns that create HMAC objects
    hmac_create: Vec<&'static str>,
    /// Patterns that create cipher objects
    cipher_create: Vec<&'static str>,
    /// Patterns that initialize ciphers (set key/IV)
    cipher_init: Vec<&'static str>,
    /// Patterns that update hash/cipher with data
    update_patterns: Vec<&'static str>,
    /// Patterns that finalize hash/cipher
    finalize_patterns: Vec<&'static str>,
    /// Patterns that reset hash/cipher for reuse
    reset_patterns: Vec<&'static str>,
    /// Weak algorithms: (pattern, algorithm_name, severity_reason)
    weak_algorithms: Vec<(&'static str, &'static str, &'static str)>,
    /// Unsafe modes: (pattern, mode_name, severity_reason)
    unsafe_modes: Vec<(&'static str, &'static str, &'static str)>,
}

impl CryptoStateMachine {
    /// Create a crypto state machine for a specific language
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self::javascript(),
            Language::Python => Self::python(),
            Language::Go => Self::go(),
            Language::Rust => Self::rust(),
            Language::Java => Self::java(),
            _ => Self::empty(),
        }
    }

    /// JavaScript/TypeScript crypto patterns
    fn javascript() -> Self {
        Self {
            hash_create: vec![
                "crypto.createHash(",
                "createHash(",
                "new SHA256(",
                "new SHA512(",
                "new MD5(",
                "CryptoJS.SHA256(",
                "CryptoJS.SHA512(",
                "CryptoJS.MD5(",
                "CryptoJS.SHA1(",
            ],
            hmac_create: vec![
                "crypto.createHmac(",
                "createHmac(",
                "CryptoJS.HmacSHA256(",
                "CryptoJS.HmacSHA512(",
            ],
            cipher_create: vec![
                "crypto.createCipher(",
                "crypto.createDecipher(",
                "crypto.createCipheriv(",
                "crypto.createDecipheriv(",
                "CryptoJS.AES.encrypt(",
                "CryptoJS.AES.decrypt(",
                "CryptoJS.DES.encrypt(",
                "CryptoJS.DES.decrypt(",
            ],
            cipher_init: vec![".setKey(", ".setAAD(", ".setAutoPadding("],
            update_patterns: vec![".update(", ".write("],
            finalize_patterns: vec![".digest(", ".final(", ".end("],
            reset_patterns: vec![".reset("],
            weak_algorithms: vec![
                (
                    "createHash('md5')",
                    "MD5",
                    "MD5 is cryptographically broken",
                ),
                (
                    "createHash(\"md5\")",
                    "MD5",
                    "MD5 is cryptographically broken",
                ),
                (
                    "createHash('sha1')",
                    "SHA1",
                    "SHA1 is deprecated for security use",
                ),
                (
                    "createHash(\"sha1\")",
                    "SHA1",
                    "SHA1 is deprecated for security use",
                ),
                ("CryptoJS.MD5(", "MD5", "MD5 is cryptographically broken"),
                (
                    "CryptoJS.SHA1(",
                    "SHA1",
                    "SHA1 is deprecated for security use",
                ),
                ("createCipher('des", "DES", "DES is cryptographically weak"),
                ("createCipher(\"des", "DES", "DES is cryptographically weak"),
                (
                    "createCipher('rc4",
                    "RC4",
                    "RC4 is cryptographically broken",
                ),
                (
                    "createCipher(\"rc4",
                    "RC4",
                    "RC4 is cryptographically broken",
                ),
            ],
            unsafe_modes: vec![
                (
                    "'aes-128-ecb'",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "\"aes-128-ecb\"",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "'aes-256-ecb'",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "\"aes-256-ecb\"",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "mode: CryptoJS.mode.ECB",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
            ],
        }
    }

    /// Python crypto patterns
    fn python() -> Self {
        Self {
            hash_create: vec![
                "hashlib.md5(",
                "hashlib.sha1(",
                "hashlib.sha256(",
                "hashlib.sha512(",
                "hashlib.new(",
                "MD5.new(",
                "SHA.new(",
                "SHA256.new(",
                "SHA512.new(",
            ],
            hmac_create: vec!["hmac.new(", "HMAC.new("],
            cipher_create: vec![
                "Cipher(",
                "AES.new(",
                "DES.new(",
                "DES3.new(",
                "Blowfish.new(",
                "ARC4.new(",
                "Fernet(",
            ],
            cipher_init: vec![
                // Python crypto usually initializes in constructor
            ],
            update_patterns: vec![".update("],
            finalize_patterns: vec![
                ".digest(",
                ".hexdigest(",
                ".finalize(",
                ".encrypt(",
                ".decrypt(",
            ],
            reset_patterns: vec![
                // Most Python crypto objects are not resettable
            ],
            weak_algorithms: vec![
                ("hashlib.md5(", "MD5", "MD5 is cryptographically broken"),
                ("MD5.new(", "MD5", "MD5 is cryptographically broken"),
                (
                    "hashlib.sha1(",
                    "SHA1",
                    "SHA1 is deprecated for security use",
                ),
                ("SHA.new(", "SHA1", "SHA1 is deprecated for security use"),
                ("DES.new(", "DES", "DES is cryptographically weak"),
                ("ARC4.new(", "RC4", "RC4 is cryptographically broken"),
            ],
            unsafe_modes: vec![
                (
                    "MODE_ECB",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "AES.MODE_ECB",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "DES.MODE_ECB",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
            ],
        }
    }

    /// Go crypto patterns
    fn go() -> Self {
        Self {
            hash_create: vec![
                "md5.New(",
                "sha1.New(",
                "sha256.New(",
                "sha512.New(",
                "sha256.New224(",
                "sha512.New384(",
            ],
            hmac_create: vec!["hmac.New("],
            cipher_create: vec![
                "aes.NewCipher(",
                "des.NewCipher(",
                "des.NewTripleDESCipher(",
                "rc4.NewCipher(",
            ],
            cipher_init: vec![
                "cipher.NewGCM(",
                "cipher.NewCBCEncrypter(",
                "cipher.NewCBCDecrypter(",
                "cipher.NewCTR(",
                "cipher.NewOFB(",
                "cipher.NewCFBEncrypter(",
                "cipher.NewCFBDecrypter(",
            ],
            update_patterns: vec![".Write("],
            finalize_patterns: vec![
                ".Sum(",
                ".Seal(",
                ".Open(",
                ".XORKeyStream(",
                ".CryptBlocks(",
            ],
            reset_patterns: vec![".Reset("],
            weak_algorithms: vec![
                ("md5.New(", "MD5", "MD5 is cryptographically broken"),
                ("md5.Sum(", "MD5", "MD5 is cryptographically broken"),
                ("sha1.New(", "SHA1", "SHA1 is deprecated for security use"),
                ("sha1.Sum(", "SHA1", "SHA1 is deprecated for security use"),
                ("des.NewCipher(", "DES", "DES is cryptographically weak"),
                ("rc4.NewCipher(", "RC4", "RC4 is cryptographically broken"),
            ],
            unsafe_modes: vec![
                // Go doesn't have a direct ECB mode, but CryptBlocks without proper mode is ECB
                (
                    "NewECBEncrypter(",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "NewECBDecrypter(",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
            ],
        }
    }

    /// Rust crypto patterns
    fn rust() -> Self {
        Self {
            hash_create: vec![
                "Md5::new(",
                "Sha1::new(",
                "Sha256::new(",
                "Sha512::new(",
                "Sha224::new(",
                "Sha384::new(",
                "Digest::new(",
            ],
            hmac_create: vec!["Hmac::new(", "HmacSha256::new(", "HmacSha512::new("],
            cipher_create: vec![
                "Aes128::new(",
                "Aes256::new(",
                "Des::new(",
                "Aes128Gcm::new(",
                "Aes256Gcm::new(",
                "ChaCha20Poly1305::new(",
            ],
            cipher_init: vec![
                // Rust crypto usually initializes in constructor
            ],
            update_patterns: vec![".update(", ".chain("],
            finalize_patterns: vec![
                ".finalize(",
                ".finalize_reset(",
                ".result(",
                ".encrypt(",
                ".decrypt(",
            ],
            reset_patterns: vec![".reset(", ".finalize_reset("],
            weak_algorithms: vec![
                ("Md5::new(", "MD5", "MD5 is cryptographically broken"),
                ("Sha1::new(", "SHA1", "SHA1 is deprecated for security use"),
                ("Des::new(", "DES", "DES is cryptographically weak"),
            ],
            unsafe_modes: vec![
                (
                    "Ecb::",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "ecb::",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
            ],
        }
    }

    /// Java crypto patterns
    fn java() -> Self {
        Self {
            hash_create: vec![
                "MessageDigest.getInstance(",
                "DigestUtils.md5(",
                "DigestUtils.sha1(",
                "DigestUtils.sha256(",
            ],
            hmac_create: vec!["Mac.getInstance("],
            cipher_create: vec!["Cipher.getInstance(", "SecretKeySpec("],
            cipher_init: vec![".init("],
            update_patterns: vec![".update("],
            finalize_patterns: vec![".digest(", ".doFinal("],
            reset_patterns: vec![".reset("],
            weak_algorithms: vec![
                ("\"MD5\"", "MD5", "MD5 is cryptographically broken"),
                ("\"SHA-1\"", "SHA1", "SHA1 is deprecated for security use"),
                ("\"SHA1\"", "SHA1", "SHA1 is deprecated for security use"),
                ("\"DES\"", "DES", "DES is cryptographically weak"),
                ("\"RC4\"", "RC4", "RC4 is cryptographically broken"),
                ("\"ARCFOUR\"", "RC4", "RC4 is cryptographically broken"),
                ("DigestUtils.md5(", "MD5", "MD5 is cryptographically broken"),
                (
                    "DigestUtils.sha1(",
                    "SHA1",
                    "SHA1 is deprecated for security use",
                ),
            ],
            unsafe_modes: vec![
                (
                    "\"AES/ECB/",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "\"DES/ECB/",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
                (
                    "\"/ECB/\"",
                    "ECB",
                    "ECB mode is deterministic and leaks patterns",
                ),
            ],
        }
    }

    /// Empty crypto state machine for unsupported languages
    fn empty() -> Self {
        Self {
            hash_create: vec![],
            hmac_create: vec![],
            cipher_create: vec![],
            cipher_init: vec![],
            update_patterns: vec![],
            finalize_patterns: vec![],
            reset_patterns: vec![],
            weak_algorithms: vec![],
            unsafe_modes: vec![],
        }
    }

    /// Check if code creates a hash object
    pub fn is_hash_creation(&self, code: &str) -> bool {
        self.hash_create.iter().any(|p| code.contains(p))
    }

    /// Check if code creates an HMAC object
    pub fn is_hmac_creation(&self, code: &str) -> bool {
        self.hmac_create.iter().any(|p| code.contains(p))
    }

    /// Check if code creates a cipher object
    pub fn is_cipher_creation(&self, code: &str) -> bool {
        self.cipher_create.iter().any(|p| code.contains(p))
    }

    /// Check if code creates any crypto object
    pub fn is_creation(&self, code: &str) -> Option<CryptoObjectType> {
        if self.is_hash_creation(code) {
            Some(CryptoObjectType::Hash)
        } else if self.is_hmac_creation(code) {
            Some(CryptoObjectType::Hmac)
        } else if self.is_cipher_creation(code) {
            Some(CryptoObjectType::Cipher)
        } else {
            None
        }
    }

    /// Check if code initializes a cipher (sets key/IV)
    pub fn is_init(&self, code: &str) -> bool {
        self.cipher_init.iter().any(|p| code.contains(p))
    }

    /// Check if code updates hash/cipher with data
    pub fn is_update(&self, code: &str) -> bool {
        self.update_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code finalizes hash/cipher
    pub fn is_finalize(&self, code: &str) -> bool {
        self.finalize_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code resets the hash/cipher
    pub fn is_reset(&self, code: &str) -> bool {
        self.reset_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code uses a weak algorithm
    pub fn uses_weak_algorithm(&self, code: &str) -> Option<(&'static str, &'static str)> {
        for (pattern, name, reason) in &self.weak_algorithms {
            if code.contains(pattern) {
                return Some((name, reason));
            }
        }
        None
    }

    /// Check if code uses an unsafe mode
    pub fn uses_unsafe_mode(&self, code: &str) -> Option<(&'static str, &'static str)> {
        for (pattern, name, reason) in &self.unsafe_modes {
            if code.contains(pattern) {
                return Some((name, reason));
            }
        }
        None
    }
}

/// Tracked crypto object instance
#[derive(Debug, Clone)]
struct TrackedCryptoObject {
    /// Type of crypto object
    object_type: CryptoObjectType,
    /// Current state
    state: CryptoState,
    /// Line where object was created
    creation_line: usize,
    /// Line where object was last finalized (if any)
    finalize_line: Option<usize>,
}

/// Rule that detects cryptographic API state violations and misuse patterns
pub struct CryptoTypestateRule;

impl CryptoTypestateRule {
    /// Get the crypto state machine for a specific language
    pub fn state_machine(language: Language) -> CryptoStateMachine {
        CryptoStateMachine::for_language(language)
    }
}

impl Rule for CryptoTypestateRule {
    fn id(&self) -> &str {
        "generic/crypto-typestate"
    }

    fn description(&self) -> &str {
        "Detects cryptographic API misuse including state violations, weak algorithms, and unsafe modes"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Rust
                | Language::Java
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, _flow: &FlowContext) -> Vec<Finding> {
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        let sm = Self::state_machine(parsed.language);
        let mut findings = Vec::new();
        let mut tracked_object: Option<TrackedCryptoObject> = None;

        for (line_num, line) in parsed.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for weak algorithms (Warning severity)
            if let Some((algo_name, reason)) = sm.uses_weak_algorithm(line) {
                let mut finding = create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num,
                    line.trim(),
                    Severity::Warning,
                    &format!("Weak cryptographic algorithm '{}': {}", algo_name, reason),
                    parsed.language,
                );
                finding.confidence = Confidence::High;
                finding.suggestion = Some(format!(
                    "Replace {} with a stronger algorithm (e.g., SHA-256 for hashing, AES-256-GCM for encryption).",
                    algo_name
                ));
                findings.push(finding);
            }

            // Check for unsafe modes (Error severity)
            if let Some((mode_name, reason)) = sm.uses_unsafe_mode(line) {
                let mut finding = create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num,
                    line.trim(),
                    Severity::Error,
                    &format!("Unsafe cipher mode '{}': {}", mode_name, reason),
                    parsed.language,
                );
                finding.confidence = Confidence::High;
                finding.suggestion = Some(
                    "Use authenticated encryption modes like GCM or CBC with HMAC.".to_string(),
                );
                findings.push(finding);
            }

            // Track crypto object state
            if let Some(object_type) = sm.is_creation(line) {
                // New crypto object created
                let initial_state = match object_type {
                    CryptoObjectType::Hash | CryptoObjectType::Hmac => CryptoState::Created,
                    CryptoObjectType::Cipher => CryptoState::Created,
                };
                tracked_object = Some(TrackedCryptoObject {
                    object_type,
                    state: initial_state,
                    creation_line: line_num,
                    finalize_line: None,
                });
            } else if let Some(ref mut obj) = tracked_object {
                // Check state transitions
                if sm.is_init(line) {
                    if obj.object_type == CryptoObjectType::Cipher {
                        obj.state = CryptoState::Initialized;
                    }
                } else if sm.is_update(line) {
                    match obj.state {
                        CryptoState::Finalized => {
                            // Update after finalize - Error
                            let mut finding = create_finding_at_line(
                                self.id(),
                                &parsed.path,
                                line_num,
                                line.trim(),
                                Severity::Error,
                                &format!(
                                    "{} updated after finalization (finalized at line {})",
                                    obj.object_type,
                                    obj.finalize_line.unwrap_or(0)
                                ),
                                parsed.language,
                            );
                            finding.confidence = Confidence::High;
                            finding.suggestion = Some(format!(
                                "Create a new {} object instead of reusing a finalized one.",
                                obj.object_type
                            ));
                            findings.push(finding);
                        }
                        CryptoState::Created if obj.object_type == CryptoObjectType::Cipher => {
                            // Cipher used without initialization - Critical
                            let mut finding = create_finding_at_line(
                                self.id(),
                                &parsed.path,
                                line_num,
                                line.trim(),
                                Severity::Critical,
                                &format!(
                                    "Cipher used without initialization (created at line {})",
                                    obj.creation_line
                                ),
                                parsed.language,
                            );
                            finding.confidence = Confidence::High;
                            finding.suggestion = Some(
                                "Initialize the cipher with a key and IV before encrypting/decrypting.".to_string(),
                            );
                            findings.push(finding);
                        }
                        _ => {
                            obj.state = CryptoState::Processing;
                        }
                    }
                } else if sm.is_finalize(line) {
                    match obj.state {
                        CryptoState::Finalized => {
                            // Double finalization - Error
                            let mut finding = create_finding_at_line(
                                self.id(),
                                &parsed.path,
                                line_num,
                                line.trim(),
                                Severity::Error,
                                &format!(
                                    "{} finalized twice (first at line {})",
                                    obj.object_type,
                                    obj.finalize_line.unwrap_or(0)
                                ),
                                parsed.language,
                            );
                            finding.confidence = Confidence::High;
                            finding.suggestion = Some(format!(
                                "Create a new {} object for each finalization.",
                                obj.object_type
                            ));
                            findings.push(finding);
                        }
                        CryptoState::Created if obj.object_type == CryptoObjectType::Cipher => {
                            // Cipher finalized without initialization - Critical
                            let mut finding = create_finding_at_line(
                                self.id(),
                                &parsed.path,
                                line_num,
                                line.trim(),
                                Severity::Critical,
                                &format!(
                                    "Cipher finalized without initialization (created at line {})",
                                    obj.creation_line
                                ),
                                parsed.language,
                            );
                            finding.confidence = Confidence::High;
                            finding.suggestion = Some(
                                "Initialize the cipher with a key and IV before finalizing."
                                    .to_string(),
                            );
                            findings.push(finding);
                        }
                        _ => {
                            obj.state = CryptoState::Finalized;
                            obj.finalize_line = Some(line_num);
                        }
                    }
                } else if sm.is_reset(line) {
                    // Reset brings object back to Created/Initialized state
                    obj.state = match obj.object_type {
                        CryptoObjectType::Cipher => CryptoState::Initialized,
                        _ => CryptoState::Created,
                    };
                    obj.finalize_line = None;
                }
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Database Typestate Rule
// =============================================================================

/// Represents the state of a database connection
///
/// State Machine:
/// ```text
/// States: Disconnected -> Connected -> InTransaction -> Committed/RolledBack -> Connected -> Closed
///         Disconnected is initial
///         Closed is final
///
/// Transitions:
///   Disconnected --[connect/open]--> Connected
///   Connected --[begin/startTransaction]--> InTransaction
///   InTransaction --[commit]--> Connected
///   InTransaction --[rollback]--> Connected
///   InTransaction --[query/execute]--> InTransaction
///   Connected --[query/execute]--> Connected
///   Connected --[close/disconnect]--> Closed
///
/// Violations:
///   - query when Disconnected (UseInErrorState)
///   - commit/rollback when not InTransaction (InvalidTransactionOp)
///   - close when InTransaction (UncommittedTransaction)
///   - exit when Connected without close (ConnectionLeak)
///   - begin when already InTransaction (NestedTransaction - error in some DBs)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatabaseState {
    /// Connection not established
    Disconnected,
    /// Connection is open and ready for operations
    Connected,
    /// In an active transaction
    InTransaction,
    /// Connection is closed
    Closed,
    /// Connection is in an error state (requires reconnect or rollback)
    Error,
}

impl DatabaseState {
    /// Check if this is a final state
    pub fn is_final(&self) -> bool {
        matches!(self, DatabaseState::Disconnected | DatabaseState::Closed)
    }

    /// Check if this is an initial state
    pub fn is_initial(&self) -> bool {
        matches!(self, DatabaseState::Disconnected)
    }

    /// Check if queries can be executed in this state
    pub fn can_query(&self) -> bool {
        matches!(
            self,
            DatabaseState::Connected | DatabaseState::InTransaction
        )
    }

    /// Check if transaction operations are valid in this state
    pub fn can_transact(&self) -> bool {
        matches!(self, DatabaseState::InTransaction)
    }
}

impl std::fmt::Display for DatabaseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseState::Disconnected => write!(f, "Disconnected"),
            DatabaseState::Connected => write!(f, "Connected"),
            DatabaseState::InTransaction => write!(f, "InTransaction"),
            DatabaseState::Closed => write!(f, "Closed"),
            DatabaseState::Error => write!(f, "Error"),
        }
    }
}

/// Type of database action detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseAction {
    /// Open/establish a connection
    Connect,
    /// Begin a transaction
    BeginTransaction,
    /// Execute a query
    Query,
    /// Commit the current transaction
    Commit,
    /// Rollback the current transaction
    Rollback,
    /// Close the connection
    Close,
}

impl std::fmt::Display for DatabaseAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseAction::Connect => write!(f, "connect"),
            DatabaseAction::BeginTransaction => write!(f, "begin transaction"),
            DatabaseAction::Query => write!(f, "query"),
            DatabaseAction::Commit => write!(f, "commit"),
            DatabaseAction::Rollback => write!(f, "rollback"),
            DatabaseAction::Close => write!(f, "close"),
        }
    }
}

/// Type of database state violation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseViolation {
    /// Query/operation on a disconnected or closed connection
    UseInErrorState {
        action: DatabaseAction,
        current_state: DatabaseState,
    },
    /// Commit/rollback when not in a transaction
    InvalidTransactionOp { action: DatabaseAction },
    /// Closing connection while transaction is active
    UncommittedTransaction { transaction_started_line: usize },
    /// Function exits without closing connection
    ConnectionLeak { connect_line: usize },
    /// Starting transaction when already in one
    NestedTransaction { outer_transaction_line: usize },
    /// Query on closed connection
    QueryAfterClose { close_line: usize },
    /// Double close
    DoubleClose { first_close_line: usize },
}

impl std::fmt::Display for DatabaseViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseViolation::UseInErrorState {
                action,
                current_state,
            } => {
                write!(
                    f,
                    "Cannot {} when connection is in {} state",
                    action, current_state
                )
            }
            DatabaseViolation::InvalidTransactionOp { action } => {
                write!(f, "Cannot {} when not in a transaction", action)
            }
            DatabaseViolation::UncommittedTransaction {
                transaction_started_line,
            } => {
                write!(
                    f,
                    "Connection closed with uncommitted transaction (started at line {})",
                    transaction_started_line
                )
            }
            DatabaseViolation::ConnectionLeak { connect_line } => {
                write!(
                    f,
                    "Connection opened at line {} may not be closed",
                    connect_line
                )
            }
            DatabaseViolation::NestedTransaction {
                outer_transaction_line,
            } => {
                write!(
                    f,
                    "Cannot start nested transaction (outer transaction at line {})",
                    outer_transaction_line
                )
            }
            DatabaseViolation::QueryAfterClose { close_line } => {
                write!(
                    f,
                    "Query executed after connection was closed at line {}",
                    close_line
                )
            }
            DatabaseViolation::DoubleClose { first_close_line } => {
                write!(f, "Connection already closed at line {}", first_close_line)
            }
        }
    }
}

/// Database state machine for different languages
#[derive(Debug, Clone)]
pub struct DatabaseStateMachine {
    /// Patterns that establish connections
    connect_patterns: Vec<&'static str>,
    /// Patterns that execute queries (require connection)
    query_patterns: Vec<&'static str>,
    /// Patterns that begin transactions
    begin_patterns: Vec<&'static str>,
    /// Patterns that commit transactions
    commit_patterns: Vec<&'static str>,
    /// Patterns that rollback transactions
    rollback_patterns: Vec<&'static str>,
    /// Patterns that close connections
    close_patterns: Vec<&'static str>,
    /// Safe patterns (context managers, defer, try-with-resources)
    safe_patterns: Vec<&'static str>,
}

impl DatabaseStateMachine {
    /// Create a database state machine for a specific language
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self::javascript_patterns(),
            Language::Python => Self::python_patterns(),
            Language::Go => Self::go_patterns(),
            Language::Java => Self::java_patterns(),
            Language::Rust => Self::rust_patterns(),
            _ => Self::empty(),
        }
    }

    /// JavaScript/TypeScript database patterns (including Sequelize ORM)
    fn javascript_patterns() -> Self {
        Self {
            connect_patterns: vec![
                // Node.js mysql/mysql2
                "createConnection(",
                "createPool(",
                ".getConnection(",
                // Node.js pg (postgres)
                "new Client(",
                "new Pool(",
                ".connect(",
                // MongoDB
                "MongoClient.connect(",
                "mongoose.connect(",
                // Sequelize ORM
                "new Sequelize(",
                "sequelize.authenticate(",
                // Prisma
                "new PrismaClient(",
                // Generic
                "createClient(",
                "getConnection(",
            ],
            query_patterns: vec![
                ".query(",
                ".execute(",
                ".run(",
                // Note: .find( is NOT included because it conflicts with Array.prototype.find()
                // Use more specific ORM patterns instead
                ".findOne(",
                ".findMany(",
                ".findById(",
                ".findUnique(",
                ".findFirst(",
                ".insertOne(",
                ".insertMany(",
                ".updateOne(",
                ".updateMany(",
                ".deleteOne(",
                ".deleteMany(",
                ".aggregate(",
                ".exec(",
                // Sequelize
                ".findAll(",
                ".findByPk(",
                ".findOrCreate(",
                ".create(",
                ".bulkCreate(",
                ".update(",
                ".destroy(",
                // Prisma
                ".$queryRaw(",
                ".$executeRaw(",
                // MongoDB specific (collection methods)
                "collection.find(",
                ".collection(",
            ],
            begin_patterns: vec![
                ".beginTransaction(",
                ".begin(",
                ".startTransaction(",
                // Sequelize
                "sequelize.transaction(",
                // Prisma
                ".$transaction(",
            ],
            commit_patterns: vec![".commit("],
            rollback_patterns: vec![".rollback(", ".abortTransaction("],
            close_patterns: vec![".close(", ".end(", ".destroy(", ".disconnect(", ".release("],
            safe_patterns: vec![
                // Promise-based transaction patterns
                ".transaction(async",
                "transaction((",
                ".transaction(t =>",
                // Auto-release pool patterns
                "pool.query(",
            ],
        }
    }

    /// Python database patterns (including SQLAlchemy ORM)
    fn python_patterns() -> Self {
        Self {
            connect_patterns: vec![
                // Standard DB-API
                ".connect(",
                "psycopg2.connect(",
                "mysql.connector.connect(",
                "sqlite3.connect(",
                "pymysql.connect(",
                // SQLAlchemy
                "create_engine(",
                "sessionmaker(",
                "Session(",
                "scoped_session(",
                // asyncpg
                "asyncpg.connect(",
                "asyncpg.create_pool(",
                // MongoDB
                "MongoClient(",
                "motor.motor_asyncio.AsyncIOMotorClient(",
            ],
            query_patterns: vec![
                ".execute(",
                ".executemany(",
                ".cursor(",
                ".fetchone(",
                ".fetchall(",
                ".fetchmany(",
                // SQLAlchemy
                ".query(",
                ".add(",
                ".delete(",
                ".filter(",
                ".scalar(",
                ".all(",
                ".first(",
            ],
            begin_patterns: vec![".begin(", ".begin_nested("],
            commit_patterns: vec![".commit("],
            rollback_patterns: vec![".rollback("],
            close_patterns: vec![".close(", ".dispose("],
            safe_patterns: vec![
                // Context managers
                "with engine.connect()",
                "with Session(",
                "with session:",
                "with connection:",
                "async with",
                // SQLAlchemy session scope
                "session_scope(",
            ],
        }
    }

    /// Go database patterns (including GORM)
    fn go_patterns() -> Self {
        Self {
            connect_patterns: vec![
                // Standard library
                "sql.Open(",
                "sqlx.Open(",
                "sqlx.Connect(",
                // GORM
                "gorm.Open(",
                "db.Open(",
                // MongoDB
                "mongo.Connect(",
                "mongo.NewClient(",
            ],
            query_patterns: vec![
                // Standard library
                ".Query(",
                ".QueryRow(",
                ".QueryContext(",
                ".Exec(",
                ".ExecContext(",
                ".Prepare(",
                ".PrepareContext(",
                // GORM
                ".Find(",
                ".First(",
                ".Create(",
                ".Save(",
                ".Update(",
                ".Delete(",
                ".Where(",
                ".Raw(",
            ],
            begin_patterns: vec![
                ".Begin(",
                ".BeginTx(",
                // GORM
                ".Transaction(",
            ],
            commit_patterns: vec![".Commit("],
            rollback_patterns: vec![".Rollback("],
            close_patterns: vec![".Close("],
            safe_patterns: vec![
                // Deferred close
                "defer db.Close()",
                "defer conn.Close()",
                "defer tx.Rollback()",
                // GORM transaction callback
                ".Transaction(func(",
            ],
        }
    }

    /// Java database patterns (including Hibernate ORM)
    fn java_patterns() -> Self {
        Self {
            connect_patterns: vec![
                // JDBC
                "DriverManager.getConnection(",
                "DataSource.getConnection(",
                ".getConnection(",
                // JPA/Hibernate
                "EntityManagerFactory.createEntityManager(",
                "sessionFactory.openSession(",
                "sessionFactory.getCurrentSession(",
                // Spring
                "JdbcTemplate(",
                "NamedParameterJdbcTemplate(",
            ],
            query_patterns: vec![
                // JDBC
                ".executeQuery(",
                ".executeUpdate(",
                ".execute(",
                ".prepareStatement(",
                ".prepareCall(",
                // JPA/Hibernate
                ".createQuery(",
                ".createNativeQuery(",
                ".find(",
                ".persist(",
                ".merge(",
                ".remove(",
                ".getResultList(",
                ".getSingleResult(",
                // Spring JdbcTemplate
                ".queryForObject(",
                ".queryForList(",
                ".update(",
            ],
            begin_patterns: vec![
                ".setAutoCommit(false)",
                ".beginTransaction(",
                ".getTransaction().begin(",
            ],
            commit_patterns: vec![".commit()"],
            rollback_patterns: vec![".rollback()"],
            close_patterns: vec![".close("],
            safe_patterns: vec![
                // Try-with-resources
                "try (Connection",
                "try (PreparedStatement",
                "try (ResultSet",
                "try (Session",
                // Spring @Transactional
                "@Transactional",
                // JPA transaction management
                "em.getTransaction()",
            ],
        }
    }

    /// Rust database patterns
    fn rust_patterns() -> Self {
        Self {
            connect_patterns: vec![
                // sqlx
                "Pool::connect(",
                "PgPool::connect(",
                "MySqlPool::connect(",
                "SqlitePool::connect(",
                // diesel
                "establish_connection(",
                "PgConnection::establish(",
                "MysqlConnection::establish(",
                "SqliteConnection::establish(",
                // tokio-postgres
                "connect(",
                "Client::connect(",
                // mongodb
                "Client::with_uri_str(",
            ],
            query_patterns: vec![
                // sqlx
                ".fetch_one(",
                ".fetch_all(",
                ".fetch_optional(",
                ".execute(",
                "sqlx::query(",
                // diesel
                ".load::<",
                ".get_result(",
                ".first::<",
                "diesel::insert_into(",
                "diesel::update(",
                "diesel::delete(",
                // General
                ".query(",
                ".batch_execute(",
            ],
            begin_patterns: vec![".begin()", ".transaction(", "conn.transaction("],
            commit_patterns: vec![".commit()"],
            rollback_patterns: vec![".rollback("],
            close_patterns: vec![
                // Rust uses Drop, but explicit close exists
                ".close()", "drop(",
            ],
            safe_patterns: vec![
                // RAII - Drop handles cleanup
                "Pool<",
                "PoolConnection<",
                // Transaction closures
                ".transaction(|",
                ".transaction(async |",
                // Scoped connections
                "web::Data<Pool",
            ],
        }
    }

    /// Empty patterns for unsupported languages
    fn empty() -> Self {
        Self {
            connect_patterns: vec![],
            query_patterns: vec![],
            begin_patterns: vec![],
            commit_patterns: vec![],
            rollback_patterns: vec![],
            close_patterns: vec![],
            safe_patterns: vec![],
        }
    }

    /// Check if code establishes a connection
    pub fn is_connect(&self, code: &str) -> bool {
        self.connect_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code executes a query
    pub fn is_query(&self, code: &str) -> bool {
        self.query_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code begins a transaction
    pub fn is_begin_transaction(&self, code: &str) -> bool {
        self.begin_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code commits a transaction
    pub fn is_commit(&self, code: &str) -> bool {
        self.commit_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code rolls back a transaction
    pub fn is_rollback(&self, code: &str) -> bool {
        self.rollback_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code closes a connection
    pub fn is_close(&self, code: &str) -> bool {
        self.close_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code uses a safe pattern (context manager, defer, try-with-resources)
    pub fn is_safe_pattern(&self, code: &str) -> bool {
        self.safe_patterns.iter().any(|p| code.contains(p))
    }

    /// Detect the action being performed
    pub fn detect_action(&self, code: &str) -> Option<DatabaseAction> {
        if self.is_connect(code) {
            Some(DatabaseAction::Connect)
        } else if self.is_begin_transaction(code) {
            Some(DatabaseAction::BeginTransaction)
        } else if self.is_commit(code) {
            Some(DatabaseAction::Commit)
        } else if self.is_rollback(code) {
            Some(DatabaseAction::Rollback)
        } else if self.is_close(code) {
            Some(DatabaseAction::Close)
        } else if self.is_query(code) {
            Some(DatabaseAction::Query)
        } else {
            None
        }
    }

    /// Apply a state transition and return the new state or a violation
    #[allow(dead_code)]
    pub fn transition(
        &self,
        current: DatabaseState,
        action: DatabaseAction,
        _code: &str,
    ) -> Result<DatabaseState, DatabaseViolation> {
        match (current, action) {
            // Connect transitions
            (DatabaseState::Disconnected, DatabaseAction::Connect) => Ok(DatabaseState::Connected),
            (DatabaseState::Closed, DatabaseAction::Connect) => Ok(DatabaseState::Connected),

            // Begin transaction
            (DatabaseState::Connected, DatabaseAction::BeginTransaction) => {
                Ok(DatabaseState::InTransaction)
            }
            (DatabaseState::InTransaction, DatabaseAction::BeginTransaction) => {
                Err(DatabaseViolation::NestedTransaction {
                    outer_transaction_line: 0,
                })
            }

            // Query operations
            (DatabaseState::Connected, DatabaseAction::Query) => Ok(DatabaseState::Connected),
            (DatabaseState::InTransaction, DatabaseAction::Query) => {
                Ok(DatabaseState::InTransaction)
            }
            (DatabaseState::Disconnected, DatabaseAction::Query) => {
                Err(DatabaseViolation::UseInErrorState {
                    action,
                    current_state: current,
                })
            }
            (DatabaseState::Closed, DatabaseAction::Query) => {
                Err(DatabaseViolation::QueryAfterClose { close_line: 0 })
            }

            // Commit
            (DatabaseState::InTransaction, DatabaseAction::Commit) => Ok(DatabaseState::Connected),
            (_, DatabaseAction::Commit) => Err(DatabaseViolation::InvalidTransactionOp { action }),

            // Rollback
            (DatabaseState::InTransaction, DatabaseAction::Rollback) => {
                Ok(DatabaseState::Connected)
            }
            (_, DatabaseAction::Rollback) => {
                Err(DatabaseViolation::InvalidTransactionOp { action })
            }

            // Close
            (DatabaseState::Connected, DatabaseAction::Close) => Ok(DatabaseState::Closed),
            (DatabaseState::InTransaction, DatabaseAction::Close) => {
                Err(DatabaseViolation::UncommittedTransaction {
                    transaction_started_line: 0,
                })
            }
            (DatabaseState::Closed, DatabaseAction::Close) => Err(DatabaseViolation::DoubleClose {
                first_close_line: 0,
            }),
            (DatabaseState::Disconnected, DatabaseAction::Close) => Ok(DatabaseState::Closed),

            // Error state - most operations fail
            (DatabaseState::Error, action) => Err(DatabaseViolation::UseInErrorState {
                action,
                current_state: current,
            }),

            // Default: stay in current state
            _ => Ok(current),
        }
    }
}

/// Tracked database connection for state analysis
#[derive(Debug, Clone)]
struct TrackedDbConnection {
    /// Current state
    state: DatabaseState,
    /// Line where connection was opened
    connect_line: usize,
    /// Line where transaction began (if any)
    transaction_line: Option<usize>,
    /// Line where connection was closed (if any)
    close_line: Option<usize>,
    /// Whether a safe pattern was detected
    in_safe_context: bool,
}

impl TrackedDbConnection {
    fn new(connect_line: usize) -> Self {
        Self {
            state: DatabaseState::Connected,
            connect_line,
            transaction_line: None,
            close_line: None,
            in_safe_context: false,
        }
    }
}

/// Rule that detects database connection state violations
pub struct DatabaseTypestateRule;

impl DatabaseTypestateRule {
    /// Get the database state machine for a specific language
    pub fn state_machine(language: Language) -> DatabaseStateMachine {
        DatabaseStateMachine::for_language(language)
    }

    /// Check if the function has a safe pattern that handles cleanup
    fn has_safe_cleanup_pattern(content: &str, sm: &DatabaseStateMachine) -> bool {
        // Check for safe patterns throughout the content
        sm.is_safe_pattern(content)
    }

    /// Detect potential connection leak
    fn check_connection_leak(
        conn: &TrackedDbConnection,
        path: &std::path::Path,
        language: Language,
    ) -> Option<Finding> {
        if conn.state == DatabaseState::Connected
            && conn.close_line.is_none()
            && !conn.in_safe_context
        {
            let mut finding = create_finding_at_line(
                "generic/database-typestate",
                path,
                conn.connect_line,
                "",
                Severity::Warning,
                "Possible connection leak: connection opened but may not be closed",
                language,
            );
            finding.confidence = Confidence::Medium;
            finding.suggestion = Some(match language {
                Language::Python => {
                    "Use 'with' context manager or ensure connection.close() is called".to_string()
                }
                Language::Go => "Use 'defer conn.Close()' after opening connection".to_string(),
                Language::Java => {
                    "Use try-with-resources or ensure connection.close() in finally block"
                        .to_string()
                }
                Language::Rust => "Use connection pools or ensure proper Drop handling".to_string(),
                _ => "Ensure the connection is properly closed after use".to_string(),
            });
            Some(finding)
        } else {
            None
        }
    }
}

impl Rule for DatabaseTypestateRule {
    fn id(&self) -> &str {
        "generic/database-typestate"
    }

    fn description(&self) -> &str {
        "Detects database connection lifecycle violations including transaction errors, connection leaks, and use-after-close"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Java
                | Language::Rust
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, _flow: &FlowContext) -> Vec<Finding> {
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        let sm = Self::state_machine(parsed.language);
        let mut findings = Vec::new();
        let mut connections: Vec<TrackedDbConnection> = Vec::new();

        // Check for file-level safe patterns
        let has_global_safe = Self::has_safe_cleanup_pattern(&parsed.content, &sm);

        for (line_num, line) in parsed.content.lines().enumerate() {
            let line_num = line_num + 1;

            // Check for safe patterns on this line
            let line_has_safe = sm.is_safe_pattern(line);

            if let Some(action) = sm.detect_action(line) {
                match action {
                    DatabaseAction::Connect => {
                        let mut conn = TrackedDbConnection::new(line_num);
                        conn.in_safe_context = has_global_safe || line_has_safe;
                        connections.push(conn);
                    }
                    DatabaseAction::BeginTransaction => {
                        if let Some(conn) = connections.last_mut() {
                            if conn.state == DatabaseState::InTransaction {
                                // Nested transaction violation
                                let mut finding = create_finding_at_line(
                                    self.id(),
                                    &parsed.path,
                                    line_num,
                                    line.trim(),
                                    Severity::Warning,
                                    &format!(
                                        "Nested transaction detected (outer transaction started at line {})",
                                        conn.transaction_line.unwrap_or(0)
                                    ),
                                    parsed.language,
                                );
                                finding.confidence = Confidence::Medium;
                                finding.suggestion = Some(
                                    "Consider using savepoints for nested transactions or restructure the code".to_string()
                                );
                                findings.push(finding);
                            } else if conn.state == DatabaseState::Connected {
                                conn.state = DatabaseState::InTransaction;
                                conn.transaction_line = Some(line_num);
                            }
                        }
                    }
                    DatabaseAction::Query => {
                        // Check if we have any open connection
                        let has_valid_conn = connections.iter().any(|c| c.state.can_query());

                        if connections.is_empty() {
                            let mut finding = create_finding_at_line(
                                self.id(),
                                &parsed.path,
                                line_num,
                                line.trim(),
                                Severity::Error,
                                "Query executed without establishing connection",
                                parsed.language,
                            );
                            finding.confidence = Confidence::Medium;
                            finding.suggestion = Some(
                                "Establish a database connection before executing queries."
                                    .to_string(),
                            );
                            findings.push(finding);
                        } else if !has_valid_conn {
                            // Find the most recently closed connection
                            if let Some(conn) = connections
                                .iter()
                                .rev()
                                .find(|c| c.state == DatabaseState::Closed)
                            {
                                let mut finding = create_finding_at_line(
                                    self.id(),
                                    &parsed.path,
                                    line_num,
                                    line.trim(),
                                    Severity::Error,
                                    &format!(
                                        "Query executed on closed connection (closed at line {})",
                                        conn.close_line.unwrap_or(0)
                                    ),
                                    parsed.language,
                                );
                                finding.confidence = Confidence::High;
                                finding.suggestion = Some(
                                    "The connection was closed. Open a new connection before querying.".to_string()
                                );
                                findings.push(finding);
                            }
                        }
                    }
                    DatabaseAction::Commit => {
                        if let Some(conn) = connections.last_mut() {
                            if conn.state != DatabaseState::InTransaction {
                                let mut finding = create_finding_at_line(
                                    self.id(),
                                    &parsed.path,
                                    line_num,
                                    line.trim(),
                                    Severity::Error,
                                    "Commit called without active transaction",
                                    parsed.language,
                                );
                                finding.confidence = Confidence::Medium;
                                finding.suggestion = Some(
                                    "Ensure a transaction is started with begin() before calling commit().".to_string()
                                );
                                findings.push(finding);
                            } else {
                                conn.state = DatabaseState::Connected;
                                conn.transaction_line = None;
                            }
                        }
                    }
                    DatabaseAction::Rollback => {
                        if let Some(conn) = connections.last_mut() {
                            if conn.state != DatabaseState::InTransaction {
                                let mut finding = create_finding_at_line(
                                    self.id(),
                                    &parsed.path,
                                    line_num,
                                    line.trim(),
                                    Severity::Warning,
                                    "Rollback called without active transaction",
                                    parsed.language,
                                );
                                finding.confidence = Confidence::Low;
                                finding.suggestion = Some(
                                    "Rollback is typically only needed after begin(). This may be intentional for error handling.".to_string()
                                );
                                findings.push(finding);
                            } else {
                                conn.state = DatabaseState::Connected;
                                conn.transaction_line = None;
                            }
                        }
                    }
                    DatabaseAction::Close => {
                        if let Some(conn) = connections.last_mut() {
                            if conn.state == DatabaseState::InTransaction {
                                let mut finding = create_finding_at_line(
                                    self.id(),
                                    &parsed.path,
                                    line_num,
                                    line.trim(),
                                    Severity::Error,
                                    &format!(
                                        "Connection closed with uncommitted transaction (started at line {})",
                                        conn.transaction_line.unwrap_or(0)
                                    ),
                                    parsed.language,
                                );
                                finding.confidence = Confidence::High;
                                finding.suggestion = Some(
                                    "Commit or rollback the transaction before closing the connection.".to_string()
                                );
                                findings.push(finding);
                            } else if conn.state == DatabaseState::Closed {
                                let mut finding = create_finding_at_line(
                                    self.id(),
                                    &parsed.path,
                                    line_num,
                                    line.trim(),
                                    Severity::Warning,
                                    &format!(
                                        "Connection already closed at line {}",
                                        conn.close_line.unwrap_or(0)
                                    ),
                                    parsed.language,
                                );
                                finding.confidence = Confidence::Medium;
                                finding.suggestion =
                                    Some("Remove duplicate close() call.".to_string());
                                findings.push(finding);
                            }
                            conn.state = DatabaseState::Closed;
                            conn.close_line = Some(line_num);
                        }
                    }
                }
            }
        }

        // Check for connection leaks at end of file
        for conn in &connections {
            if let Some(finding) = Self::check_connection_leak(conn, &parsed.path, parsed.language)
            {
                findings.push(finding);
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Iterator Typestate Rule
// =============================================================================

/// Represents the state of an iterator/stream in the state machine
///
/// State Machine:
/// ```text
/// States: Fresh -> Consumed -> Exhausted
///         Fresh is initial
///         Exhausted is final (for single-use iterators)
///
/// Transitions:
///   Fresh --[next/read]--> Consumed
///   Consumed --[next/read]--> Consumed
///   Consumed --[collect/drain]--> Exhausted
///   Fresh --[collect/drain]--> Exhausted
///
/// Additional language-specific states:
///   - Moved (Rust): after .into_iter() ownership transfer
///   - Closed (Go): after channel close()
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IteratorState {
    /// Iterator is fresh (not yet iterated)
    Fresh,
    /// Iterator has been partially consumed (at least one next() call)
    Consumed,
    /// Iterator has been fully exhausted (collect/drain called)
    Exhausted,
    /// Iterator was moved by ownership transfer (Rust-specific)
    Moved,
    /// Channel is closed (Go-specific)
    Closed,
}

impl IteratorState {
    /// Check if this is an initial state
    pub fn is_initial(&self) -> bool {
        matches!(self, IteratorState::Fresh)
    }

    /// Check if this is a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            IteratorState::Exhausted | IteratorState::Moved | IteratorState::Closed
        )
    }

    /// Check if operations are valid in this state
    pub fn can_consume(&self) -> bool {
        matches!(self, IteratorState::Fresh | IteratorState::Consumed)
    }
}

impl std::fmt::Display for IteratorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IteratorState::Fresh => write!(f, "Fresh"),
            IteratorState::Consumed => write!(f, "Consumed"),
            IteratorState::Exhausted => write!(f, "Exhausted"),
            IteratorState::Moved => write!(f, "Moved"),
            IteratorState::Closed => write!(f, "Closed"),
        }
    }
}

/// Type of operation performed on an iterator/stream
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IteratorOperation {
    /// Creating a new iterator
    Create,
    /// Partial consumption (next(), read one element)
    ConsumeOne,
    /// Full exhaustion (collect, drain)
    Exhaust,
    /// Ownership transfer (into_iter, move)
    Move,
    /// Closing a channel/resource
    Close,
}

/// Iterator state machine for different languages
#[derive(Debug, Clone)]
pub struct IteratorStateMachine {
    /// Patterns that create iterators
    creation_patterns: Vec<&'static str>,
    /// Patterns that advance iterators (partial consumption)
    next_patterns: Vec<&'static str>,
    /// Patterns that exhaust/consume iterators fully
    consume_patterns: Vec<&'static str>,
    /// Patterns indicating ownership transfer (Rust)
    move_patterns: Vec<&'static str>,
    /// Patterns that close channels (Go)
    close_patterns: Vec<&'static str>,
    /// Patterns for Java Stream creation (single-use)
    stream_patterns: Vec<&'static str>,
}

impl IteratorStateMachine {
    /// Create an iterator state machine for a specific language
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self {
                creation_patterns: vec![
                    "[Symbol.iterator](",
                    ".values()",
                    ".keys()",
                    ".entries()",
                    "function*(",
                    "yield ",
                    ".matchAll(",
                    "Object.keys(",
                    "Object.values(",
                    "Object.entries(",
                ],
                next_patterns: vec![".next("],
                consume_patterns: vec![
                    "for (",
                    "for await",
                    "Array.from(",
                    "[...",
                    ".forEach(",
                    ".reduce(",
                    ".map(",
                    ".filter(",
                ],
                move_patterns: vec![],
                close_patterns: vec![],
                stream_patterns: vec![],
            },
            Language::Python => Self {
                creation_patterns: vec![
                    "iter(",
                    "__iter__",
                    "yield ",
                    "(x for",
                    "[x for",
                    "range(",
                    "enumerate(",
                    "zip(",
                    "map(",
                    "filter(",
                ],
                next_patterns: vec!["next(", "__next__"],
                consume_patterns: vec![
                    "list(", "tuple(", "set(", "dict(", "sum(", "max(", "min(", "any(", "all(",
                    ".join(",
                ],
                move_patterns: vec![],
                close_patterns: vec![],
                stream_patterns: vec![],
            },
            Language::Go => Self {
                creation_patterns: vec!["make(chan", "bufio.NewScanner(", "bufio.NewReader("],
                next_patterns: vec!["<-", ".Scan()", ".Read(", ".Next("],
                consume_patterns: vec!["for range"],
                move_patterns: vec![],
                close_patterns: vec!["close("],
                stream_patterns: vec![],
            },
            Language::Rust => Self {
                creation_patterns: vec![
                    ".iter()",
                    ".iter_mut()",
                    ".chars()",
                    ".bytes()",
                    ".lines(",
                    ".split(",
                    ".enumerate()",
                    ".zip(",
                    ".map(",
                    ".filter(",
                    ".peekable(",
                ],
                next_patterns: vec![".next()", ".peek("],
                consume_patterns: vec![
                    ".collect(",
                    ".collect::",
                    ".for_each(",
                    ".count()",
                    ".sum()",
                    ".product(",
                    ".fold(",
                    ".reduce(",
                    ".all(",
                    ".any(",
                    ".find(",
                    ".max()",
                    ".min(",
                    ".last(",
                ],
                move_patterns: vec![".into_iter()"],
                close_patterns: vec![],
                stream_patterns: vec![],
            },
            Language::Java => Self {
                creation_patterns: vec![".iterator()", "Iterator<"],
                next_patterns: vec![".next()", ".hasNext("],
                consume_patterns: vec!["for (", ".forEach("],
                move_patterns: vec![],
                close_patterns: vec![],
                stream_patterns: vec![
                    ".stream()",
                    ".parallelStream()",
                    "Stream.of(",
                    "Stream.generate(",
                    "Stream.iterate(",
                    "IntStream.",
                    "LongStream.",
                    "DoubleStream.",
                    "Arrays.stream(",
                    "Files.lines(",
                    "Files.list(",
                ],
            },
            _ => Self {
                creation_patterns: vec![],
                next_patterns: vec![],
                consume_patterns: vec![],
                move_patterns: vec![],
                close_patterns: vec![],
                stream_patterns: vec![],
            },
        }
    }

    /// Check if code creates an iterator
    pub fn is_creation(&self, code: &str) -> bool {
        self.creation_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code advances an iterator
    pub fn is_next(&self, code: &str) -> bool {
        self.next_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code exhausts/consumes an iterator
    pub fn is_consume(&self, code: &str) -> bool {
        self.consume_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code transfers ownership (Rust)
    pub fn is_move(&self, code: &str) -> bool {
        self.move_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code closes a channel (Go)
    pub fn is_close(&self, code: &str) -> bool {
        self.close_patterns.iter().any(|p| code.contains(p))
    }

    /// Check if code creates a Java Stream (single-use)
    pub fn is_stream_creation(&self, code: &str) -> bool {
        self.stream_patterns.iter().any(|p| code.contains(p))
    }

    /// Detect operation type from code
    pub fn detect_operation(&self, code: &str) -> Option<IteratorOperation> {
        if self.is_close(code) {
            return Some(IteratorOperation::Close);
        }
        if self.is_move(code) {
            return Some(IteratorOperation::Move);
        }
        if self.is_consume(code) {
            return Some(IteratorOperation::Exhaust);
        }
        if self.is_next(code) {
            return Some(IteratorOperation::ConsumeOne);
        }
        if self.is_creation(code) || self.is_stream_creation(code) {
            return Some(IteratorOperation::Create);
        }
        None
    }
}

/// Rule that detects iterator/stream state violations
///
/// Detects:
/// - Using an iterator after it's been exhausted
/// - Reusing a single-use stream (Java IllegalStateException)
/// - Using an iterator after ownership transfer (Rust)
/// - Data loss from collecting a partially consumed iterator
pub struct IteratorTypestateRule;

impl IteratorTypestateRule {
    /// Get the iterator state machine for a specific language
    pub fn state_machine(language: Language) -> IteratorStateMachine {
        IteratorStateMachine::for_language(language)
    }

    /// Get language-specific suggestion for the issue type
    fn get_suggestion(language: Language, issue_type: &str) -> String {
        match (language, issue_type) {
            (Language::Java, "stream_reuse") => {
                "Java Streams can only be operated on once. Store intermediate results or create a new stream:\n\
                 // Instead of: Stream<T> s = list.stream(); s.filter(...); s.map(...);\n\
                 // Do: List<T> result = list.stream().filter(...).collect(toList());".to_string()
            }
            (Language::Python, "iterator_exhaustion") => {
                "Python iterators can only be consumed once. To reuse, either:\n\
                 1. Convert to a list first: items = list(iterator)\n\
                 2. Use itertools.tee() to create independent iterators\n\
                 3. Create a fresh iterator each time".to_string()
            }
            (Language::Rust, "iterator_moved") => {
                "Iterator ownership was transferred. Consider:\n\
                 1. Use .iter() instead of .into_iter() to borrow\n\
                 2. Clone the collection before .into_iter()\n\
                 3. Collect results before reusing: let v: Vec<_> = iter.collect();".to_string()
            }
            (Language::Go, "channel_closed") => {
                "Cannot receive from a closed channel. Check channel state with:\n\
                 value, ok := <-ch\n\
                 if !ok { /* channel is closed */ }".to_string()
            }
            _ => {
                "Iterator/stream has been exhausted or moved. Create a new one or collect intermediate results.".to_string()
            }
        }
    }

    /// Determine severity based on issue type and language
    fn determine_severity(language: Language, issue_type: &str) -> Severity {
        match (language, issue_type) {
            (Language::Java, "stream_reuse") => Severity::Error, // RuntimeException
            (Language::Rust, "iterator_moved") => Severity::Error, // Compile error pattern
            (Language::Go, "channel_closed") => Severity::Error, // Panic
            (Language::Python, "iterator_exhaustion") => Severity::Warning, // Logic bug
            _ => Severity::Warning,
        }
    }
}

impl Rule for IteratorTypestateRule {
    fn id(&self) -> &str {
        "generic/iterator-typestate"
    }

    fn description(&self) -> &str {
        "Detects iterator/stream consumption violations (reuse, exhaustion, ownership)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Rust
                | Language::Java
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, _flow: &FlowContext) -> Vec<Finding> {
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        let sm = Self::state_machine(parsed.language);
        let mut findings = Vec::new();

        // Track multiple iterators by variable name approximation
        let mut iterator_states: HashMap<String, (IteratorState, usize, bool)> = HashMap::new();
        // (state, consumed_line, is_stream)

        for (line_num, line) in parsed.content.lines().enumerate() {
            let line_num = line_num + 1;
            let line_trimmed = line.trim();

            // Check for Java Stream creation (single-use)
            if sm.is_stream_creation(line_trimmed) {
                // Extract variable name (simple heuristic)
                if let Some(var_name) = Self::extract_var_name(line_trimmed, parsed.language) {
                    iterator_states.insert(var_name, (IteratorState::Fresh, line_num, true));
                }
            }
            // Check for iterator creation
            else if sm.is_creation(line_trimmed) || sm.is_move(line_trimmed) {
                if let Some(var_name) = Self::extract_var_name(line_trimmed, parsed.language) {
                    let is_move = sm.is_move(line_trimmed);
                    let initial_state = if is_move {
                        IteratorState::Moved
                    } else {
                        IteratorState::Fresh
                    };
                    iterator_states.insert(var_name, (initial_state, line_num, false));
                }
            }

            // Check for channel close (Go)
            if sm.is_close(line_trimmed) {
                if let Some(var_name) = Self::extract_var_from_close(line_trimmed) {
                    if let Some((state, _, _)) = iterator_states.get_mut(&var_name) {
                        *state = IteratorState::Closed;
                    }
                }
            }

            // Check for iterator operations
            for (var_name, (state, created_line, is_stream)) in iterator_states.iter_mut() {
                if !line_trimmed.contains(var_name.as_str()) {
                    continue;
                }

                // Detect operation on this iterator
                if let Some(op) = sm.detect_operation(line_trimmed) {
                    match op {
                        IteratorOperation::ConsumeOne => {
                            match *state {
                                IteratorState::Fresh => {
                                    if *is_stream {
                                        // Java streams are consumed immediately
                                        *state = IteratorState::Exhausted;
                                    } else {
                                        *state = IteratorState::Consumed;
                                    }
                                }
                                IteratorState::Consumed => {
                                    // Continue consuming
                                }
                                IteratorState::Exhausted => {
                                    let issue_type = if *is_stream {
                                        "stream_reuse"
                                    } else {
                                        "iterator_exhaustion"
                                    };
                                    let severity =
                                        Self::determine_severity(parsed.language, issue_type);
                                    let suggestion =
                                        Self::get_suggestion(parsed.language, issue_type);

                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        line_num,
                                        line_trimmed,
                                        severity,
                                        &format!(
                                            "{} '{}' already exhausted at line {}. {}",
                                            if *is_stream { "Stream" } else { "Iterator" },
                                            var_name,
                                            *created_line,
                                            suggestion
                                        ),
                                        parsed.language,
                                    );
                                    finding.confidence = if *is_stream {
                                        Confidence::High
                                    } else {
                                        Confidence::Medium
                                    };
                                    finding.suggestion = Some(suggestion);
                                    findings.push(finding);
                                }
                                IteratorState::Moved => {
                                    let suggestion =
                                        Self::get_suggestion(parsed.language, "iterator_moved");
                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        line_num,
                                        line_trimmed,
                                        Severity::Error,
                                        &format!(
                                            "Iterator '{}' was moved at line {}. Cannot use after ownership transfer. {}",
                                            var_name, *created_line, suggestion
                                        ),
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::High;
                                    finding.suggestion = Some(suggestion);
                                    findings.push(finding);
                                }
                                IteratorState::Closed => {
                                    let suggestion =
                                        Self::get_suggestion(parsed.language, "channel_closed");
                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        line_num,
                                        line_trimmed,
                                        Severity::Error,
                                        &format!(
                                            "Channel '{}' is closed. Cannot receive from closed channel. {}",
                                            var_name, suggestion
                                        ),
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::High;
                                    finding.suggestion = Some(suggestion);
                                    findings.push(finding);
                                }
                            }
                        }
                        IteratorOperation::Exhaust => {
                            if state.is_terminal() {
                                let issue_type = match *state {
                                    IteratorState::Exhausted if *is_stream => "stream_reuse",
                                    IteratorState::Exhausted => "iterator_exhaustion",
                                    IteratorState::Moved => "iterator_moved",
                                    IteratorState::Closed => "channel_closed",
                                    _ => "iterator_exhaustion",
                                };
                                let severity =
                                    Self::determine_severity(parsed.language, issue_type);
                                let suggestion = Self::get_suggestion(parsed.language, issue_type);

                                let mut finding = create_finding_at_line(
                                    self.id(),
                                    &parsed.path,
                                    line_num,
                                    line_trimmed,
                                    severity,
                                    &format!(
                                        "{} '{}' already in {} state (from line {}). {}",
                                        if *is_stream { "Stream" } else { "Iterator" },
                                        var_name,
                                        *state,
                                        *created_line,
                                        suggestion
                                    ),
                                    parsed.language,
                                );
                                finding.confidence = if *is_stream {
                                    Confidence::High
                                } else {
                                    Confidence::Medium
                                };
                                finding.suggestion = Some(suggestion);
                                findings.push(finding);
                            } else {
                                *state = IteratorState::Exhausted;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

impl IteratorTypestateRule {
    /// Simple heuristic to extract variable name from assignment
    fn extract_var_name(line: &str, _language: Language) -> Option<String> {
        // Look for common assignment patterns
        // let x = ..., const x = ..., var x = ..., x = ..., x := ...
        let line = line.trim();

        // Handle "let/const/var x = ..."
        for prefix in &["let ", "const ", "var ", "val ", "mut "] {
            if let Some(rest) = line.strip_prefix(prefix) {
                if let Some(eq_pos) = rest.find('=') {
                    let name = rest[..eq_pos].trim().trim_end_matches(':').trim();
                    // Remove type annotations
                    let name = name.split(':').next().unwrap_or(name).trim();
                    if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        return Some(name.to_string());
                    }
                }
            }
        }

        // Handle "x = ..." or "x := ..."
        if let Some(eq_pos) = line.find('=') {
            let before = line[..eq_pos].trim();
            // Skip compound assignments
            if !before.ends_with('+')
                && !before.ends_with('-')
                && !before.ends_with('*')
                && !before.ends_with('/')
            {
                let name = before.split_whitespace().last()?;
                if name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return Some(name.to_string());
                }
            }
        }

        None
    }

    /// Extract variable name from close() call
    fn extract_var_from_close(line: &str) -> Option<String> {
        // Handle "close(ch)" pattern
        if let Some(start) = line.find("close(") {
            let rest = &line[start + 6..];
            if let Some(end) = rest.find(')') {
                let name = rest[..end].trim();
                if name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return Some(name.to_string());
                }
            }
        }
        None
    }
}

// =============================================================================
// Convenience function to get all built-in typestate rules
// =============================================================================

/// Get all built-in typestate rules
pub fn builtin_typestate_rules() -> Vec<Box<dyn Rule + Send + Sync>> {
    vec![
        Box::new(FileTypestateRule),
        Box::new(LockTypestateRule),
        Box::new(CryptoTypestateRule),
        Box::new(DatabaseTypestateRule),
        Box::new(IteratorTypestateRule),
    ]
}

// =============================================================================
// Additional Tests for New Rules
// =============================================================================

#[cfg(test)]
mod additional_tests {
    use super::*;

    #[test]
    fn test_lock_state_machine_patterns() {
        let sm = LockStateMachine::for_language(Language::Go);

        assert_eq!(
            sm.detect_operation("mutex.Lock()"),
            Some(LockOperation::Lock)
        );
        assert_eq!(
            sm.detect_operation("mutex.Unlock()"),
            Some(LockOperation::Unlock)
        );
        assert!(sm.is_safe_context("defer m.Unlock()"));
    }

    #[test]
    fn test_lock_rule_id() {
        let rule = LockTypestateRule;
        assert_eq!(rule.id(), "generic/lock-typestate");
        assert!(rule.uses_flow());
    }

    #[test]
    fn test_crypto_state_machine_patterns() {
        let sm = CryptoStateMachine::for_language(Language::Java);

        // Test cipher creation
        assert!(sm.is_creation("Cipher.getInstance(\"AES\")").is_some());
        assert_eq!(
            sm.is_creation("Cipher.getInstance(\"AES\")"),
            Some(CryptoObjectType::Cipher)
        );

        // Test cipher initialization
        assert!(sm.is_init("cipher.init(Cipher.ENCRYPT_MODE, key)"));

        // Test cipher operations (update and finalize)
        assert!(sm.is_update("cipher.update(data)"));
        assert!(sm.is_finalize("cipher.doFinal(data)"));

        // Test hash creation
        assert!(
            sm.is_creation("MessageDigest.getInstance(\"SHA-256\")")
                .is_some()
        );
        assert_eq!(
            sm.is_creation("MessageDigest.getInstance(\"SHA-256\")"),
            Some(CryptoObjectType::Hash)
        );

        // Test hash operations
        assert!(sm.is_update("digest.update(data)"));
        assert!(sm.is_finalize("digest.digest()"));

        // Test weak algorithm detection
        assert!(
            sm.uses_weak_algorithm("MessageDigest.getInstance(\"MD5\")")
                .is_some()
        );
        assert!(
            sm.uses_weak_algorithm("MessageDigest.getInstance(\"SHA-256\")")
                .is_none()
        );

        // Test unsafe mode detection
        assert!(
            sm.uses_unsafe_mode("Cipher.getInstance(\"AES/ECB/PKCS5Padding\")")
                .is_some()
        );
        assert!(
            sm.uses_unsafe_mode("Cipher.getInstance(\"AES/GCM/NoPadding\")")
                .is_none()
        );
    }

    #[test]
    fn test_crypto_rule_id() {
        let rule = CryptoTypestateRule;
        assert_eq!(rule.id(), "generic/crypto-typestate");
        assert!(rule.uses_flow());
    }

    #[test]
    fn test_database_state_machine_patterns() {
        let sm = DatabaseStateMachine::for_language(Language::Python);

        assert!(sm.is_connect("conn = sqlite3.connect('test.db')"));
        assert!(sm.is_query("cursor.execute('SELECT * FROM users')"));
        assert!(sm.is_close("conn.close()"));

        // Test transaction patterns
        assert!(sm.is_begin_transaction("conn.begin()"));
        assert!(sm.is_commit("conn.commit()"));
        assert!(sm.is_rollback("conn.rollback()"));

        // Test safe patterns
        assert!(sm.is_safe_pattern("with Session() as session:"));
    }

    #[test]
    fn test_database_rule_id() {
        let rule = DatabaseTypestateRule;
        assert_eq!(rule.id(), "generic/database-typestate");
        assert!(rule.uses_flow());
    }

    #[test]
    fn test_database_state_transitions() {
        assert!(DatabaseState::Disconnected.is_initial());
        assert!(DatabaseState::Closed.is_final());
        assert!(DatabaseState::Connected.can_query());
        assert!(DatabaseState::InTransaction.can_query());
        assert!(DatabaseState::InTransaction.can_transact());
        assert!(!DatabaseState::Connected.can_transact());
        assert!(!DatabaseState::Disconnected.can_query());
    }

    #[test]
    fn test_database_action_display() {
        assert_eq!(format!("{}", DatabaseAction::Connect), "connect");
        assert_eq!(
            format!("{}", DatabaseAction::BeginTransaction),
            "begin transaction"
        );
        assert_eq!(format!("{}", DatabaseAction::Query), "query");
        assert_eq!(format!("{}", DatabaseAction::Commit), "commit");
        assert_eq!(format!("{}", DatabaseAction::Rollback), "rollback");
        assert_eq!(format!("{}", DatabaseAction::Close), "close");
    }

    #[test]
    fn test_database_violation_display() {
        let violation = DatabaseViolation::ConnectionLeak { connect_line: 10 };
        assert!(format!("{}", violation).contains("line 10"));

        let violation = DatabaseViolation::UncommittedTransaction {
            transaction_started_line: 5,
        };
        assert!(format!("{}", violation).contains("uncommitted transaction"));

        let violation = DatabaseViolation::NestedTransaction {
            outer_transaction_line: 3,
        };
        assert!(format!("{}", violation).contains("nested transaction"));
    }

    #[test]
    fn test_database_javascript_patterns() {
        let sm = DatabaseStateMachine::for_language(Language::JavaScript);

        // Node.js mysql
        assert!(sm.is_connect("mysql.createConnection({ host: 'localhost' })"));
        assert!(sm.is_connect("pool.getConnection()"));

        // Node.js pg
        assert!(sm.is_connect("const client = new Client()"));
        assert!(sm.is_connect("await client.connect()"));

        // Sequelize ORM
        assert!(sm.is_connect("const sequelize = new Sequelize('sqlite::memory:')"));
        assert!(sm.is_begin_transaction("const t = await sequelize.transaction()"));

        // Safe patterns
        assert!(sm.is_safe_pattern("await sequelize.transaction(async (t) => {"));
    }

    #[test]
    fn test_database_python_patterns() {
        let sm = DatabaseStateMachine::for_language(Language::Python);

        // Standard DB-API
        assert!(sm.is_connect("conn = psycopg2.connect('postgres://...')"));
        assert!(sm.is_connect("conn = mysql.connector.connect(host='localhost')"));

        // SQLAlchemy
        assert!(sm.is_connect("engine = create_engine('sqlite:///test.db')"));
        assert!(sm.is_connect("session = Session()"));
        assert!(sm.is_begin_transaction("session.begin_nested()"));

        // Safe patterns
        assert!(sm.is_safe_pattern("with Session() as session:"));
        assert!(sm.is_safe_pattern("async with engine.connect() as conn:"));
    }

    #[test]
    fn test_database_go_patterns() {
        let sm = DatabaseStateMachine::for_language(Language::Go);

        // Standard library
        assert!(sm.is_connect("db, err := sql.Open(\"postgres\", connStr)"));
        assert!(sm.is_connect("db, err := sqlx.Connect(\"postgres\", connStr)"));

        // GORM
        assert!(sm.is_connect("db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})"));
        assert!(sm.is_begin_transaction("tx := db.Begin()"));

        // Safe patterns
        assert!(sm.is_safe_pattern("defer db.Close()"));
        assert!(sm.is_safe_pattern("defer tx.Rollback()"));
    }

    #[test]
    fn test_database_java_patterns() {
        let sm = DatabaseStateMachine::for_language(Language::Java);

        // JDBC
        assert!(sm.is_connect("Connection conn = DriverManager.getConnection(url)"));
        assert!(sm.is_begin_transaction("conn.setAutoCommit(false)"));

        // JPA/Hibernate
        assert!(sm.is_connect("EntityManager em = EntityManagerFactory.createEntityManager()"));
        assert!(sm.is_connect("Session session = sessionFactory.openSession()"));
        assert!(sm.is_begin_transaction("session.getTransaction().begin()"));

        // Safe patterns
        assert!(sm.is_safe_pattern("try (Connection conn = ds.getConnection()) {"));
        assert!(sm.is_safe_pattern("@Transactional"));
    }

    #[test]
    fn test_database_rust_patterns() {
        let sm = DatabaseStateMachine::for_language(Language::Rust);

        // sqlx
        assert!(sm.is_connect("let pool = PgPool::connect(&database_url).await?"));
        assert!(sm.is_connect("let pool = Pool::connect(&database_url).await?"));

        // diesel
        assert!(sm.is_connect("let conn = PgConnection::establish(&database_url)?"));

        // Transactions
        assert!(sm.is_begin_transaction("let tx = conn.transaction()?"));

        // Safe patterns
        assert!(sm.is_safe_pattern("conn.transaction(|tx| {"));
    }

    #[test]
    fn test_database_detect_action() {
        let sm = DatabaseStateMachine::for_language(Language::Python);

        assert_eq!(
            sm.detect_action("conn = psycopg2.connect('...')"),
            Some(DatabaseAction::Connect)
        );
        assert_eq!(
            sm.detect_action("session.begin()"),
            Some(DatabaseAction::BeginTransaction)
        );
        assert_eq!(
            sm.detect_action("cursor.execute('SELECT * FROM t')"),
            Some(DatabaseAction::Query)
        );
        assert_eq!(
            sm.detect_action("session.commit()"),
            Some(DatabaseAction::Commit)
        );
        assert_eq!(
            sm.detect_action("session.rollback()"),
            Some(DatabaseAction::Rollback)
        );
        assert_eq!(
            sm.detect_action("conn.close()"),
            Some(DatabaseAction::Close)
        );
        assert_eq!(sm.detect_action("x = 1"), None);
    }

    #[test]
    fn test_database_state_machine_transition() {
        let sm = DatabaseStateMachine::for_language(Language::Python);

        // Valid transitions
        assert!(
            sm.transition(DatabaseState::Disconnected, DatabaseAction::Connect, "")
                .is_ok()
        );
        assert!(
            sm.transition(
                DatabaseState::Connected,
                DatabaseAction::BeginTransaction,
                ""
            )
            .is_ok()
        );
        assert!(
            sm.transition(DatabaseState::InTransaction, DatabaseAction::Query, "")
                .is_ok()
        );
        assert!(
            sm.transition(DatabaseState::InTransaction, DatabaseAction::Commit, "")
                .is_ok()
        );
        assert!(
            sm.transition(DatabaseState::Connected, DatabaseAction::Close, "")
                .is_ok()
        );

        // Invalid transitions
        assert!(
            sm.transition(DatabaseState::Disconnected, DatabaseAction::Query, "")
                .is_err()
        );
        assert!(
            sm.transition(DatabaseState::Connected, DatabaseAction::Commit, "")
                .is_err()
        );
        assert!(
            sm.transition(
                DatabaseState::InTransaction,
                DatabaseAction::BeginTransaction,
                ""
            )
            .is_err()
        );
    }

    #[test]
    fn test_database_rule_applies_to_rust() {
        let rule = DatabaseTypestateRule;
        assert!(rule.applies_to(Language::Rust));
    }

    #[test]
    fn test_iterator_state_machine_patterns() {
        let sm = IteratorStateMachine::for_language(Language::Rust);

        assert!(sm.is_creation("let iter = vec.iter()"));
        assert!(sm.is_next("iter.next()"));
        assert!(sm.is_consume("iter.collect::<Vec<_>>()"));
    }

    #[test]
    fn test_iterator_rule_id() {
        let rule = IteratorTypestateRule;
        assert_eq!(rule.id(), "generic/iterator-typestate");
        assert!(rule.uses_flow());
    }

    #[test]
    fn test_builtin_typestate_rules_count() {
        let rules = builtin_typestate_rules();
        assert_eq!(rules.len(), 5);
    }

    #[test]
    fn test_all_rules_apply_to_javascript() {
        let file_rule = FileTypestateRule;
        let lock_rule = LockTypestateRule;
        let crypto_rule = CryptoTypestateRule;
        let db_rule = DatabaseTypestateRule;
        let iter_rule = IteratorTypestateRule;

        assert!(file_rule.applies_to(Language::JavaScript));
        assert!(lock_rule.applies_to(Language::JavaScript));
        assert!(crypto_rule.applies_to(Language::JavaScript));
        assert!(db_rule.applies_to(Language::JavaScript));
        assert!(iter_rule.applies_to(Language::JavaScript));
    }
}
