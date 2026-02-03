//! Typestate Analysis Framework
//!
//! This module provides a framework for tracking object state transitions through
//! control flow. It enables detection of state-related bugs such as:
//! - Use-after-close (e.g., reading from a closed file)
//! - Missing cleanup (e.g., file not closed before function exit)
//! - Invalid state transitions (e.g., calling read() on an unopened file)
//!
//! The framework uses a state machine model where:
//! - Objects are in specific states (Open, Closed, Locked, etc.)
//! - Method calls trigger state transitions
//! - Some states are valid end states (final), others are error states
//!
//! Example state machine for a File:
//! ```text
//!   [Unopened] --open()--> [Open] --close()--> [Closed]
//!                            |                     |
//!                         read()/write()       read()/write()
//!                            |                     |
//!                         [Open]              [Error: UseAfterClose]
//! ```

use crate::flow::cfg::{BlockId, CFG, Terminator};
use crate::flow::dataflow::find_node_by_id;
use crate::semantics::LanguageSemantics;
use rma_parser::ParsedFile;
use std::collections::{HashMap, HashSet, VecDeque};

// =============================================================================
// Core Types
// =============================================================================

/// A state in a state machine
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct State {
    /// Name of the state (e.g., "Open", "Closed", "Locked")
    pub name: String,
    /// Whether this is the initial state when an object is created
    pub is_initial: bool,
    /// Whether this is a valid final state (object can be dropped/go out of scope)
    pub is_final: bool,
    /// Whether this is an error state (e.g., use-after-close)
    pub is_error: bool,
}

impl State {
    /// Create a new state
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_initial: false,
            is_final: false,
            is_error: false,
        }
    }

    /// Create an initial state
    pub fn initial(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_initial: true,
            is_final: false,
            is_error: false,
        }
    }

    /// Create a final state
    pub fn final_state(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_initial: false,
            is_final: true,
            is_error: false,
        }
    }

    /// Create an error state
    pub fn error(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_initial: false,
            is_final: false,
            is_error: true,
        }
    }

    /// Builder: set as initial
    pub fn with_initial(mut self, is_initial: bool) -> Self {
        self.is_initial = is_initial;
        self
    }

    /// Builder: set as final
    pub fn with_final(mut self, is_final: bool) -> Self {
        self.is_final = is_final;
        self
    }

    /// Builder: set as error
    pub fn with_error(mut self, is_error: bool) -> Self {
        self.is_error = is_error;
        self
    }
}

/// What triggers a state transition
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransitionTrigger {
    /// A method call (e.g., "open", "close", "lock")
    MethodCall(String),
    /// An assignment (e.g., x = null)
    Assignment,
    /// A function return value (e.g., return value of open())
    FunctionReturn(String),
    /// Destructor/Drop/dispose/finalize
    Destructor,
    /// A specific pattern match (e.g., checking for null)
    PatternMatch(String),
}

impl TransitionTrigger {
    /// Create a method call trigger
    pub fn method(name: impl Into<String>) -> Self {
        Self::MethodCall(name.into())
    }

    /// Create a function return trigger
    pub fn function_return(name: impl Into<String>) -> Self {
        Self::FunctionReturn(name.into())
    }

    /// Check if this trigger matches a method name
    pub fn matches_method(&self, method: &str) -> bool {
        match self {
            TransitionTrigger::MethodCall(m) => m == method || m == "*",
            _ => false,
        }
    }

    /// Check if this trigger matches a function return
    pub fn matches_function_return(&self, func: &str) -> bool {
        match self {
            TransitionTrigger::FunctionReturn(f) => f == func || f == "*",
            _ => false,
        }
    }
}

/// A transition between states
#[derive(Debug, Clone)]
pub struct Transition {
    /// State transitioning from
    pub from: String,
    /// State transitioning to
    pub to: String,
    /// What triggers this transition
    pub trigger: TransitionTrigger,
}

impl Transition {
    /// Create a new transition
    pub fn new(from: impl Into<String>, to: impl Into<String>, trigger: TransitionTrigger) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            trigger,
        }
    }

    /// Create a method call transition
    pub fn on_method(
        from: impl Into<String>,
        to: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self::new(from, to, TransitionTrigger::MethodCall(method.into()))
    }

    /// Create an assignment transition
    pub fn on_assignment(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::new(from, to, TransitionTrigger::Assignment)
    }

    /// Create a destructor transition
    pub fn on_destructor(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::new(from, to, TransitionTrigger::Destructor)
    }
}

/// A complete state machine definition
#[derive(Debug, Clone)]
pub struct StateMachine {
    /// Name of the state machine (e.g., "File", "Lock", "Connection")
    pub name: String,
    /// All states in the machine
    pub states: Vec<State>,
    /// All valid transitions
    pub transitions: Vec<Transition>,
    /// Type names this state machine applies to (e.g., ["File", "std::fs::File"])
    pub tracked_types: Vec<String>,
}

impl StateMachine {
    /// Create a new state machine
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            states: Vec::new(),
            transitions: Vec::new(),
            tracked_types: Vec::new(),
        }
    }

    /// Add a state
    pub fn with_state(mut self, state: State) -> Self {
        self.states.push(state);
        self
    }

    /// Add a transition
    pub fn with_transition(mut self, transition: Transition) -> Self {
        self.transitions.push(transition);
        self
    }

    /// Add a tracked type
    pub fn with_tracked_type(mut self, type_name: impl Into<String>) -> Self {
        self.tracked_types.push(type_name.into());
        self
    }

    /// Add multiple tracked types
    pub fn with_tracked_types(mut self, type_names: &[&str]) -> Self {
        self.tracked_types
            .extend(type_names.iter().map(|s| s.to_string()));
        self
    }

    /// Get the initial state
    pub fn initial_state(&self) -> Option<&State> {
        self.states.iter().find(|s| s.is_initial)
    }

    /// Get a state by name
    pub fn get_state(&self, name: &str) -> Option<&State> {
        self.states.iter().find(|s| s.name == name)
    }

    /// Check if a state is final (valid end state)
    pub fn is_final_state(&self, name: &str) -> bool {
        self.get_state(name).map(|s| s.is_final).unwrap_or(false)
    }

    /// Check if a state is an error state
    pub fn is_error_state(&self, name: &str) -> bool {
        self.get_state(name).map(|s| s.is_error).unwrap_or(false)
    }

    /// Get a transition for a method call from a given state
    pub fn get_method_transition(&self, from_state: &str, method: &str) -> Option<&Transition> {
        self.transitions
            .iter()
            .find(|t| t.from == from_state && t.trigger.matches_method(method))
    }

    /// Get any transition that matches the trigger from a given state
    pub fn get_transition(
        &self,
        from_state: &str,
        trigger: &TransitionTrigger,
    ) -> Option<&Transition> {
        self.transitions
            .iter()
            .find(|t| t.from == from_state && &t.trigger == trigger)
    }

    /// Check if this machine tracks the given type
    pub fn tracks_type(&self, type_name: &str) -> bool {
        self.tracked_types
            .iter()
            .any(|t| t == type_name || type_name.ends_with(t))
    }
}

// =============================================================================
// Analysis Result Types
// =============================================================================

/// The kind of typestate violation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// Invalid state transition (e.g., read() when state is Closed)
    InvalidTransition,
    /// Missing state transition before exit (e.g., never called close())
    MissingTransition,
    /// Use of object in error state (e.g., use after close)
    UseInErrorState,
    /// Object not in final state at function return/scope exit
    NonFinalStateAtExit,
    /// Conflicting states at merge point (e.g., open on one path, closed on another)
    ConflictingStates,
}

impl std::fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationKind::InvalidTransition => write!(f, "Invalid state transition"),
            ViolationKind::MissingTransition => write!(f, "Missing required state transition"),
            ViolationKind::UseInErrorState => write!(f, "Use of object in error state"),
            ViolationKind::NonFinalStateAtExit => write!(f, "Object not in final state at exit"),
            ViolationKind::ConflictingStates => write!(f, "Conflicting states at merge point"),
        }
    }
}

/// A typestate violation detected during analysis
#[derive(Debug, Clone)]
pub struct TypestateViolation {
    /// The kind of violation
    pub kind: ViolationKind,
    /// The AST node ID where the violation occurred
    pub location: usize,
    /// Line number where the violation occurred
    pub line: usize,
    /// The current state when the violation occurred
    pub current_state: String,
    /// The attempted transition (if applicable)
    pub attempted_transition: Option<String>,
    /// Human-readable message describing the violation
    pub message: String,
}

impl TypestateViolation {
    /// Create a new violation
    pub fn new(
        kind: ViolationKind,
        location: usize,
        line: usize,
        current_state: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            location,
            line,
            current_state: current_state.into(),
            attempted_transition: None,
            message: message.into(),
        }
    }

    /// Add attempted transition information
    pub fn with_attempted_transition(mut self, transition: impl Into<String>) -> Self {
        self.attempted_transition = Some(transition.into());
        self
    }
}

/// Represents the tracked state at a particular point
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackedState {
    /// Known to be in a specific state
    Known(String),
    /// State is unknown (not yet initialized or analysis couldn't determine)
    Unknown,
    /// Conflicting states from different paths (includes all possible states)
    Conflicting(HashSet<String>),
}

impl TrackedState {
    /// Check if this is a known state
    pub fn is_known(&self) -> bool {
        matches!(self, TrackedState::Known(_))
    }

    /// Get the state name if known
    pub fn state_name(&self) -> Option<&str> {
        match self {
            TrackedState::Known(name) => Some(name),
            _ => None,
        }
    }

    /// Merge two tracked states (at CFG merge points)
    pub fn merge(&self, other: &TrackedState) -> TrackedState {
        match (self, other) {
            // Same state -> keep it
            (TrackedState::Known(a), TrackedState::Known(b)) if a == b => {
                TrackedState::Known(a.clone())
            }
            // Different known states -> conflicting
            (TrackedState::Known(a), TrackedState::Known(b)) => {
                let mut set = HashSet::new();
                set.insert(a.clone());
                set.insert(b.clone());
                TrackedState::Conflicting(set)
            }
            // Known + Unknown -> the known state (conservative)
            (TrackedState::Known(a), TrackedState::Unknown)
            | (TrackedState::Unknown, TrackedState::Known(a)) => TrackedState::Known(a.clone()),
            // Unknown + Unknown -> Unknown
            (TrackedState::Unknown, TrackedState::Unknown) => TrackedState::Unknown,
            // Any + Conflicting -> merge into conflicting
            (TrackedState::Conflicting(set), TrackedState::Known(s))
            | (TrackedState::Known(s), TrackedState::Conflicting(set)) => {
                let mut new_set = set.clone();
                new_set.insert(s.clone());
                TrackedState::Conflicting(new_set)
            }
            (TrackedState::Conflicting(a), TrackedState::Conflicting(b)) => {
                let mut new_set = a.clone();
                new_set.extend(b.iter().cloned());
                TrackedState::Conflicting(new_set)
            }
            (TrackedState::Conflicting(set), TrackedState::Unknown)
            | (TrackedState::Unknown, TrackedState::Conflicting(set)) => {
                TrackedState::Conflicting(set.clone())
            }
        }
    }
}

/// Result of typestate analysis for a single variable
#[derive(Debug, Clone)]
pub struct TypestateResult {
    /// Variable name being tracked
    pub variable: String,
    /// Name of the state machine used
    pub state_machine: String,
    /// Violations detected
    pub violations: Vec<TypestateViolation>,
    /// State at the entry of each CFG block
    pub block_states: HashMap<BlockId, TrackedState>,
    /// State at the exit of each CFG block
    pub block_exit_states: HashMap<BlockId, TrackedState>,
}

impl TypestateResult {
    /// Create a new result
    pub fn new(variable: impl Into<String>, state_machine: impl Into<String>) -> Self {
        Self {
            variable: variable.into(),
            state_machine: state_machine.into(),
            violations: Vec::new(),
            block_states: HashMap::new(),
            block_exit_states: HashMap::new(),
        }
    }

    /// Check if there are any violations
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Get the state at a specific block
    pub fn state_at_block(&self, block_id: BlockId) -> Option<&TrackedState> {
        self.block_states.get(&block_id)
    }

    /// Get the exit state at a specific block
    pub fn exit_state_at_block(&self, block_id: BlockId) -> Option<&TrackedState> {
        self.block_exit_states.get(&block_id)
    }
}

// =============================================================================
// Cross-File Typestate Summaries
// =============================================================================

/// Summary of a function's typestate behavior for cross-file analysis
///
/// This tracks which functions manage resource lifecycle, allowing typestate
/// analysis to understand resource state changes across file boundaries.
#[derive(Debug, Clone)]
pub struct TypestateSummary {
    /// Function name
    pub function_name: String,
    /// File containing this function
    pub file: Option<std::path::PathBuf>,
    /// Resources (by type) that this function acquires/opens
    pub opens_resources: Vec<ResourceAction>,
    /// Resources (by type) that this function releases/closes
    pub closes_resources: Vec<ResourceAction>,
    /// Whether this function returns an open resource
    pub returns_open_resource: bool,
    /// Resource type returned (if any)
    pub return_resource_type: Option<String>,
    /// Parameters that receive resources (by index)
    pub resource_params: Vec<usize>,
}

/// Represents an action on a resource (open, close, etc.)
#[derive(Debug, Clone)]
pub struct ResourceAction {
    /// Type of resource (e.g., "Connection", "File", "Lock")
    pub resource_type: String,
    /// Line number where the action occurs
    pub line: usize,
    /// Variable name involved (if known)
    pub variable: Option<String>,
}

impl TypestateSummary {
    /// Create a new typestate summary for a function
    pub fn new(function_name: impl Into<String>) -> Self {
        Self {
            function_name: function_name.into(),
            file: None,
            opens_resources: Vec::new(),
            closes_resources: Vec::new(),
            returns_open_resource: false,
            return_resource_type: None,
            resource_params: Vec::new(),
        }
    }

    /// Set the file path
    pub fn with_file(mut self, file: std::path::PathBuf) -> Self {
        self.file = Some(file);
        self
    }

    /// Record that this function opens a resource
    pub fn opens(
        &mut self,
        resource_type: impl Into<String>,
        line: usize,
        variable: Option<String>,
    ) {
        self.opens_resources.push(ResourceAction {
            resource_type: resource_type.into(),
            line,
            variable,
        });
    }

    /// Record that this function closes a resource
    pub fn closes(
        &mut self,
        resource_type: impl Into<String>,
        line: usize,
        variable: Option<String>,
    ) {
        self.closes_resources.push(ResourceAction {
            resource_type: resource_type.into(),
            line,
            variable,
        });
    }

    /// Mark that this function returns an open resource
    pub fn returns_resource(mut self, resource_type: impl Into<String>) -> Self {
        self.returns_open_resource = true;
        self.return_resource_type = Some(resource_type.into());
        self
    }

    /// Mark a parameter as receiving a resource
    pub fn with_resource_param(mut self, param_idx: usize) -> Self {
        self.resource_params.push(param_idx);
        self
    }

    /// Check if this function opens any resources
    pub fn opens_any(&self) -> bool {
        !self.opens_resources.is_empty()
    }

    /// Check if this function closes any resources
    pub fn closes_any(&self) -> bool {
        !self.closes_resources.is_empty()
    }

    /// Check if this function opens a specific resource type
    pub fn opens_resource_type(&self, resource_type: &str) -> bool {
        self.opens_resources
            .iter()
            .any(|r| r.resource_type == resource_type)
    }

    /// Check if this function closes a specific resource type
    pub fn closes_resource_type(&self, resource_type: &str) -> bool {
        self.closes_resources
            .iter()
            .any(|r| r.resource_type == resource_type)
    }
}

/// Registry of typestate summaries for cross-file analysis
#[derive(Debug, Default)]
pub struct TypestateSummaryRegistry {
    /// Summaries indexed by file path and function name
    summaries: HashMap<String, TypestateSummary>,
}

impl TypestateSummaryRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a summary to the registry
    pub fn add(&mut self, summary: TypestateSummary) {
        let key = if let Some(ref file) = summary.file {
            format!("{}:{}", file.display(), summary.function_name)
        } else {
            summary.function_name.clone()
        };
        self.summaries.insert(key, summary);
    }

    /// Get a summary by function name
    pub fn get(&self, function_name: &str) -> Option<&TypestateSummary> {
        self.summaries.get(function_name)
    }

    /// Get a summary by file and function name
    pub fn get_by_file(
        &self,
        file: &std::path::Path,
        function_name: &str,
    ) -> Option<&TypestateSummary> {
        let key = format!("{}:{}", file.display(), function_name);
        self.summaries.get(&key)
    }

    /// Get all summaries that open a specific resource type
    pub fn functions_that_open(&self, resource_type: &str) -> Vec<&TypestateSummary> {
        self.summaries
            .values()
            .filter(|s| s.opens_resource_type(resource_type))
            .collect()
    }

    /// Get all summaries that close a specific resource type
    pub fn functions_that_close(&self, resource_type: &str) -> Vec<&TypestateSummary> {
        self.summaries
            .values()
            .filter(|s| s.closes_resource_type(resource_type))
            .collect()
    }

    /// Check if a function opens a resource
    pub fn function_opens_resource(&self, function_name: &str) -> bool {
        self.summaries
            .get(function_name)
            .map(|s| s.opens_any())
            .unwrap_or(false)
    }

    /// Check if a function closes a resource
    pub fn function_closes_resource(&self, function_name: &str) -> bool {
        self.summaries
            .get(function_name)
            .map(|s| s.closes_any())
            .unwrap_or(false)
    }
}

// =============================================================================
// Method Call Detection
// =============================================================================

/// Information about a method call found in the AST
#[derive(Debug, Clone)]
pub struct MethodCallInfo {
    /// AST node ID of the call
    pub node_id: usize,
    /// Line number
    pub line: usize,
    /// Method name
    pub method_name: String,
    /// Object the method is called on (if identifiable)
    pub receiver: Option<String>,
}

/// Find all method calls on a specific variable in a parsed file
pub fn find_method_calls_on_var(
    parsed: &ParsedFile,
    var_name: &str,
    semantics: &LanguageSemantics,
) -> Vec<MethodCallInfo> {
    let mut results = Vec::new();
    let source = parsed.content.as_bytes();

    fn walk_node<'a>(
        node: tree_sitter::Node<'a>,
        source: &[u8],
        var_name: &str,
        semantics: &LanguageSemantics,
        results: &mut Vec<MethodCallInfo>,
    ) {
        let kind = node.kind();

        // Check for method call expressions
        if semantics.is_call(kind) {
            // Look for the function/method being called
            if let Some(func_node) = node.child_by_field_name(semantics.function_field) {
                // Check if it's a member expression (obj.method)
                if semantics.is_member_access(func_node.kind()) {
                    // Get the object and method
                    if let (Some(obj), Some(method)) = (
                        func_node.child_by_field_name(semantics.object_field),
                        func_node.child_by_field_name(semantics.property_field),
                    ) {
                        // Check if the object is our target variable
                        if let Ok(obj_text) = obj.utf8_text(source)
                            && obj_text == var_name
                            && let Ok(method_text) = method.utf8_text(source)
                        {
                            results.push(MethodCallInfo {
                                node_id: node.id(),
                                line: node.start_position().row + 1,
                                method_name: method_text.to_string(),
                                receiver: Some(var_name.to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_node(child, source, var_name, semantics, results);
        }
    }

    walk_node(
        parsed.tree.root_node(),
        source,
        var_name,
        semantics,
        &mut results,
    );

    // Sort by line number
    results.sort_by_key(|info| info.line);
    results
}

/// Find all assignments to a specific variable
pub fn find_assignments_to_var(
    parsed: &ParsedFile,
    var_name: &str,
    semantics: &LanguageSemantics,
) -> Vec<(usize, usize)> {
    // Returns (node_id, line)
    let mut results = Vec::new();
    let source = parsed.content.as_bytes();

    fn walk_node<'a>(
        node: tree_sitter::Node<'a>,
        source: &[u8],
        var_name: &str,
        semantics: &LanguageSemantics,
        results: &mut Vec<(usize, usize)>,
    ) {
        let kind = node.kind();

        // Check for assignments
        if semantics.is_assignment(kind) || semantics.is_variable_declaration(kind) {
            let left = node
                .child_by_field_name(semantics.left_field)
                .or_else(|| node.child_by_field_name(semantics.name_field));

            if let Some(left) = left
                && let Ok(left_text) = left.utf8_text(source)
                && (left_text == var_name
                    || left_text.trim_start_matches("mut ").trim() == var_name)
            {
                results.push((node.id(), node.start_position().row + 1));
            }
        }

        // Recurse
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk_node(child, source, var_name, semantics, results);
        }
    }

    walk_node(
        parsed.tree.root_node(),
        source,
        var_name,
        semantics,
        &mut results,
    );

    results.sort_by_key(|(_, line)| *line);
    results
}

// =============================================================================
// Typestate Analyzer
// =============================================================================

/// The main typestate analyzer
pub struct TypestateAnalyzer {
    /// State machines to use for analysis
    state_machines: Vec<StateMachine>,
    /// Language semantics
    semantics: &'static LanguageSemantics,
}

impl TypestateAnalyzer {
    /// Create a new analyzer
    pub fn new(semantics: &'static LanguageSemantics) -> Self {
        Self {
            state_machines: Vec::new(),
            semantics,
        }
    }

    /// Add a state machine for analysis
    pub fn with_state_machine(mut self, sm: StateMachine) -> Self {
        self.state_machines.push(sm);
        self
    }

    /// Add multiple state machines
    pub fn with_state_machines(mut self, machines: Vec<StateMachine>) -> Self {
        self.state_machines.extend(machines);
        self
    }

    /// Get all state machines
    pub fn state_machines(&self) -> &[StateMachine] {
        &self.state_machines
    }

    /// Analyze a parsed file with CFG
    pub fn analyze(&self, parsed: &ParsedFile, cfg: &CFG) -> Vec<TypestateResult> {
        let mut results = Vec::new();

        // Find all variables that should be tracked
        let tracked_vars = self.find_tracked_variables(parsed);

        // Analyze each tracked variable
        for (var_name, sm) in tracked_vars {
            let result = self.track_variable_state(&var_name, sm, cfg, parsed);
            results.push(result);
        }

        results
    }

    /// Find variables that should be tracked by state machines
    fn find_tracked_variables<'a>(
        &'a self,
        parsed: &ParsedFile,
    ) -> Vec<(String, &'a StateMachine)> {
        let mut tracked = Vec::new();
        let source = parsed.content.as_bytes();

        // Walk the AST looking for variable declarations with tracked types
        fn walk_for_declarations<'a>(
            node: tree_sitter::Node,
            source: &[u8],
            semantics: &LanguageSemantics,
            state_machines: &'a [StateMachine],
            tracked: &mut Vec<(String, &'a StateMachine)>,
        ) {
            let kind = node.kind();

            // Check variable declarations
            if semantics.is_variable_declaration(kind) {
                // Try to extract the variable name and type
                let name = node
                    .child_by_field_name(semantics.name_field)
                    .or_else(|| node.child_by_field_name("name"))
                    .or_else(|| node.child_by_field_name("pattern"));

                let value = node
                    .child_by_field_name(semantics.value_field)
                    .or_else(|| node.child_by_field_name("value"));

                if let (Some(name_node), Some(value_node)) = (name, value)
                    && let Ok(var_name) = name_node.utf8_text(source)
                {
                    let var_name = var_name.trim_start_matches("mut ").trim().to_string();

                    // Check if the value is a call to a tracked type constructor
                    if semantics.is_call(value_node.kind())
                        && let Some(func) = value_node.child_by_field_name(semantics.function_field)
                        && let Ok(func_name) = func.utf8_text(source)
                    {
                        // Check if any state machine tracks this function/type
                        for sm in state_machines {
                            if sm.tracks_type(func_name)
                                || sm
                                    .transitions
                                    .iter()
                                    .any(|t| t.trigger.matches_function_return(func_name))
                            {
                                tracked.push((var_name.clone(), sm));
                                break;
                            }
                        }
                    }

                    // Also check for member access that returns tracked type
                    if semantics.is_member_access(value_node.kind())
                        && let Ok(expr_text) = value_node.utf8_text(source)
                    {
                        for sm in state_machines {
                            if sm.tracks_type(expr_text) {
                                tracked.push((var_name.clone(), sm));
                                break;
                            }
                        }
                    }
                }
            }

            // Recurse
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if !semantics.is_function_def(child.kind()) {
                    walk_for_declarations(child, source, semantics, state_machines, tracked);
                }
            }
        }

        walk_for_declarations(
            parsed.tree.root_node(),
            source,
            self.semantics,
            &self.state_machines,
            &mut tracked,
        );

        tracked
    }

    /// Track the state of a variable through the CFG
    pub fn track_variable_state(
        &self,
        var_name: &str,
        sm: &StateMachine,
        cfg: &CFG,
        parsed: &ParsedFile,
    ) -> TypestateResult {
        let mut result = TypestateResult::new(var_name, &sm.name);

        // Get method calls and assignments for this variable
        let method_calls = find_method_calls_on_var(parsed, var_name, self.semantics);
        let assignments = find_assignments_to_var(parsed, var_name, self.semantics);

        // Build a map from node_id to (method_name or "assignment")
        let mut node_events: HashMap<usize, (String, bool)> = HashMap::new(); // (event_name, is_method)
        for call in &method_calls {
            node_events.insert(call.node_id, (call.method_name.clone(), true));
        }
        for (node_id, _) in &assignments {
            node_events.insert(*node_id, ("__assignment__".to_string(), false));
        }

        // Initialize states for all blocks
        let initial_state = sm
            .initial_state()
            .map(|s| TrackedState::Known(s.name.clone()))
            .unwrap_or(TrackedState::Unknown);

        for block in &cfg.blocks {
            result.block_states.insert(block.id, TrackedState::Unknown);
            result
                .block_exit_states
                .insert(block.id, TrackedState::Unknown);
        }

        // Set entry block initial state
        result.block_states.insert(cfg.entry, initial_state.clone());

        // Forward dataflow analysis using worklist algorithm
        let mut worklist: VecDeque<BlockId> = VecDeque::new();
        let mut in_worklist: HashSet<BlockId> = HashSet::new();
        worklist.push_back(cfg.entry);
        in_worklist.insert(cfg.entry);

        let max_iterations = cfg.blocks.len() * 10;
        let mut iterations = 0;

        while let Some(block_id) = worklist.pop_front() {
            in_worklist.remove(&block_id);
            iterations += 1;

            if iterations > max_iterations {
                break;
            }

            if block_id >= cfg.blocks.len() {
                continue;
            }

            let block = &cfg.blocks[block_id];
            if !block.reachable {
                continue;
            }

            // Compute entry state from predecessors
            let entry_state = if block_id == cfg.entry {
                initial_state.clone()
            } else {
                let mut merged = TrackedState::Unknown;
                let mut has_pred = false;
                for &pred in &block.predecessors {
                    if let Some(pred_exit) = result.block_exit_states.get(&pred) {
                        if has_pred {
                            merged = merged.merge(pred_exit);
                        } else {
                            merged = pred_exit.clone();
                            has_pred = true;
                        }
                    }
                }
                merged
            };

            // Process statements in this block
            let mut current_state = entry_state.clone();

            for &stmt_node_id in &block.statements {
                // Check if this node has an event
                if let Some((event_name, is_method)) = node_events.get(&stmt_node_id) {
                    let line = self.get_line_for_node(parsed, stmt_node_id);

                    if *is_method {
                        // Method call - check for transition
                        current_state = self.apply_method_transition(
                            &current_state,
                            event_name,
                            sm,
                            stmt_node_id,
                            line,
                            var_name,
                            &mut result.violations,
                        );
                    } else {
                        // Assignment - might reset state or trigger null assignment
                        current_state = self.apply_assignment_transition(
                            &current_state,
                            sm,
                            stmt_node_id,
                            line,
                            var_name,
                            &mut result.violations,
                        );
                    }
                }
            }

            // Check for conflicting states and add violations
            if let TrackedState::Conflicting(states) = &current_state {
                let state_list: Vec<_> = states.iter().cloned().collect();
                result.violations.push(TypestateViolation::new(
                    ViolationKind::ConflictingStates,
                    block.statements.first().copied().unwrap_or(0),
                    self.get_line_for_block(parsed, cfg, block_id),
                    state_list.join(" | "),
                    format!(
                        "Variable '{}' has conflicting states at this point: {}",
                        var_name,
                        state_list.join(", ")
                    ),
                ));
            }

            // Update exit state
            let old_exit = result.block_exit_states.get(&block_id).cloned();
            let state_changed = old_exit.as_ref() != Some(&current_state);

            result.block_states.insert(block_id, entry_state);
            result.block_exit_states.insert(block_id, current_state);

            // If state changed, add successors to worklist
            if state_changed {
                for succ in cfg.successors(block_id) {
                    if !in_worklist.contains(&succ) {
                        worklist.push_back(succ);
                        in_worklist.insert(succ);
                    }
                }
            }
        }

        // Check for non-final states at exit points
        self.check_exit_states(&mut result, sm, cfg, parsed, var_name);

        result
    }

    /// Apply a method call transition
    fn apply_method_transition(
        &self,
        current_state: &TrackedState,
        method: &str,
        sm: &StateMachine,
        node_id: usize,
        line: usize,
        var_name: &str,
        violations: &mut Vec<TypestateViolation>,
    ) -> TrackedState {
        match current_state {
            TrackedState::Known(state_name) => {
                // Check if this state is an error state
                if sm.is_error_state(state_name) {
                    violations.push(
                        TypestateViolation::new(
                            ViolationKind::UseInErrorState,
                            node_id,
                            line,
                            state_name,
                            format!(
                                "Method '{}' called on '{}' which is in error state '{}'",
                                method, var_name, state_name
                            ),
                        )
                        .with_attempted_transition(method.to_string()),
                    );
                    return current_state.clone();
                }

                // Look for a valid transition
                if let Some(transition) = sm.get_method_transition(state_name, method) {
                    TrackedState::Known(transition.to.clone())
                } else {
                    // No valid transition - check if any transition from this state exists
                    let has_any_transition = sm.transitions.iter().any(|t| t.from == *state_name);

                    if has_any_transition {
                        violations.push(
                            TypestateViolation::new(
                                ViolationKind::InvalidTransition,
                                node_id,
                                line,
                                state_name,
                                format!(
                                    "Invalid method '{}' called on '{}' in state '{}' - no transition defined",
                                    method, var_name, state_name
                                ),
                            )
                            .with_attempted_transition(method.to_string()),
                        );
                    }
                    // Stay in current state (or could transition to error state)
                    current_state.clone()
                }
            }
            TrackedState::Unknown => TrackedState::Unknown,
            TrackedState::Conflicting(states) => {
                // Apply transition to each possible state
                let mut new_states = HashSet::new();
                for state_name in states {
                    if let Some(transition) = sm.get_method_transition(state_name, method) {
                        new_states.insert(transition.to.clone());
                    } else {
                        new_states.insert(state_name.clone());
                    }
                }
                if new_states.len() == 1 {
                    TrackedState::Known(new_states.into_iter().next().unwrap())
                } else {
                    TrackedState::Conflicting(new_states)
                }
            }
        }
    }

    /// Apply an assignment transition (e.g., x = null or x = new File())
    fn apply_assignment_transition(
        &self,
        current_state: &TrackedState,
        sm: &StateMachine,
        _node_id: usize,
        _line: usize,
        _var_name: &str,
        _violations: &mut Vec<TypestateViolation>,
    ) -> TrackedState {
        // Check for assignment transition
        if let TrackedState::Known(state_name) = current_state
            && let Some(transition) = sm.get_transition(state_name, &TransitionTrigger::Assignment)
        {
            return TrackedState::Known(transition.to.clone());
        }

        // Default: assignment resets to initial state (new object assigned)
        if let Some(initial) = sm.initial_state() {
            TrackedState::Known(initial.name.clone())
        } else {
            TrackedState::Unknown
        }
    }

    /// Check that all exit points have valid final states
    fn check_exit_states(
        &self,
        result: &mut TypestateResult,
        sm: &StateMachine,
        cfg: &CFG,
        parsed: &ParsedFile,
        var_name: &str,
    ) {
        // Find all blocks with Return or Unreachable terminators
        for block in &cfg.blocks {
            if !block.reachable {
                continue;
            }

            let is_exit = matches!(
                block.terminator,
                Terminator::Return | Terminator::Unreachable
            );

            if is_exit && let Some(exit_state) = result.block_exit_states.get(&block.id) {
                match exit_state {
                    TrackedState::Known(state_name) => {
                        if !sm.is_final_state(state_name) && !sm.is_error_state(state_name) {
                            let line = self.get_line_for_block(parsed, cfg, block.id);
                            result.violations.push(TypestateViolation::new(
                                    ViolationKind::NonFinalStateAtExit,
                                    block.statements.last().copied().unwrap_or(0),
                                    line,
                                    state_name,
                                    format!(
                                        "Variable '{}' is in state '{}' at function exit, but expected a final state ({})",
                                        var_name,
                                        state_name,
                                        sm.states.iter()
                                            .filter(|s| s.is_final)
                                            .map(|s| &s.name)
                                            .cloned()
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    ),
                                ));
                        }
                    }
                    TrackedState::Conflicting(states) => {
                        let non_final: Vec<_> = states
                            .iter()
                            .filter(|s| !sm.is_final_state(s))
                            .cloned()
                            .collect();

                        if !non_final.is_empty() {
                            let line = self.get_line_for_block(parsed, cfg, block.id);
                            result.violations.push(TypestateViolation::new(
                                    ViolationKind::NonFinalStateAtExit,
                                    block.statements.last().copied().unwrap_or(0),
                                    line,
                                    non_final.join(" | "),
                                    format!(
                                        "Variable '{}' may be in non-final state(s) {} at function exit",
                                        var_name,
                                        non_final.join(", ")
                                    ),
                                ));
                        }
                    }
                    TrackedState::Unknown => {
                        // Unknown state at exit - could be a problem but we're lenient
                    }
                }
            }
        }
    }

    /// Get the line number for an AST node
    fn get_line_for_node(&self, parsed: &ParsedFile, node_id: usize) -> usize {
        find_node_by_id(&parsed.tree, node_id)
            .map(|n| n.start_position().row + 1)
            .unwrap_or(0)
    }

    /// Get a representative line number for a block
    fn get_line_for_block(&self, parsed: &ParsedFile, cfg: &CFG, block_id: BlockId) -> usize {
        if block_id < cfg.blocks.len() {
            let block = &cfg.blocks[block_id];
            if let Some(&first_stmt) = block.statements.first() {
                return self.get_line_for_node(parsed, first_stmt);
            }
        }
        0
    }

    /// Get the transition for a method call (public API)
    pub fn get_transition<'a>(
        &self,
        sm: &'a StateMachine,
        method: &str,
        current_state: &str,
    ) -> Option<&'a Transition> {
        sm.get_method_transition(current_state, method)
    }

    /// Check if all paths to exit have valid final states (public API)
    pub fn check_all_paths_final(
        &self,
        sm: &StateMachine,
        cfg: &CFG,
        states: &HashMap<BlockId, String>,
    ) -> Vec<TypestateViolation> {
        let mut violations = Vec::new();

        for block in &cfg.blocks {
            if !block.reachable {
                continue;
            }

            let is_exit = matches!(
                block.terminator,
                Terminator::Return | Terminator::Unreachable
            );

            if is_exit
                && let Some(state) = states.get(&block.id)
                && !sm.is_final_state(state)
            {
                violations.push(TypestateViolation::new(
                    ViolationKind::NonFinalStateAtExit,
                    block.statements.last().copied().unwrap_or(0),
                    0,
                    state,
                    format!("Path exits with non-final state: {}", state),
                ));
            }
        }

        violations
    }
}

// =============================================================================
// Default State Machine for common patterns
// =============================================================================

/// Create a File state machine (Open/Closed)
pub fn file_state_machine() -> StateMachine {
    StateMachine::new("File")
        .with_state(State::initial("Unopened"))
        .with_state(State::new("Open").with_final(false))
        .with_state(State::final_state("Closed"))
        .with_state(State::error("UseAfterClose"))
        .with_transition(Transition::on_method("Unopened", "Open", "open"))
        .with_transition(Transition::on_method("Unopened", "Open", "create"))
        .with_transition(Transition::on_method("Open", "Open", "read"))
        .with_transition(Transition::on_method("Open", "Open", "write"))
        .with_transition(Transition::on_method("Open", "Open", "flush"))
        .with_transition(Transition::on_method("Open", "Closed", "close"))
        .with_transition(Transition::on_method("Closed", "UseAfterClose", "read"))
        .with_transition(Transition::on_method("Closed", "UseAfterClose", "write"))
        .with_tracked_types(&["File", "std::fs::File", "fs.File", "FileHandle"])
}

/// Create a Lock state machine (Unlocked/Locked)
pub fn lock_state_machine() -> StateMachine {
    StateMachine::new("Lock")
        .with_state(State::initial("Unlocked").with_final(true))
        .with_state(State::new("Locked").with_final(false))
        .with_state(State::error("DoubleLock"))
        .with_state(State::error("DoubleUnlock"))
        .with_transition(Transition::on_method("Unlocked", "Locked", "lock"))
        .with_transition(Transition::on_method("Unlocked", "Locked", "acquire"))
        .with_transition(Transition::on_method("Locked", "Unlocked", "unlock"))
        .with_transition(Transition::on_method("Locked", "Unlocked", "release"))
        .with_transition(Transition::on_method("Locked", "DoubleLock", "lock"))
        .with_transition(Transition::on_method("Unlocked", "DoubleUnlock", "unlock"))
        .with_tracked_types(&["Lock", "Mutex", "RwLock", "sync.Mutex"])
}

/// Create a Database Connection state machine
pub fn connection_state_machine() -> StateMachine {
    StateMachine::new("Connection")
        .with_state(State::initial("Disconnected"))
        .with_state(State::new("Connected").with_final(false))
        .with_state(State::final_state("Closed"))
        .with_state(State::error("UseAfterClose"))
        .with_transition(Transition::on_method(
            "Disconnected",
            "Connected",
            "connect",
        ))
        .with_transition(Transition::on_method("Disconnected", "Connected", "open"))
        .with_transition(Transition::on_method("Connected", "Connected", "query"))
        .with_transition(Transition::on_method("Connected", "Connected", "execute"))
        .with_transition(Transition::on_method("Connected", "Closed", "close"))
        .with_transition(Transition::on_method("Connected", "Closed", "disconnect"))
        .with_transition(Transition::on_method("Closed", "UseAfterClose", "query"))
        .with_transition(Transition::on_method("Closed", "UseAfterClose", "execute"))
        .with_tracked_types(&["Connection", "DatabaseConnection", "DbConnection", "sql.DB"])
}

/// Create an Iterator state machine (for detecting use after exhaustion in some contexts)
pub fn iterator_state_machine() -> StateMachine {
    StateMachine::new("Iterator")
        .with_state(State::initial("Ready").with_final(true))
        .with_state(State::new("Iterating").with_final(true))
        .with_state(State::new("Exhausted").with_final(true))
        .with_transition(Transition::on_method("Ready", "Iterating", "next"))
        .with_transition(Transition::on_method("Iterating", "Iterating", "next"))
        .with_transition(Transition::on_method("Iterating", "Exhausted", "collect"))
        .with_tracked_types(&["Iterator", "IntoIterator"])
}

// =============================================================================
// FlowContext Integration
// =============================================================================

use crate::flow::FlowContext;

impl FlowContext {
    /// Analyze typestate for tracked variables
    ///
    /// Note: This is a placeholder. Use `compute_typestate` in the main FlowContext
    /// implementation which takes the parsed file as a parameter.
    pub fn analyze_typestate(&mut self, _state_machines: &[StateMachine]) -> Vec<TypestateResult> {
        // This would require storing the ParsedFile reference, which we don't have
        // Instead, use compute_typestate() in mod.rs which takes parsed file as parameter
        Vec::new() // Placeholder - actual implementation requires parsed file
    }
}

/// Analyze typestate with full context
pub fn analyze_typestate_with_context(
    parsed: &ParsedFile,
    cfg: &CFG,
    semantics: &'static LanguageSemantics,
    state_machines: &[StateMachine],
) -> Vec<TypestateResult> {
    let analyzer = TypestateAnalyzer::new(semantics).with_state_machines(state_machines.to_vec());
    analyzer.analyze(parsed, cfg)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::cfg::CFG;
    use rma_common::Language;
    use rma_parser::ParserEngine;
    use std::path::Path;

    fn parse_js(code: &str) -> ParsedFile {
        let config = rma_common::RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser
            .parse_file(Path::new("test.js"), code)
            .expect("parse failed")
    }

    fn parse_rust(code: &str) -> ParsedFile {
        let config = rma_common::RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser
            .parse_file(Path::new("test.rs"), code)
            .expect("parse failed")
    }

    // =========================================================================
    // State Machine Definition Tests
    // =========================================================================

    #[test]
    fn test_state_creation() {
        let s = State::new("Open");
        assert_eq!(s.name, "Open");
        assert!(!s.is_initial);
        assert!(!s.is_final);
        assert!(!s.is_error);

        let initial = State::initial("Start");
        assert!(initial.is_initial);

        let final_state = State::final_state("End");
        assert!(final_state.is_final);

        let error = State::error("Error");
        assert!(error.is_error);
    }

    #[test]
    fn test_state_builder() {
        let s = State::new("Test").with_initial(true).with_final(true);
        assert!(s.is_initial);
        assert!(s.is_final);
    }

    #[test]
    fn test_transition_creation() {
        let t = Transition::on_method("Open", "Closed", "close");
        assert_eq!(t.from, "Open");
        assert_eq!(t.to, "Closed");
        assert!(t.trigger.matches_method("close"));
        assert!(!t.trigger.matches_method("open"));
    }

    #[test]
    fn test_state_machine_creation() {
        let sm = file_state_machine();
        assert_eq!(sm.name, "File");
        assert!(!sm.states.is_empty());
        assert!(!sm.transitions.is_empty());

        let initial = sm.initial_state();
        assert!(initial.is_some());
        assert_eq!(initial.unwrap().name, "Unopened");

        assert!(sm.is_final_state("Closed"));
        assert!(!sm.is_final_state("Open"));
        assert!(sm.is_error_state("UseAfterClose"));
    }

    #[test]
    fn test_state_machine_transitions() {
        let sm = file_state_machine();

        // Valid transitions
        let t = sm.get_method_transition("Open", "close");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "Closed");

        // Invalid transition
        let t = sm.get_method_transition("Closed", "close");
        assert!(t.is_none());

        // Error transition
        let t = sm.get_method_transition("Closed", "read");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "UseAfterClose");
    }

    #[test]
    fn test_tracks_type() {
        let sm = file_state_machine();
        assert!(sm.tracks_type("File"));
        assert!(sm.tracks_type("std::fs::File"));
        assert!(sm.tracks_type("my::module::File")); // ends with "File"
        assert!(!sm.tracks_type("Connection")); // Different type entirely
        assert!(!sm.tracks_type("Lock")); // Different type
    }

    // =========================================================================
    // TrackedState Tests
    // =========================================================================

    #[test]
    fn test_tracked_state_merge_same() {
        let a = TrackedState::Known("Open".to_string());
        let b = TrackedState::Known("Open".to_string());
        let merged = a.merge(&b);
        assert_eq!(merged, TrackedState::Known("Open".to_string()));
    }

    #[test]
    fn test_tracked_state_merge_different() {
        let a = TrackedState::Known("Open".to_string());
        let b = TrackedState::Known("Closed".to_string());
        let merged = a.merge(&b);
        match merged {
            TrackedState::Conflicting(states) => {
                assert!(states.contains("Open"));
                assert!(states.contains("Closed"));
            }
            _ => panic!("Expected Conflicting state"),
        }
    }

    #[test]
    fn test_tracked_state_merge_with_unknown() {
        let a = TrackedState::Known("Open".to_string());
        let b = TrackedState::Unknown;
        let merged = a.merge(&b);
        assert_eq!(merged, TrackedState::Known("Open".to_string()));
    }

    // =========================================================================
    // Violation Tests
    // =========================================================================

    #[test]
    fn test_violation_creation() {
        let v = TypestateViolation::new(
            ViolationKind::InvalidTransition,
            123,
            5,
            "Open",
            "Cannot call close() when file is already closed",
        )
        .with_attempted_transition("close");

        assert_eq!(v.kind, ViolationKind::InvalidTransition);
        assert_eq!(v.location, 123);
        assert_eq!(v.line, 5);
        assert_eq!(v.current_state, "Open");
        assert_eq!(v.attempted_transition, Some("close".to_string()));
    }

    #[test]
    fn test_violation_kind_display() {
        assert_eq!(
            format!("{}", ViolationKind::InvalidTransition),
            "Invalid state transition"
        );
        assert_eq!(
            format!("{}", ViolationKind::UseInErrorState),
            "Use of object in error state"
        );
    }

    // =========================================================================
    // Method Call Detection Tests
    // =========================================================================

    #[test]
    fn test_find_method_calls() {
        let code = r#"
            const file = openFile("test.txt");
            file.read();
            file.write("data");
            file.close();
        "#;
        let parsed = parse_js(code);
        let semantics = crate::semantics::LanguageSemantics::for_language(Language::JavaScript);

        let calls = find_method_calls_on_var(&parsed, "file", semantics);

        // Should find read, write, close
        let method_names: Vec<_> = calls.iter().map(|c| c.method_name.as_str()).collect();
        assert!(method_names.contains(&"read"), "Should find read()");
        assert!(method_names.contains(&"write"), "Should find write()");
        assert!(method_names.contains(&"close"), "Should find close()");
    }

    #[test]
    fn test_find_method_calls_different_var() {
        let code = r#"
            const file1 = openFile("a.txt");
            const file2 = openFile("b.txt");
            file1.read();
            file2.write();
        "#;
        let parsed = parse_js(code);
        let semantics = crate::semantics::LanguageSemantics::for_language(Language::JavaScript);

        let calls1 = find_method_calls_on_var(&parsed, "file1", semantics);
        let calls2 = find_method_calls_on_var(&parsed, "file2", semantics);

        assert_eq!(calls1.len(), 1);
        assert_eq!(calls1[0].method_name, "read");

        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].method_name, "write");
    }

    // =========================================================================
    // TypestateResult Tests
    // =========================================================================

    #[test]
    fn test_typestate_result() {
        let mut result = TypestateResult::new("file", "File");
        assert_eq!(result.variable, "file");
        assert_eq!(result.state_machine, "File");
        assert!(!result.has_violations());

        result.violations.push(TypestateViolation::new(
            ViolationKind::InvalidTransition,
            0,
            1,
            "Closed",
            "Test violation",
        ));
        assert!(result.has_violations());
    }

    // =========================================================================
    // Analyzer Tests
    // =========================================================================

    #[test]
    fn test_analyzer_creation() {
        let semantics = crate::semantics::LanguageSemantics::for_language(Language::JavaScript);
        let analyzer = TypestateAnalyzer::new(semantics)
            .with_state_machine(file_state_machine())
            .with_state_machine(lock_state_machine());

        assert_eq!(analyzer.state_machines().len(), 2);
    }

    #[test]
    fn test_analyzer_basic_file_operations() {
        let code = r#"
            function process() {
                const file = File.open("test.txt");
                file.read();
                file.close();
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = crate::semantics::LanguageSemantics::for_language(Language::JavaScript);

        let analyzer = TypestateAnalyzer::new(semantics).with_state_machine(file_state_machine());

        // This tests that the analyzer doesn't panic
        let _results = analyzer.analyze(&parsed, &cfg);
    }

    #[test]
    fn test_simple_state_tracking() {
        // Create a simple state machine
        let sm = StateMachine::new("TestSM")
            .with_state(State::initial("A"))
            .with_state(State::new("B"))
            .with_state(State::final_state("C"))
            .with_transition(Transition::on_method("A", "B", "step1"))
            .with_transition(Transition::on_method("B", "C", "step2"))
            .with_tracked_type("TestType");

        let semantics = crate::semantics::LanguageSemantics::for_language(Language::JavaScript);
        let analyzer = TypestateAnalyzer::new(semantics).with_state_machine(sm.clone());

        // Test get_transition
        let t = analyzer.get_transition(&sm, "step1", "A");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "B");

        let t = analyzer.get_transition(&sm, "step1", "B");
        assert!(t.is_none());
    }

    // =========================================================================
    // Lock State Machine Tests
    // =========================================================================

    #[test]
    fn test_lock_state_machine() {
        let sm = lock_state_machine();

        assert!(sm.initial_state().is_some());
        assert_eq!(sm.initial_state().unwrap().name, "Unlocked");

        // Unlocked is both initial and final
        assert!(sm.is_final_state("Unlocked"));
        assert!(!sm.is_final_state("Locked"));

        // Error states
        assert!(sm.is_error_state("DoubleLock"));
        assert!(sm.is_error_state("DoubleUnlock"));
    }

    #[test]
    fn test_lock_transitions() {
        let sm = lock_state_machine();

        // Normal lock/unlock
        let t = sm.get_method_transition("Unlocked", "lock");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "Locked");

        let t = sm.get_method_transition("Locked", "unlock");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "Unlocked");

        // Double lock error
        let t = sm.get_method_transition("Locked", "lock");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "DoubleLock");

        // Double unlock error
        let t = sm.get_method_transition("Unlocked", "unlock");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "DoubleUnlock");
    }

    // =========================================================================
    // Connection State Machine Tests
    // =========================================================================

    #[test]
    fn test_connection_state_machine() {
        let sm = connection_state_machine();

        assert_eq!(sm.initial_state().unwrap().name, "Disconnected");
        assert!(sm.is_final_state("Closed"));
        assert!(sm.is_error_state("UseAfterClose"));

        // Connect and query
        let t = sm.get_method_transition("Disconnected", "connect");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "Connected");

        let t = sm.get_method_transition("Connected", "query");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "Connected"); // Stays connected

        let t = sm.get_method_transition("Connected", "close");
        assert!(t.is_some());
        assert_eq!(t.unwrap().to, "Closed");
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_analyze_typestate_with_context() {
        let code = r#"
            function test() {
                const f = File.open("x");
                f.read();
                return;
            }
        "#;
        let parsed = parse_js(code);
        let cfg = CFG::build(&parsed, Language::JavaScript);
        let semantics = crate::semantics::LanguageSemantics::for_language(Language::JavaScript);

        let state_machines = vec![file_state_machine()];
        let _results = analyze_typestate_with_context(&parsed, &cfg, semantics, &state_machines);

        // Should not panic
    }

    #[test]
    fn test_multiple_state_machines() {
        let semantics = crate::semantics::LanguageSemantics::for_language(Language::JavaScript);
        let analyzer = TypestateAnalyzer::new(semantics).with_state_machines(vec![
            file_state_machine(),
            lock_state_machine(),
            connection_state_machine(),
        ]);

        assert_eq!(analyzer.state_machines().len(), 3);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_empty_state_machine() {
        let sm = StateMachine::new("Empty");
        assert!(sm.initial_state().is_none());
        assert!(sm.states.is_empty());
        assert!(sm.transitions.is_empty());
    }

    #[test]
    fn test_wildcard_method_transition() {
        let sm = StateMachine::new("Test")
            .with_state(State::initial("Any"))
            .with_transition(Transition::on_method("Any", "Any", "*"));

        // Wildcard should match any method
        assert!(sm.get_method_transition("Any", "foo").is_some());
        assert!(sm.get_method_transition("Any", "bar").is_some());
    }

    #[test]
    fn test_conflicting_states_at_merge() {
        // Test that conflicting states are properly detected
        let a = TrackedState::Known("Open".to_string());
        let b = TrackedState::Known("Closed".to_string());
        let c = TrackedState::Known("Open".to_string());

        // a and b conflict
        let merged = a.merge(&b);
        match &merged {
            TrackedState::Conflicting(states) => {
                assert_eq!(states.len(), 2);
            }
            _ => panic!("Expected conflicting"),
        }

        // merging conflicting with same state
        let merged2 = merged.merge(&c);
        match merged2 {
            TrackedState::Conflicting(states) => {
                assert_eq!(states.len(), 2); // Still just Open and Closed
            }
            _ => panic!("Expected conflicting"),
        }
    }

    #[test]
    fn test_rust_semantics() {
        let code = r#"
            fn main() {
                let file = File::open("test.txt").unwrap();
                file.read_to_string(&mut s);
            }
        "#;
        let parsed = parse_rust(code);
        let cfg = CFG::build(&parsed, Language::Rust);
        let semantics = crate::semantics::LanguageSemantics::for_language(Language::Rust);

        let analyzer = TypestateAnalyzer::new(semantics).with_state_machine(file_state_machine());

        // Should not panic even with Rust code
        let _results = analyzer.analyze(&parsed, &cfg);
    }
}
