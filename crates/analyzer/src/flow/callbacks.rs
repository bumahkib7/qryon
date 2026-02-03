//! Callback and Higher-Order Function Taint Propagation
//!
//! This module provides taint tracking through callback patterns that traditionally
//! break taint analysis. It handles:
//!
//! - **Array methods**: map, filter, forEach, reduce, find, some, every
//! - **Promise chains**: .then(), .catch(), .finally()
//! - **Event handlers**: on('event', handler), addEventListener()
//! - **Async callbacks**: setTimeout, setImmediate, setInterval, process.nextTick
//!
//! The core insight is that taint flows through higher-order functions:
//! - `taintedArray.map(x => sink(x))` - taint flows from array elements to `x`
//! - `taintedPromise.then(result => sink(result))` - taint flows to `result`
//! - `emitter.on('data', data => sink(data))` - taint flows from emit args to handler params
//!
//! # Example
//!
//! ```ignore
//! // This code has a taint flow that traditional analysis misses:
//! const userInputs = req.body.items;  // tainted array
//! userInputs.forEach(item => {        // item is tainted!
//!     db.query(`SELECT * FROM t WHERE id = ${item}`);  // SQL injection
//! });
//! ```

use crate::semantics::LanguageSemantics;
use rma_common::Language;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Represents a site where a callback is registered
///
/// Captures the location and context where a callback function is passed
/// to a higher-order function or event handler registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallbackSite {
    /// File containing this callback site
    pub file: PathBuf,
    /// Line number of the callback registration
    pub line: usize,
    /// Column number
    pub column: usize,
    /// The higher-order function being called (e.g., "map", "then", "on")
    pub hof_name: String,
    /// The receiver object/variable if method call (e.g., "userInputs" in "userInputs.map")
    pub receiver: Option<String>,
    /// Kind of callback pattern detected
    pub kind: CallbackKind,
    /// The callback function parameters
    pub callback_params: Vec<String>,
    /// Function containing this callback site (if known)
    pub containing_function: Option<String>,
    /// Node ID in AST
    pub node_id: usize,
}

/// Classification of callback patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallbackKind {
    /// Array iteration methods: map, filter, forEach, find, some, every
    ArrayIterator,
    /// Array reduction methods: reduce, reduceRight
    ArrayReducer,
    /// Promise chain methods: then, catch, finally
    PromiseChain,
    /// Event handler registration: on, once, addEventListener
    EventHandler,
    /// Timer callbacks: setTimeout, setInterval, setImmediate
    TimerCallback,
    /// Generic higher-order function
    HigherOrderFunction,
}

impl CallbackKind {
    /// Get the parameter index that receives tainted data for this callback kind
    pub fn tainted_param_index(&self) -> usize {
        match self {
            // Array iterators: first param is the element
            CallbackKind::ArrayIterator => 0,
            // Array reducers: second param is the current element (first is accumulator)
            CallbackKind::ArrayReducer => 1,
            // Promise chains: first param is the resolved value
            CallbackKind::PromiseChain => 0,
            // Event handlers: first param is the event data
            CallbackKind::EventHandler => 0,
            // Timer callbacks don't directly receive taint (no data flow)
            CallbackKind::TimerCallback => usize::MAX,
            // Generic HOF: assume first param
            CallbackKind::HigherOrderFunction => 0,
        }
    }
}

/// Describes how taint flows into callback parameters
#[derive(Debug, Clone)]
pub struct CallbackTaintFlow {
    /// The callback site where this flow originates
    pub callback_site: CallbackSite,
    /// Source of taint (variable or expression)
    pub taint_source: TaintSource,
    /// Target parameter in the callback
    pub target_param: String,
    /// Index of the target parameter
    pub target_param_index: usize,
    /// Whether the taint is definite or potential
    pub confidence: TaintConfidence,
}

/// Source of taint flowing into a callback
#[derive(Debug, Clone)]
pub enum TaintSource {
    /// Taint from array elements: arr.map(x => ...) where arr is tainted
    ArrayElements(String),
    /// Taint from promise resolution: promise.then(x => ...) where promise resolves to tainted
    PromiseResolution(String),
    /// Taint from event data: emitter.on('event', data => ...) where emit passes tainted data
    EventData { event_name: String, emitter: String },
    /// Taint from accumulator in reduce
    Accumulator(String),
    /// Direct variable reference
    Variable(String),
}

/// Confidence level for taint propagation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintConfidence {
    /// Definite taint flow (e.g., receiver is known to be tainted)
    Definite,
    /// Possible taint flow (e.g., may depend on runtime conditions)
    Possible,
    /// Speculative taint flow (e.g., unknown receiver type)
    Speculative,
}

/// Registry of callback patterns and their taint flows
#[derive(Debug, Default)]
pub struct CallbackRegistry {
    /// All detected callback sites
    callback_sites: Vec<CallbackSite>,
    /// Callback sites indexed by receiver variable
    by_receiver: HashMap<String, Vec<usize>>,
    /// Callback sites indexed by HOF name
    by_hof_name: HashMap<String, Vec<usize>>,
    /// Detected taint flows through callbacks
    taint_flows: Vec<CallbackTaintFlow>,
    /// Variables known to be tainted
    tainted_vars: HashSet<String>,
}

impl CallbackRegistry {
    /// Create a new callback registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry with initial tainted variables
    pub fn with_tainted_vars(tainted_vars: HashSet<String>) -> Self {
        Self {
            tainted_vars,
            ..Default::default()
        }
    }

    /// Register a callback site
    pub fn register_callback(&mut self, site: CallbackSite) {
        let index = self.callback_sites.len();

        // Index by receiver
        if let Some(ref receiver) = site.receiver {
            self.by_receiver
                .entry(receiver.clone())
                .or_default()
                .push(index);
        }

        // Index by HOF name
        self.by_hof_name
            .entry(site.hof_name.clone())
            .or_default()
            .push(index);

        self.callback_sites.push(site);
    }

    /// Add a tainted variable
    pub fn add_tainted_var(&mut self, var: String) {
        self.tainted_vars.insert(var);
    }

    /// Check if a variable is tainted
    pub fn is_tainted(&self, var: &str) -> bool {
        self.tainted_vars.contains(var)
    }

    /// Compute taint flows based on registered callbacks and tainted variables
    pub fn compute_taint_flows(&mut self) {
        self.taint_flows.clear();

        for site in &self.callback_sites {
            if let Some(flow) = self.compute_flow_for_site(site) {
                self.taint_flows.push(flow);
            }
        }
    }

    fn compute_flow_for_site(&self, site: &CallbackSite) -> Option<CallbackTaintFlow> {
        let tainted_param_idx = site.kind.tainted_param_index();
        if tainted_param_idx == usize::MAX {
            return None; // This callback kind doesn't propagate taint
        }

        let target_param = site.callback_params.get(tainted_param_idx)?;

        // Determine taint source based on callback kind
        let (taint_source, confidence) = match site.kind {
            CallbackKind::ArrayIterator | CallbackKind::ArrayReducer => {
                if let Some(ref receiver) = site.receiver {
                    if self.tainted_vars.contains(receiver) {
                        (
                            TaintSource::ArrayElements(receiver.clone()),
                            TaintConfidence::Definite,
                        )
                    } else {
                        // Check if receiver might be tainted through member access
                        let possibly_tainted = self.tainted_vars.iter().any(|t| {
                            receiver.starts_with(t) || receiver.contains(&format!(".{}", t))
                        });
                        if possibly_tainted {
                            (
                                TaintSource::ArrayElements(receiver.clone()),
                                TaintConfidence::Possible,
                            )
                        } else {
                            return None;
                        }
                    }
                } else {
                    return None;
                }
            }

            CallbackKind::PromiseChain => {
                if let Some(ref receiver) = site.receiver {
                    if self.tainted_vars.contains(receiver) {
                        (
                            TaintSource::PromiseResolution(receiver.clone()),
                            TaintConfidence::Definite,
                        )
                    } else {
                        // Promises may be tainted through their origin
                        (
                            TaintSource::PromiseResolution(receiver.clone()),
                            TaintConfidence::Speculative,
                        )
                    }
                } else {
                    return None;
                }
            }

            CallbackKind::EventHandler => {
                // Event handlers: need to check if the emitter receives tainted data
                // This is typically handled by event-based analysis
                if let Some(ref receiver) = site.receiver {
                    (
                        TaintSource::EventData {
                            event_name: site.hof_name.clone(),
                            emitter: receiver.clone(),
                        },
                        TaintConfidence::Possible,
                    )
                } else {
                    return None;
                }
            }

            CallbackKind::TimerCallback => {
                // Timer callbacks don't propagate taint through parameters
                return None;
            }

            CallbackKind::HigherOrderFunction => {
                // Generic HOF: check if any argument might be tainted
                if let Some(ref receiver) = site.receiver {
                    if self.tainted_vars.contains(receiver) {
                        (
                            TaintSource::Variable(receiver.clone()),
                            TaintConfidence::Possible,
                        )
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
        };

        Some(CallbackTaintFlow {
            callback_site: site.clone(),
            taint_source,
            target_param: target_param.clone(),
            target_param_index: tainted_param_idx,
            confidence,
        })
    }

    /// Get all detected taint flows
    pub fn taint_flows(&self) -> &[CallbackTaintFlow] {
        &self.taint_flows
    }

    /// Get callback sites for a specific receiver variable
    pub fn callbacks_for_receiver(&self, receiver: &str) -> Vec<&CallbackSite> {
        self.by_receiver
            .get(receiver)
            .map(|indices| indices.iter().map(|&i| &self.callback_sites[i]).collect())
            .unwrap_or_default()
    }

    /// Get callback sites for a specific HOF name
    pub fn callbacks_for_hof(&self, hof_name: &str) -> Vec<&CallbackSite> {
        self.by_hof_name
            .get(hof_name)
            .map(|indices| indices.iter().map(|&i| &self.callback_sites[i]).collect())
            .unwrap_or_default()
    }

    /// Get all callback sites
    pub fn all_callbacks(&self) -> &[CallbackSite] {
        &self.callback_sites
    }

    /// Get tainted callback parameters (variables that should be marked tainted)
    pub fn tainted_callback_params(&self) -> HashSet<String> {
        self.taint_flows
            .iter()
            .filter(|f| f.confidence != TaintConfidence::Speculative)
            .map(|f| f.target_param.clone())
            .collect()
    }
}

/// Patterns for detecting callback registrations
pub struct CallbackPatterns {
    /// Array iterator methods
    pub array_iterators: &'static [&'static str],
    /// Array reducer methods
    pub array_reducers: &'static [&'static str],
    /// Promise chain methods
    pub promise_methods: &'static [&'static str],
    /// Event handler registration methods
    pub event_handlers: &'static [&'static str],
    /// Timer callback functions
    pub timer_functions: &'static [&'static str],
}

impl CallbackPatterns {
    /// Get callback patterns for a specific language
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self {
                array_iterators: &[
                    "map",
                    "filter",
                    "forEach",
                    "find",
                    "findIndex",
                    "some",
                    "every",
                    "flatMap",
                ],
                array_reducers: &["reduce", "reduceRight"],
                promise_methods: &["then", "catch", "finally"],
                event_handlers: &["on", "once", "addEventListener", "addListener", "subscribe"],
                timer_functions: &[
                    "setTimeout",
                    "setInterval",
                    "setImmediate",
                    "requestAnimationFrame",
                    "queueMicrotask",
                ],
            },
            Language::Python => Self {
                array_iterators: &["map", "filter"],
                array_reducers: &["reduce"],
                promise_methods: &[], // Python uses async/await differently
                event_handlers: &["connect", "on"],
                timer_functions: &["call_later", "call_at", "call_soon"],
            },
            Language::Java => Self {
                array_iterators: &[
                    "map",
                    "filter",
                    "forEach",
                    "findFirst",
                    "findAny",
                    "anyMatch",
                    "allMatch",
                    "noneMatch",
                ],
                array_reducers: &["reduce", "collect"],
                promise_methods: &["thenApply", "thenAccept", "thenCompose", "exceptionally"],
                event_handlers: &["addListener", "subscribe", "on"],
                timer_functions: &["schedule", "scheduleAtFixedRate"],
            },
            Language::Go => Self {
                // Go doesn't have traditional callbacks in the same way
                array_iterators: &[],
                array_reducers: &[],
                promise_methods: &[],
                event_handlers: &[],
                timer_functions: &["AfterFunc"],
            },
            Language::Rust => Self {
                array_iterators: &[
                    "map", "filter", "for_each", "find", "any", "all", "flat_map",
                ],
                array_reducers: &["fold", "reduce"],
                promise_methods: &["and_then", "map", "map_err", "or_else"],
                event_handlers: &[],
                timer_functions: &[],
            },
            _ => Self {
                array_iterators: &[],
                array_reducers: &[],
                promise_methods: &[],
                event_handlers: &[],
                timer_functions: &[],
            },
        }
    }

    /// Classify a method/function name as a callback pattern
    pub fn classify(&self, name: &str) -> Option<CallbackKind> {
        if self.array_iterators.contains(&name) {
            Some(CallbackKind::ArrayIterator)
        } else if self.array_reducers.contains(&name) {
            Some(CallbackKind::ArrayReducer)
        } else if self.promise_methods.contains(&name) {
            Some(CallbackKind::PromiseChain)
        } else if self.event_handlers.contains(&name) {
            Some(CallbackKind::EventHandler)
        } else if self.timer_functions.contains(&name) {
            Some(CallbackKind::TimerCallback)
        } else {
            None
        }
    }

    /// Check if a name is any kind of callback pattern
    pub fn is_callback_pattern(&self, name: &str) -> bool {
        self.classify(name).is_some()
    }
}

/// Analyzer for detecting callback patterns in AST
pub struct CallbackAnalyzer<'a> {
    /// Language semantics
    semantics: &'static LanguageSemantics,
    /// Callback patterns for the language
    patterns: CallbackPatterns,
    /// Source code bytes
    source: &'a [u8],
    /// Currently tainted variables
    tainted_vars: HashSet<String>,
    /// Current file path
    file_path: PathBuf,
}

impl<'a> CallbackAnalyzer<'a> {
    /// Create a new callback analyzer
    pub fn new(
        semantics: &'static LanguageSemantics,
        source: &'a [u8],
        file_path: PathBuf,
    ) -> Self {
        let language = semantics.language_enum();
        Self {
            semantics,
            patterns: CallbackPatterns::for_language(language),
            source,
            tainted_vars: HashSet::new(),
            file_path,
        }
    }

    /// Create analyzer with initial tainted variables
    pub fn with_tainted_vars(
        semantics: &'static LanguageSemantics,
        source: &'a [u8],
        file_path: PathBuf,
        tainted_vars: HashSet<String>,
    ) -> Self {
        let language = semantics.language_enum();
        Self {
            semantics,
            patterns: CallbackPatterns::for_language(language),
            source,
            tainted_vars,
            file_path,
        }
    }

    /// Analyze a tree-sitter tree for callback patterns
    pub fn analyze(&self, tree: &tree_sitter::Tree) -> CallbackRegistry {
        let mut registry = CallbackRegistry::with_tainted_vars(self.tainted_vars.clone());

        let root = tree.root_node();
        self.walk_for_callbacks(root, &mut registry, None);

        // Compute taint flows after collecting all callback sites
        registry.compute_taint_flows();

        registry
    }

    fn walk_for_callbacks(
        &self,
        node: tree_sitter::Node,
        registry: &mut CallbackRegistry,
        current_function: Option<String>,
    ) {
        // Track current function context
        let func_context = if self.semantics.is_function_def(node.kind()) {
            self.extract_function_name(node)
                .or(current_function.clone())
        } else {
            current_function.clone()
        };

        // Check for call expressions that might be callback registrations
        if self.semantics.is_call(node.kind())
            && let Some(callback_site) = self.extract_callback_site(node, &func_context)
        {
            registry.register_callback(callback_site);
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_for_callbacks(child, registry, func_context.clone());
        }
    }

    fn extract_callback_site(
        &self,
        node: tree_sitter::Node,
        containing_function: &Option<String>,
    ) -> Option<CallbackSite> {
        // Get the function being called
        let func_node = node
            .child_by_field_name(self.semantics.function_field)
            .or_else(|| node.child(0))?;

        let (hof_name, receiver) = self.extract_hof_and_receiver(func_node)?;

        // Check if this is a known callback pattern
        let kind = self.patterns.classify(&hof_name)?;

        // Extract callback parameters
        let callback_params = self.extract_callback_params(node)?;

        Some(CallbackSite {
            file: self.file_path.clone(),
            line: node.start_position().row + 1,
            column: node.start_position().column,
            hof_name,
            receiver,
            kind,
            callback_params,
            containing_function: containing_function.clone(),
            node_id: node.id(),
        })
    }

    fn extract_hof_and_receiver(
        &self,
        func_node: tree_sitter::Node,
    ) -> Option<(String, Option<String>)> {
        match func_node.kind() {
            "member_expression" | "field_expression" | "attribute" | "selector_expression" => {
                // Method call: receiver.method(...)
                let method_name = func_node
                    .child_by_field_name(self.semantics.property_field)
                    .or_else(|| {
                        // Try last named child as property
                        let count = func_node.named_child_count();
                        if count > 0 {
                            func_node.named_child(count - 1)
                        } else {
                            None
                        }
                    })?
                    .utf8_text(self.source)
                    .ok()?
                    .to_string();

                let receiver = func_node
                    .child_by_field_name(self.semantics.object_field)
                    .or_else(|| func_node.named_child(0))
                    .and_then(|n| {
                        if n.kind() == "identifier" {
                            n.utf8_text(self.source).ok().map(String::from)
                        } else {
                            // Try to get the full receiver expression for member chains
                            n.utf8_text(self.source).ok().map(String::from)
                        }
                    });

                Some((method_name, receiver))
            }
            "identifier" => {
                // Direct function call: setTimeout(...)
                let name = func_node.utf8_text(self.source).ok()?.to_string();
                Some((name, None))
            }
            _ => None,
        }
    }

    fn extract_callback_params(&self, call_node: tree_sitter::Node) -> Option<Vec<String>> {
        let args_node = call_node.child_by_field_name(self.semantics.arguments_field)?;

        // Find the callback argument (usually an arrow function or function expression)
        let mut cursor = args_node.walk();
        for arg in args_node.named_children(&mut cursor) {
            match arg.kind() {
                "arrow_function" | "function_expression" | "function" | "lambda" => {
                    return self.extract_function_params(arg);
                }
                _ => continue,
            }
        }

        None
    }

    fn extract_function_params(&self, func_node: tree_sitter::Node) -> Option<Vec<String>> {
        let params_node = func_node.child_by_field_name(self.semantics.parameters_field)?;
        let mut params = Vec::new();

        let mut cursor = params_node.walk();
        for param in params_node.named_children(&mut cursor) {
            match param.kind() {
                "identifier" => {
                    if let Ok(name) = param.utf8_text(self.source) {
                        params.push(name.to_string());
                    }
                }
                "formal_parameter" | "required_parameter" | "parameter" => {
                    // Try to get the name from the parameter node
                    if let Some(name_node) = param.child_by_field_name(self.semantics.name_field) {
                        if let Ok(name) = name_node.utf8_text(self.source) {
                            params.push(name.to_string());
                        }
                    } else if let Ok(name) = param.utf8_text(self.source) {
                        // Fallback: use the whole param text (might include type annotations)
                        let name = name.split(':').next().unwrap_or(name).trim();
                        params.push(name.to_string());
                    }
                }
                "assignment_pattern" | "default_parameter" => {
                    // Parameter with default value: x = 5
                    if let Some(left) = param.child_by_field_name(self.semantics.left_field)
                        && let Ok(name) = left.utf8_text(self.source)
                    {
                        params.push(name.to_string());
                    }
                }
                _ => continue,
            }
        }

        if params.is_empty() {
            None
        } else {
            Some(params)
        }
    }

    fn extract_function_name(&self, node: tree_sitter::Node) -> Option<String> {
        node.child_by_field_name(self.semantics.name_field)
            .and_then(|n| n.utf8_text(self.source).ok())
            .map(String::from)
    }
}

/// Propagate taint through callback parameters
///
/// Given a set of tainted variables and detected callback sites,
/// returns the set of callback parameters that should also be tainted.
pub fn propagate_callback_taint(
    tainted_vars: &HashSet<String>,
    callback_sites: &[CallbackSite],
) -> HashSet<String> {
    let mut registry = CallbackRegistry::with_tainted_vars(tainted_vars.clone());

    for site in callback_sites {
        registry.register_callback(site.clone());
    }

    registry.compute_taint_flows();
    registry.tainted_callback_params()
}

/// Convenience function to analyze a file for callback taint flows
pub fn analyze_callback_taint(
    tree: &tree_sitter::Tree,
    source: &[u8],
    file_path: PathBuf,
    tainted_vars: HashSet<String>,
    semantics: &'static LanguageSemantics,
) -> CallbackRegistry {
    let analyzer = CallbackAnalyzer::with_tainted_vars(semantics, source, file_path, tainted_vars);
    analyzer.analyze(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callback_patterns_js() {
        let patterns = CallbackPatterns::for_language(Language::JavaScript);

        assert_eq!(patterns.classify("map"), Some(CallbackKind::ArrayIterator));
        assert_eq!(
            patterns.classify("filter"),
            Some(CallbackKind::ArrayIterator)
        );
        assert_eq!(
            patterns.classify("forEach"),
            Some(CallbackKind::ArrayIterator)
        );
        assert_eq!(
            patterns.classify("reduce"),
            Some(CallbackKind::ArrayReducer)
        );
        assert_eq!(patterns.classify("then"), Some(CallbackKind::PromiseChain));
        assert_eq!(patterns.classify("catch"), Some(CallbackKind::PromiseChain));
        assert_eq!(patterns.classify("on"), Some(CallbackKind::EventHandler));
        assert_eq!(
            patterns.classify("setTimeout"),
            Some(CallbackKind::TimerCallback)
        );
        assert_eq!(patterns.classify("unknownMethod"), None);
    }

    #[test]
    fn test_callback_kind_tainted_param() {
        assert_eq!(CallbackKind::ArrayIterator.tainted_param_index(), 0);
        assert_eq!(CallbackKind::ArrayReducer.tainted_param_index(), 1);
        assert_eq!(CallbackKind::PromiseChain.tainted_param_index(), 0);
        assert_eq!(CallbackKind::EventHandler.tainted_param_index(), 0);
        assert_eq!(
            CallbackKind::TimerCallback.tainted_param_index(),
            usize::MAX
        );
    }

    #[test]
    fn test_callback_registry_basic() {
        let mut registry = CallbackRegistry::new();
        registry.add_tainted_var("userInputs".to_string());

        let site = CallbackSite {
            file: PathBuf::from("test.js"),
            line: 10,
            column: 0,
            hof_name: "map".to_string(),
            receiver: Some("userInputs".to_string()),
            kind: CallbackKind::ArrayIterator,
            callback_params: vec!["item".to_string()],
            containing_function: Some("handler".to_string()),
            node_id: 100,
        };

        registry.register_callback(site);
        registry.compute_taint_flows();

        let flows = registry.taint_flows();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].target_param, "item");
        assert_eq!(flows[0].confidence, TaintConfidence::Definite);
    }

    #[test]
    fn test_callback_registry_promise_chain() {
        let mut registry = CallbackRegistry::new();
        registry.add_tainted_var("fetchResult".to_string());

        let site = CallbackSite {
            file: PathBuf::from("test.js"),
            line: 15,
            column: 0,
            hof_name: "then".to_string(),
            receiver: Some("fetchResult".to_string()),
            kind: CallbackKind::PromiseChain,
            callback_params: vec!["response".to_string()],
            containing_function: None,
            node_id: 200,
        };

        registry.register_callback(site);
        registry.compute_taint_flows();

        let flows = registry.taint_flows();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].target_param, "response");

        match &flows[0].taint_source {
            TaintSource::PromiseResolution(receiver) => {
                assert_eq!(receiver, "fetchResult");
            }
            _ => panic!("Expected PromiseResolution taint source"),
        }
    }

    #[test]
    fn test_callback_registry_no_taint() {
        let mut registry = CallbackRegistry::new();
        // Don't add any tainted vars

        let site = CallbackSite {
            file: PathBuf::from("test.js"),
            line: 10,
            column: 0,
            hof_name: "map".to_string(),
            receiver: Some("safeArray".to_string()),
            kind: CallbackKind::ArrayIterator,
            callback_params: vec!["item".to_string()],
            containing_function: None,
            node_id: 100,
        };

        registry.register_callback(site);
        registry.compute_taint_flows();

        let flows = registry.taint_flows();
        assert_eq!(flows.len(), 0); // No taint should flow
    }

    #[test]
    fn test_tainted_callback_params() {
        let mut registry = CallbackRegistry::new();
        registry.add_tainted_var("taintedArray".to_string());
        registry.add_tainted_var("taintedPromise".to_string());

        // Array iterator
        registry.register_callback(CallbackSite {
            file: PathBuf::from("test.js"),
            line: 10,
            column: 0,
            hof_name: "forEach".to_string(),
            receiver: Some("taintedArray".to_string()),
            kind: CallbackKind::ArrayIterator,
            callback_params: vec!["item".to_string(), "index".to_string()],
            containing_function: None,
            node_id: 100,
        });

        // Promise chain
        registry.register_callback(CallbackSite {
            file: PathBuf::from("test.js"),
            line: 20,
            column: 0,
            hof_name: "then".to_string(),
            receiver: Some("taintedPromise".to_string()),
            kind: CallbackKind::PromiseChain,
            callback_params: vec!["result".to_string()],
            containing_function: None,
            node_id: 200,
        });

        registry.compute_taint_flows();

        let tainted_params = registry.tainted_callback_params();
        assert!(tainted_params.contains("item"));
        assert!(tainted_params.contains("result"));
        // index is not the tainted param (it's param[0] that gets array element)
        assert!(!tainted_params.contains("index"));
    }

    #[test]
    fn test_propagate_callback_taint() {
        let mut tainted = HashSet::new();
        tainted.insert("userInputs".to_string());

        let callbacks = vec![CallbackSite {
            file: PathBuf::from("test.js"),
            line: 10,
            column: 0,
            hof_name: "map".to_string(),
            receiver: Some("userInputs".to_string()),
            kind: CallbackKind::ArrayIterator,
            callback_params: vec!["x".to_string()],
            containing_function: None,
            node_id: 100,
        }];

        let tainted_params = propagate_callback_taint(&tainted, &callbacks);
        assert!(tainted_params.contains("x"));
    }

    #[test]
    fn test_callback_site_indexing() {
        let mut registry = CallbackRegistry::new();

        let site1 = CallbackSite {
            file: PathBuf::from("test.js"),
            line: 10,
            column: 0,
            hof_name: "map".to_string(),
            receiver: Some("arr1".to_string()),
            kind: CallbackKind::ArrayIterator,
            callback_params: vec!["x".to_string()],
            containing_function: None,
            node_id: 100,
        };

        let site2 = CallbackSite {
            file: PathBuf::from("test.js"),
            line: 20,
            column: 0,
            hof_name: "filter".to_string(),
            receiver: Some("arr1".to_string()),
            kind: CallbackKind::ArrayIterator,
            callback_params: vec!["y".to_string()],
            containing_function: None,
            node_id: 200,
        };

        let site3 = CallbackSite {
            file: PathBuf::from("test.js"),
            line: 30,
            column: 0,
            hof_name: "map".to_string(),
            receiver: Some("arr2".to_string()),
            kind: CallbackKind::ArrayIterator,
            callback_params: vec!["z".to_string()],
            containing_function: None,
            node_id: 300,
        };

        registry.register_callback(site1);
        registry.register_callback(site2);
        registry.register_callback(site3);

        // Test indexing by receiver
        let arr1_callbacks = registry.callbacks_for_receiver("arr1");
        assert_eq!(arr1_callbacks.len(), 2);

        let arr2_callbacks = registry.callbacks_for_receiver("arr2");
        assert_eq!(arr2_callbacks.len(), 1);

        // Test indexing by HOF name
        let map_callbacks = registry.callbacks_for_hof("map");
        assert_eq!(map_callbacks.len(), 2);

        let filter_callbacks = registry.callbacks_for_hof("filter");
        assert_eq!(filter_callbacks.len(), 1);
    }
}
