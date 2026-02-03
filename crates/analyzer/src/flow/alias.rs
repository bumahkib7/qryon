//! Alias/Points-to Analysis
//!
//! Tracks which variables may point to the same value (aliasing).
//! This is essential for precise taint analysis: when `y = x; x = tainted`,
//! we need to recognize that `y` might be tainted through aliasing.
//!
//! The analysis uses a flow-insensitive, field-insensitive points-to graph
//! with support for:
//! - Direct assignment: `y = x` (y aliases x)
//! - Parameter passing: `func(x)` (param aliases x)
//! - Return values: `y = getRef()` (y aliases returned ref)
//! - Object references: `y = obj; z = obj` (y, z alias)
//!
//! The may_alias query is conservative: it returns true if aliasing is possible.

use crate::flow::symbol_table::{SymbolInfo, SymbolTable, ValueOrigin};
use crate::semantics::LanguageSemantics;
use std::collections::{HashMap, HashSet, VecDeque};

// =============================================================================
// Core Types
// =============================================================================

/// A unique identifier for an abstract memory location.
/// Variables point to locations, and aliasing occurs when multiple
/// variables point to the same location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocationId(pub usize);

impl LocationId {
    /// Create a new location ID
    pub fn new(id: usize) -> Self {
        Self(id)
    }
}

/// Represents an abstract memory location that variables can point to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Location {
    /// A concrete allocation site (e.g., object literal, function call result)
    Alloc(AllocationSite),
    /// A parameter location (parameters can alias caller arguments)
    Parameter { func_name: String, index: usize },
    /// A return value location
    ReturnValue { func_name: String },
    /// An unknown/external location (conservative approximation)
    Unknown,
    /// A field of another location (for field-sensitive analysis)
    Field { base: LocationId, field: String },
}

/// Represents where an object was allocated
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllocationSite {
    /// Node ID in the AST where allocation occurred
    pub node_id: usize,
    /// Line number
    pub line: usize,
    /// Kind of allocation
    pub kind: AllocKind,
}

/// Kind of allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllocKind {
    /// Object literal: `{}`
    ObjectLiteral,
    /// Array literal: `[]`
    ArrayLiteral,
    /// Constructor call: `new Foo()`
    Constructor,
    /// Function call that returns a reference
    FunctionCall,
    /// Import/require
    Import,
    /// Unknown allocation
    Unknown,
}

// =============================================================================
// Alias Set
// =============================================================================

/// A set of variables that may point to the same value.
///
/// This is the fundamental unit for answering may-alias queries.
/// Variables in the same AliasSet are considered potentially aliased.
#[derive(Debug, Clone, Default)]
pub struct AliasSet {
    /// Variables in this alias set
    variables: HashSet<String>,
    /// The abstract locations this set points to
    locations: HashSet<LocationId>,
    /// Representative variable (for Union-Find optimization)
    representative: Option<String>,
}

impl AliasSet {
    /// Create a new empty alias set
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an alias set with a single variable
    pub fn singleton(var: impl Into<String>) -> Self {
        let var = var.into();
        let mut set = Self::new();
        set.variables.insert(var.clone());
        set.representative = Some(var);
        set
    }

    /// Add a variable to this alias set
    pub fn add_variable(&mut self, var: impl Into<String>) {
        let var = var.into();
        if self.representative.is_none() {
            self.representative = Some(var.clone());
        }
        self.variables.insert(var);
    }

    /// Add a location that this alias set points to
    pub fn add_location(&mut self, loc: LocationId) {
        self.locations.insert(loc);
    }

    /// Check if a variable is in this alias set
    pub fn contains(&self, var: &str) -> bool {
        self.variables.contains(var)
    }

    /// Get all variables in this alias set
    pub fn variables(&self) -> &HashSet<String> {
        &self.variables
    }

    /// Get all locations this alias set points to
    pub fn locations(&self) -> &HashSet<LocationId> {
        &self.locations
    }

    /// Get the number of variables in this alias set
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Check if this alias set is empty
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// Merge another alias set into this one
    pub fn merge(&mut self, other: &AliasSet) {
        self.variables.extend(other.variables.iter().cloned());
        self.locations.extend(other.locations.iter().copied());
    }

    /// Get an iterator over variables
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.variables.iter()
    }
}

// =============================================================================
// Points-To Graph
// =============================================================================

/// A points-to graph that tracks which variables point to which abstract locations.
///
/// The graph supports:
/// - Adding points-to edges (var -> location)
/// - Computing aliasing relationships
/// - Querying may-alias pairs
#[derive(Debug, Clone, Default)]
pub struct PointsToGraph {
    /// Map from variable name to the set of locations it may point to
    points_to: HashMap<String, HashSet<LocationId>>,
    /// Map from location ID to the Location metadata
    locations: HashMap<LocationId, Location>,
    /// Reverse map: location -> variables pointing to it (for fast alias queries)
    reverse_points_to: HashMap<LocationId, HashSet<String>>,
    /// Counter for generating unique location IDs
    next_location_id: usize,
    /// Direct alias relationships (for y = x patterns)
    direct_aliases: HashMap<String, HashSet<String>>,
    /// Parameter-to-argument mappings for inter-procedural aliasing
    param_aliases: HashMap<String, HashSet<(String, usize)>>, // param -> [(call_site_var, arg_index)]
}

impl PointsToGraph {
    /// Create a new empty points-to graph
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new abstract location and return its ID
    pub fn create_location(&mut self, loc: Location) -> LocationId {
        let id = LocationId::new(self.next_location_id);
        self.next_location_id += 1;
        self.locations.insert(id, loc);
        id
    }

    /// Add a points-to edge: variable points to location
    pub fn add_points_to(&mut self, var: impl Into<String>, loc: LocationId) {
        let var = var.into();
        self.points_to.entry(var.clone()).or_default().insert(loc);
        self.reverse_points_to.entry(loc).or_default().insert(var);
    }

    /// Record a direct alias relationship: `alias` is a direct copy of `original`
    pub fn add_direct_alias(&mut self, alias: impl Into<String>, original: impl Into<String>) {
        let alias = alias.into();
        let original = original.into();

        // Record the direct alias
        self.direct_aliases
            .entry(alias.clone())
            .or_default()
            .insert(original.clone());

        // Propagate points-to information
        if let Some(locs) = self.points_to.get(&original).cloned() {
            for loc in locs {
                self.add_points_to(alias.clone(), loc);
            }
        }
    }

    /// Record that a parameter aliases an argument at a call site
    pub fn add_param_alias(
        &mut self,
        param: impl Into<String>,
        call_site_var: impl Into<String>,
        arg_index: usize,
    ) {
        let param = param.into();
        let call_site_var = call_site_var.into();
        self.param_aliases
            .entry(param)
            .or_default()
            .insert((call_site_var, arg_index));
    }

    /// Get all locations a variable may point to
    pub fn points_to_set(&self, var: &str) -> HashSet<LocationId> {
        self.points_to.get(var).cloned().unwrap_or_default()
    }

    /// Get all variables that may point to a location
    pub fn variables_pointing_to(&self, loc: LocationId) -> HashSet<String> {
        self.reverse_points_to
            .get(&loc)
            .cloned()
            .unwrap_or_default()
    }

    /// Get location metadata
    pub fn get_location(&self, id: LocationId) -> Option<&Location> {
        self.locations.get(&id)
    }

    /// Check if two variables may alias (point to the same location)
    pub fn may_alias(&self, var1: &str, var2: &str) -> bool {
        if var1 == var2 {
            return true;
        }

        // Check direct alias relationships
        if self.are_directly_aliased(var1, var2) {
            return true;
        }

        // Check if they share any points-to locations
        let pts1 = self.points_to_set(var1);
        let pts2 = self.points_to_set(var2);

        // If either has no known points-to set, be conservative
        if pts1.is_empty() || pts2.is_empty() {
            // Check transitively through aliases
            return self.transitive_alias_check(var1, var2);
        }

        // Check for intersection
        pts1.intersection(&pts2).next().is_some()
    }

    /// Check if two variables are directly aliased (through assignment chains)
    fn are_directly_aliased(&self, var1: &str, var2: &str) -> bool {
        // Check if var1 aliases var2
        if let Some(aliases) = self.direct_aliases.get(var1)
            && aliases.contains(var2)
        {
            return true;
        }
        // Check if var2 aliases var1
        if let Some(aliases) = self.direct_aliases.get(var2)
            && aliases.contains(var1)
        {
            return true;
        }
        false
    }

    /// Perform a transitive alias check using BFS
    fn transitive_alias_check(&self, var1: &str, var2: &str) -> bool {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(var1.to_string());
        visited.insert(var1.to_string());

        while let Some(current) = queue.pop_front() {
            if current == var2 {
                return true;
            }

            // Follow direct alias edges
            if let Some(aliases) = self.direct_aliases.get(&current) {
                for alias in aliases {
                    if !visited.contains(alias) {
                        visited.insert(alias.clone());
                        queue.push_back(alias.clone());
                    }
                }
            }

            // Also check reverse (who aliases current)
            for (aliased_var, aliases) in &self.direct_aliases {
                if aliases.contains(&current) && !visited.contains(aliased_var) {
                    visited.insert(aliased_var.clone());
                    queue.push_back(aliased_var.clone());
                }
            }
        }

        false
    }

    /// Get all variables that may alias with the given variable
    pub fn aliases_of(&self, var: &str) -> HashSet<String> {
        let mut aliases = HashSet::new();

        // Add direct aliases (transitive)
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(var.to_string());
        visited.insert(var.to_string());

        while let Some(current) = queue.pop_front() {
            // Forward aliases
            if let Some(direct) = self.direct_aliases.get(&current) {
                for alias in direct {
                    if visited.insert(alias.clone()) {
                        aliases.insert(alias.clone());
                        queue.push_back(alias.clone());
                    }
                }
            }
            // Reverse aliases
            for (other_var, other_aliases) in &self.direct_aliases {
                if other_aliases.contains(&current) && visited.insert(other_var.clone()) {
                    aliases.insert(other_var.clone());
                    queue.push_back(other_var.clone());
                }
            }
        }

        // Add variables sharing points-to locations
        for loc in self.points_to_set(var) {
            if let Some(vars) = self.reverse_points_to.get(&loc) {
                for v in vars {
                    if v != var {
                        aliases.insert(v.clone());
                    }
                }
            }
        }

        aliases
    }

    /// Get all alias sets (connected components in the alias graph)
    pub fn compute_alias_sets(&self) -> Vec<AliasSet> {
        let mut visited = HashSet::new();
        let mut sets = Vec::new();

        // Collect all variables
        let all_vars: HashSet<_> = self
            .points_to
            .keys()
            .chain(self.direct_aliases.keys())
            .chain(self.direct_aliases.values().flat_map(|s| s.iter()))
            .cloned()
            .collect();

        for var in all_vars {
            if visited.contains(&var) {
                continue;
            }

            let mut set = AliasSet::new();
            let mut queue = VecDeque::new();

            queue.push_back(var.clone());
            visited.insert(var.clone());
            set.add_variable(var.clone());

            while let Some(current) = queue.pop_front() {
                // Add points-to locations
                for loc in self.points_to_set(&current) {
                    set.add_location(loc);

                    // Add other variables pointing to same location
                    if let Some(vars) = self.reverse_points_to.get(&loc) {
                        for v in vars {
                            if visited.insert(v.clone()) {
                                set.add_variable(v.clone());
                                queue.push_back(v.clone());
                            }
                        }
                    }
                }

                // Follow direct alias edges
                if let Some(aliases) = self.direct_aliases.get(&current) {
                    for alias in aliases {
                        if visited.insert(alias.clone()) {
                            set.add_variable(alias.clone());
                            queue.push_back(alias.clone());
                        }
                    }
                }

                // Reverse alias edges
                for (aliased_var, aliases) in &self.direct_aliases {
                    if aliases.contains(&current) && visited.insert(aliased_var.clone()) {
                        set.add_variable(aliased_var.clone());
                        queue.push_back(aliased_var.clone());
                    }
                }
            }

            if !set.is_empty() {
                sets.push(set);
            }
        }

        sets
    }

    /// Get the number of variables tracked
    pub fn variable_count(&self) -> usize {
        let mut vars: HashSet<_> = self.points_to.keys().cloned().collect();
        vars.extend(self.direct_aliases.keys().cloned());
        vars.extend(self.direct_aliases.values().flat_map(|s| s.iter()).cloned());
        vars.len()
    }

    /// Get the number of locations tracked
    pub fn location_count(&self) -> usize {
        self.locations.len()
    }
}

// =============================================================================
// Alias Analysis
// =============================================================================

/// Result of alias analysis
#[derive(Debug, Clone)]
pub struct AliasResult {
    /// The points-to graph
    pub graph: PointsToGraph,
    /// Computed alias sets
    pub alias_sets: Vec<AliasSet>,
    /// Map from variable to its alias set index
    pub var_to_set: HashMap<String, usize>,
    /// Number of analysis iterations
    pub iterations: usize,
}

impl AliasResult {
    /// Check if two variables may alias
    pub fn may_alias(&self, var1: &str, var2: &str) -> bool {
        if var1 == var2 {
            return true;
        }

        // Check via alias sets
        if let (Some(&set1), Some(&set2)) = (self.var_to_set.get(var1), self.var_to_set.get(var2))
            && set1 == set2
        {
            return true;
        }

        // Fall back to graph query
        self.graph.may_alias(var1, var2)
    }

    /// Get all variables that may alias with the given variable
    pub fn aliases_of(&self, var: &str) -> HashSet<String> {
        // Check alias set first
        if let Some(&set_idx) = self.var_to_set.get(var)
            && let Some(set) = self.alias_sets.get(set_idx)
        {
            return set.variables().clone();
        }

        // Fall back to graph query
        self.graph.aliases_of(var)
    }

    /// Get the alias set containing a variable
    pub fn get_alias_set(&self, var: &str) -> Option<&AliasSet> {
        self.var_to_set
            .get(var)
            .and_then(|&idx| self.alias_sets.get(idx))
    }

    /// Get all alias sets
    pub fn all_alias_sets(&self) -> &[AliasSet] {
        &self.alias_sets
    }
}

/// Alias analyzer that builds a points-to graph from the symbol table
pub struct AliasAnalyzer<'a> {
    /// Symbol table
    symbols: &'a SymbolTable,
    /// Language semantics
    semantics: &'static LanguageSemantics,
    /// Source code
    source: &'a [u8],
    /// Parsed tree
    tree: &'a tree_sitter::Tree,
}

impl<'a> AliasAnalyzer<'a> {
    /// Create a new alias analyzer
    pub fn new(
        symbols: &'a SymbolTable,
        semantics: &'static LanguageSemantics,
        source: &'a [u8],
        tree: &'a tree_sitter::Tree,
    ) -> Self {
        Self {
            symbols,
            semantics,
            source,
            tree,
        }
    }

    /// Run the alias analysis
    pub fn analyze(&self) -> AliasResult {
        let mut graph = PointsToGraph::new();
        let mut iterations = 0;

        // Phase 1: Process symbol table to build initial points-to edges
        self.process_symbols(&mut graph);

        // Phase 2: Extract call site information for inter-procedural aliasing
        self.process_calls(&mut graph);

        // Phase 3: Fixed-point iteration to propagate aliasing
        let max_iterations = 100;
        loop {
            iterations += 1;
            if iterations > max_iterations {
                break;
            }

            let changed = self.propagate_aliases(&mut graph);
            if !changed {
                break;
            }
        }

        // Phase 4: Compute alias sets
        let alias_sets = graph.compute_alias_sets();

        // Build var-to-set mapping
        let mut var_to_set = HashMap::new();
        for (idx, set) in alias_sets.iter().enumerate() {
            for var in set.variables() {
                var_to_set.insert(var.clone(), idx);
            }
        }

        AliasResult {
            graph,
            alias_sets,
            var_to_set,
            iterations,
        }
    }

    /// Process symbol table entries to build initial aliasing information
    fn process_symbols(&self, graph: &mut PointsToGraph) {
        for (name, info) in self.symbols.iter() {
            self.process_symbol(name, info, graph);
        }
    }

    /// Process a single symbol entry
    fn process_symbol(&self, name: &str, info: &SymbolInfo, graph: &mut PointsToGraph) {
        match &info.initializer {
            // Direct variable reference: y = x creates alias
            ValueOrigin::Variable(source_var) => {
                graph.add_direct_alias(name, source_var);
            }

            // Function parameters get their own allocation
            ValueOrigin::Parameter(idx) => {
                let loc = graph.create_location(Location::Parameter {
                    func_name: String::new(), // Could be refined with function context
                    index: *idx,
                });
                graph.add_points_to(name, loc);
            }

            // Function calls may return references
            ValueOrigin::FunctionCall(func_name) => {
                let loc = graph.create_location(Location::ReturnValue {
                    func_name: func_name.clone(),
                });
                graph.add_points_to(name, loc);
            }

            // Member access creates a field location
            ValueOrigin::MemberAccess(_path) => {
                // For now, treat each unique member access path as a potential alias source
                // More sophisticated analysis would track object identity
                let loc = graph.create_location(Location::Alloc(AllocationSite {
                    node_id: info.declaration_node_id,
                    line: info.line,
                    kind: AllocKind::Unknown,
                }));
                graph.add_points_to(name, loc);
            }

            // String concatenation inherits aliases from operands
            ValueOrigin::StringConcat(_vars) | ValueOrigin::TemplateLiteral(_vars) => {
                // The result doesn't alias the operands (it's a new string)
                // but we track it as a new allocation
                let loc = graph.create_location(Location::Alloc(AllocationSite {
                    node_id: info.declaration_node_id,
                    line: info.line,
                    kind: AllocKind::Unknown,
                }));
                graph.add_points_to(name, loc);
            }

            // Method calls may return references or modify receivers
            ValueOrigin::MethodCall {
                method,
                receiver,
                arguments: _,
            } => {
                // If it's a method that returns `this` or the receiver, track aliasing
                if Self::returns_receiver(method) {
                    if let Some(recv) = receiver {
                        graph.add_direct_alias(name, recv);
                    }
                } else {
                    // Treat as new allocation
                    let loc = graph.create_location(Location::ReturnValue {
                        func_name: method.clone(),
                    });
                    graph.add_points_to(name, loc);
                }
            }

            // Literals create new allocations (no aliasing)
            ValueOrigin::Literal(_) => {
                let loc = graph.create_location(Location::Alloc(AllocationSite {
                    node_id: info.declaration_node_id,
                    line: info.line,
                    kind: AllocKind::ObjectLiteral,
                }));
                graph.add_points_to(name, loc);
            }

            // Binary expressions typically create new values
            ValueOrigin::BinaryExpression => {
                let loc = graph.create_location(Location::Alloc(AllocationSite {
                    node_id: info.declaration_node_id,
                    line: info.line,
                    kind: AllocKind::Unknown,
                }));
                graph.add_points_to(name, loc);
            }

            // Unknown origin - conservative: could alias anything
            ValueOrigin::Unknown => {
                let loc = graph.create_location(Location::Unknown);
                graph.add_points_to(name, loc);
            }
        }

        // Process reassignments
        for reassign in &info.reassignments {
            self.process_reassignment(name, reassign, graph);
        }
    }

    /// Process a reassignment
    fn process_reassignment(&self, name: &str, origin: &ValueOrigin, graph: &mut PointsToGraph) {
        match origin {
            ValueOrigin::Variable(source_var) => {
                graph.add_direct_alias(name, source_var);
            }
            // Other origins create new allocations that don't affect existing aliases
            // (flow-insensitive: we merge all assignments)
            _ => {}
        }
    }

    /// Check if a method returns its receiver (for chaining patterns)
    fn returns_receiver(method: &str) -> bool {
        // Methods that typically return `this` for chaining
        matches!(
            method.to_lowercase().as_str(),
            "concat"
                | "slice"
                | "map"
                | "filter"
                | "reduce"
                | "trim"
                | "tolowercase"
                | "touppercase"
                | "replace"
                | "split"
                | "join"
                | "push"
                | "pop"
                | "shift"
                | "unshift"
                | "sort"
                | "reverse"
                | "fill"
                | "copywithin"
        )
    }

    /// Process call expressions for inter-procedural aliasing
    fn process_calls(&self, graph: &mut PointsToGraph) {
        let root = self.tree.root_node();
        self.walk_for_calls(root, graph);
    }

    fn walk_for_calls(&self, node: tree_sitter::Node, graph: &mut PointsToGraph) {
        if self.semantics.is_call(node.kind()) {
            self.process_call_site(node, graph);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.walk_for_calls(child, graph);
        }
    }

    fn process_call_site(&self, node: tree_sitter::Node, graph: &mut PointsToGraph) {
        // Get arguments
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for (idx, arg) in args.named_children(&mut cursor).enumerate() {
                // If the argument is a variable, it may alias the corresponding parameter
                if (self.semantics.is_identifier(arg.kind()) || arg.kind() == "identifier")
                    && let Ok(var_name) = arg.utf8_text(self.source)
                {
                    // Create a parameter location for this call
                    let func_name = self.extract_callee_name(node).unwrap_or_default();
                    let param_name = format!("{}$param{}", func_name, idx);
                    graph.add_param_alias(&param_name, var_name, idx);
                }
            }
        }
    }

    fn extract_callee_name(&self, call_node: tree_sitter::Node) -> Option<String> {
        let func = call_node
            .child_by_field_name("function")
            .or_else(|| call_node.child(0))?;
        func.utf8_text(self.source).ok().map(String::from)
    }

    /// Propagate aliases through transitive relationships
    fn propagate_aliases(&self, graph: &mut PointsToGraph) -> bool {
        let mut changed = false;

        // Propagate points-to through direct aliases
        let aliases: Vec<_> = graph
            .direct_aliases
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (alias, sources) in aliases {
            for source in sources {
                let source_pts = graph.points_to_set(&source);
                for loc in source_pts {
                    if !graph
                        .points_to
                        .get(&alias)
                        .is_some_and(|s| s.contains(&loc))
                    {
                        graph.add_points_to(alias.clone(), loc);
                        changed = true;
                    }
                }
            }
        }

        changed
    }
}

/// Run alias analysis on a symbol table
pub fn analyze_aliases(
    symbols: &SymbolTable,
    tree: &tree_sitter::Tree,
    source: &[u8],
    semantics: &'static LanguageSemantics,
) -> AliasResult {
    let analyzer = AliasAnalyzer::new(symbols, semantics, source, tree);
    analyzer.analyze()
}

// =============================================================================
// Taint Integration
// =============================================================================

/// Extends taint analysis to propagate through aliases.
///
/// When a variable is tainted, all its aliases should also be considered tainted.
pub fn propagate_taint_through_aliases(
    tainted_vars: &HashSet<String>,
    alias_result: &AliasResult,
) -> HashSet<String> {
    let mut result = tainted_vars.clone();

    for var in tainted_vars {
        // Add all aliases of this tainted variable
        let aliases = alias_result.aliases_of(var);
        result.extend(aliases);
    }

    result
}

/// Check if any variable in a set is tainted, considering aliases
pub fn any_tainted_with_aliases(
    vars: &[&str],
    tainted_vars: &HashSet<String>,
    alias_result: &AliasResult,
) -> bool {
    for var in vars {
        if tainted_vars.contains(*var) {
            return true;
        }
        // Check if any alias of this variable is tainted
        for alias in alias_result.aliases_of(var) {
            if tainted_vars.contains(&alias) {
                return true;
            }
        }
    }
    false
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_direct_assignment_alias() {
        let code = r#"
            const x = getValue();
            const y = x;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        assert!(result.may_alias("x", "y"), "y = x should create alias");
        assert!(result.may_alias("y", "x"), "alias should be symmetric");
    }

    #[test]
    fn test_no_alias_different_values() {
        let code = r#"
            const x = getValue1();
            const y = getValue2();
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        // Different function calls should not alias
        assert!(
            !result.may_alias("x", "y"),
            "different values should not alias"
        );
    }

    #[test]
    fn test_transitive_alias() {
        let code = r#"
            const x = getValue();
            const y = x;
            const z = y;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        assert!(result.may_alias("x", "y"));
        assert!(result.may_alias("y", "z"));
        assert!(result.may_alias("x", "z"), "aliasing should be transitive");
    }

    #[test]
    fn test_shared_origin_alias() {
        let code = r#"
            const obj = getObject();
            const a = obj;
            const b = obj;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        assert!(result.may_alias("a", "obj"));
        assert!(result.may_alias("b", "obj"));
        assert!(
            result.may_alias("a", "b"),
            "variables from same origin should alias"
        );
    }

    #[test]
    fn test_alias_set_computation() {
        let code = r#"
            const x = getValue();
            const y = x;
            const a = getOther();
            const b = a;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        // Should have two distinct alias sets: {x, y} and {a, b}
        let sets = result.all_alias_sets();

        // Find the set containing x
        let x_set = sets.iter().find(|s| s.contains("x"));
        assert!(x_set.is_some());
        let x_set = x_set.unwrap();
        assert!(x_set.contains("y"));
        assert!(!x_set.contains("a"));
        assert!(!x_set.contains("b"));
    }

    #[test]
    fn test_taint_propagation_through_aliases() {
        let mut tainted = HashSet::new();
        tainted.insert("x".to_string());

        let code = r#"
            const x = userInput;
            const y = x;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let alias_result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        let expanded_taint = propagate_taint_through_aliases(&tainted, &alias_result);

        assert!(expanded_taint.contains("x"));
        assert!(
            expanded_taint.contains("y"),
            "alias should be tainted when original is tainted"
        );
    }

    #[test]
    fn test_literal_no_alias() {
        let code = r#"
            const a = "hello";
            const b = "hello";
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        // Same literal value doesn't create aliasing (different allocations)
        assert!(!result.may_alias("a", "b"));
    }

    #[test]
    fn test_aliases_of_query() {
        let code = r#"
            const x = getValue();
            const y = x;
            const z = y;
        "#;
        let parsed = parse_js(code);
        let symbols = SymbolTable::build(&parsed, Language::JavaScript);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);

        let result = analyze_aliases(&symbols, &parsed.tree, code.as_bytes(), semantics);

        let x_aliases = result.aliases_of("x");
        assert!(x_aliases.contains("y"));
        assert!(x_aliases.contains("z"));
    }

    #[test]
    fn test_points_to_graph_basics() {
        let mut graph = PointsToGraph::new();

        let loc1 = graph.create_location(Location::Unknown);
        let loc2 = graph.create_location(Location::Unknown);

        graph.add_points_to("x", loc1);
        graph.add_points_to("y", loc1);
        graph.add_points_to("z", loc2);

        assert!(graph.may_alias("x", "y"));
        assert!(!graph.may_alias("x", "z"));
        assert!(!graph.may_alias("y", "z"));
    }

    #[test]
    fn test_self_alias() {
        let mut graph = PointsToGraph::new();
        let loc = graph.create_location(Location::Unknown);
        graph.add_points_to("x", loc);

        // Variable always aliases itself
        assert!(graph.may_alias("x", "x"));
    }
}
