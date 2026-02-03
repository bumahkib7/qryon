//! Field-sensitive taint tracking
//!
//! Tracks taint at the field level to handle cases like:
//! - `obj.field = tainted` - only `obj.field` is tainted, not `obj`
//! - `x = obj.field` - `x` inherits taint from `obj.field`
//! - `const {field} = obj` - destructuring extracts field taint
//! - `{...obj, field: tainted}` - spread with override
//!
//! This enables more precise taint tracking that doesn't lose information
//! when taint flows through object properties.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};

/// Represents an access path like `obj`, `obj.field`, or `obj.field.subfield`
///
/// Access paths track the sequence of property accesses from a base variable.
/// This allows distinguishing between `obj.clean` and `obj.tainted`.
#[derive(Clone, Eq)]
pub struct FieldPath {
    /// The base variable name (e.g., "obj" in "obj.field.subfield")
    pub base: String,
    /// The sequence of field accesses (e.g., ["field", "subfield"])
    pub fields: Vec<String>,
}

impl FieldPath {
    /// Create a new field path from just a base variable
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            fields: Vec::new(),
        }
    }

    /// Create a field path from a base and a single field
    pub fn with_field(base: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            fields: vec![field.into()],
        }
    }

    /// Create a field path from a dotted string like "obj.field.subfield"
    pub fn from_dotted(path: &str) -> Self {
        let parts: Vec<&str> = path.split('.').collect();
        if parts.is_empty() {
            return Self::new("");
        }
        Self {
            base: parts[0].to_string(),
            fields: parts[1..].iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Append a field to this path
    pub fn append(&self, field: impl Into<String>) -> Self {
        let mut new_fields = self.fields.clone();
        new_fields.push(field.into());
        Self {
            base: self.base.clone(),
            fields: new_fields,
        }
    }

    /// Get the parent path (removes the last field)
    /// Returns None if this is just a base variable
    pub fn parent(&self) -> Option<Self> {
        if self.fields.is_empty() {
            None
        } else {
            Some(Self {
                base: self.base.clone(),
                fields: self.fields[..self.fields.len() - 1].to_vec(),
            })
        }
    }

    /// Get the last field name, if any
    pub fn last_field(&self) -> Option<&str> {
        self.fields.last().map(|s| s.as_str())
    }

    /// Check if this path is a prefix of another path
    /// e.g., "obj.field" is a prefix of "obj.field.subfield"
    pub fn is_prefix_of(&self, other: &FieldPath) -> bool {
        if self.base != other.base {
            return false;
        }
        if self.fields.len() > other.fields.len() {
            return false;
        }
        self.fields
            .iter()
            .zip(other.fields.iter())
            .all(|(a, b)| a == b)
    }

    /// Check if this path starts with another path
    pub fn starts_with(&self, other: &FieldPath) -> bool {
        other.is_prefix_of(self)
    }

    /// Get the full path as a dotted string
    pub fn to_dotted(&self) -> String {
        if self.fields.is_empty() {
            self.base.clone()
        } else {
            format!("{}.{}", self.base, self.fields.join("."))
        }
    }

    /// Get the depth of this path (0 for base variable, 1 for obj.field, etc.)
    pub fn depth(&self) -> usize {
        self.fields.len()
    }

    /// Check if this is just a base variable with no field accesses
    pub fn is_base(&self) -> bool {
        self.fields.is_empty()
    }
}

impl PartialEq for FieldPath {
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base && self.fields == other.fields
    }
}

impl Hash for FieldPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.base.hash(state);
        self.fields.hash(state);
    }
}

impl fmt::Debug for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldPath({})", self.to_dotted())
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_dotted())
    }
}

impl From<&str> for FieldPath {
    fn from(s: &str) -> Self {
        FieldPath::from_dotted(s)
    }
}

impl From<String> for FieldPath {
    fn from(s: String) -> Self {
        FieldPath::from_dotted(&s)
    }
}

/// Taint status for a field path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTaintStatus {
    /// The field is clean (not tainted)
    Clean,
    /// The field is tainted
    Tainted,
    /// The field was sanitized
    Sanitized,
    /// Unknown taint status
    Unknown,
}

impl FieldTaintStatus {
    /// Check if this status represents a tainted value
    pub fn is_tainted(&self) -> bool {
        matches!(self, FieldTaintStatus::Tainted)
    }

    /// Check if this status represents a clean value
    pub fn is_clean(&self) -> bool {
        matches!(self, FieldTaintStatus::Clean | FieldTaintStatus::Sanitized)
    }
}

/// Information about a tainted field
#[derive(Debug, Clone)]
pub struct FieldTaintInfo {
    /// The taint status
    pub status: FieldTaintStatus,
    /// Line number where the taint was introduced
    pub taint_line: Option<usize>,
    /// Source of the taint (e.g., "req.query", "userInput")
    pub source: Option<String>,
    /// Line number where sanitization occurred (if sanitized)
    pub sanitized_line: Option<usize>,
}

impl Default for FieldTaintInfo {
    fn default() -> Self {
        Self {
            status: FieldTaintStatus::Unknown,
            taint_line: None,
            source: None,
            sanitized_line: None,
        }
    }
}

impl FieldTaintInfo {
    /// Create a new tainted field info
    pub fn tainted(line: Option<usize>, source: Option<String>) -> Self {
        Self {
            status: FieldTaintStatus::Tainted,
            taint_line: line,
            source,
            sanitized_line: None,
        }
    }

    /// Create a clean field info
    pub fn clean() -> Self {
        Self {
            status: FieldTaintStatus::Clean,
            taint_line: None,
            source: None,
            sanitized_line: None,
        }
    }

    /// Create a sanitized field info
    pub fn sanitized(line: usize) -> Self {
        Self {
            status: FieldTaintStatus::Sanitized,
            taint_line: None,
            source: None,
            sanitized_line: Some(line),
        }
    }
}

/// Maps field paths to their taint status
///
/// This is the core data structure for field-sensitive taint tracking.
/// It maintains a mapping from access paths to taint information, allowing
/// precise tracking of which specific fields are tainted.
#[derive(Debug, Clone, Default)]
pub struct FieldTaintMap {
    /// Map from field path to taint information
    taint_map: HashMap<FieldPath, FieldTaintInfo>,
    /// Track which base variables have any tainted fields
    /// (optimization for quick lookup)
    tainted_bases: HashSet<String>,
}

impl FieldTaintMap {
    /// Create a new empty field taint map
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a field path as tainted
    pub fn mark_tainted(&mut self, path: FieldPath, line: Option<usize>, source: Option<String>) {
        self.tainted_bases.insert(path.base.clone());
        self.taint_map
            .insert(path, FieldTaintInfo::tainted(line, source));
    }

    /// Mark a field path as tainted from a dotted string
    pub fn mark_tainted_dotted(&mut self, path: &str, line: Option<usize>, source: Option<String>) {
        self.mark_tainted(FieldPath::from_dotted(path), line, source);
    }

    /// Mark a field path as clean
    pub fn mark_clean(&mut self, path: &FieldPath) {
        self.taint_map.insert(path.clone(), FieldTaintInfo::clean());
        // Update tainted_bases if needed
        if !self.has_any_tainted_field(&path.base) {
            self.tainted_bases.remove(&path.base);
        }
    }

    /// Mark a field path as sanitized
    pub fn mark_sanitized(&mut self, path: &FieldPath, line: usize) {
        self.taint_map
            .insert(path.clone(), FieldTaintInfo::sanitized(line));
        // Update tainted_bases if needed
        if !self.has_any_tainted_field(&path.base) {
            self.tainted_bases.remove(&path.base);
        }
    }

    /// Check if a field path is tainted
    ///
    /// This also checks parent paths - if `obj` is tainted, then `obj.field` is also tainted.
    pub fn is_tainted(&self, path: &FieldPath) -> bool {
        // Check exact path
        if let Some(info) = self.taint_map.get(path) {
            if info.status.is_tainted() {
                return true;
            }
            if info.status.is_clean() {
                return false;
            }
        }

        // Check if any parent path is tainted (taint propagates down)
        let mut current = path.clone();
        while let Some(parent) = current.parent() {
            if let Some(info) = self.taint_map.get(&parent)
                && info.status.is_tainted()
            {
                return true;
            }
            current = parent;
        }

        // Check the base variable itself
        if path.depth() > 0 {
            let base_path = FieldPath::new(&path.base);
            if let Some(info) = self.taint_map.get(&base_path) {
                return info.status.is_tainted();
            }
        }

        false
    }

    /// Check if a dotted path is tainted
    pub fn is_tainted_dotted(&self, path: &str) -> bool {
        self.is_tainted(&FieldPath::from_dotted(path))
    }

    /// Check if any field of a base variable is tainted
    pub fn has_any_tainted_field(&self, base: &str) -> bool {
        if !self.tainted_bases.contains(base) {
            return false;
        }
        self.taint_map
            .iter()
            .any(|(path, info)| path.base == base && info.status.is_tainted())
    }

    /// Get all tainted paths for a base variable
    pub fn tainted_fields_of(&self, base: &str) -> Vec<&FieldPath> {
        self.taint_map
            .iter()
            .filter(|(path, info)| path.base == base && info.status.is_tainted())
            .map(|(path, _)| path)
            .collect()
    }

    /// Get all tainted paths
    pub fn all_tainted(&self) -> Vec<&FieldPath> {
        self.taint_map
            .iter()
            .filter(|(_, info)| info.status.is_tainted())
            .map(|(path, _)| path)
            .collect()
    }

    /// Get taint info for a path
    pub fn get_info(&self, path: &FieldPath) -> Option<&FieldTaintInfo> {
        self.taint_map.get(path)
    }

    /// Handle property assignment: `obj.field = value`
    ///
    /// If `value` is tainted, marks `obj.field` as tainted.
    /// This is field-sensitive: only the specific field is marked.
    pub fn handle_property_assignment(
        &mut self,
        target_path: FieldPath,
        value_tainted: bool,
        line: Option<usize>,
        source: Option<String>,
    ) {
        if value_tainted {
            self.mark_tainted(target_path, line, source);
        } else {
            // Assignment of clean value clears taint for this specific field
            self.mark_clean(&target_path);
        }
    }

    /// Handle property read: `x = obj.field`
    ///
    /// Returns whether the value is tainted (inherits from `obj.field`).
    pub fn handle_property_read(&self, source_path: &FieldPath) -> bool {
        self.is_tainted(source_path)
    }

    /// Handle destructuring: `const {field1, field2} = obj`
    ///
    /// Returns a map of destructured variable names to their taint status.
    pub fn handle_destructuring(
        &self,
        source: &FieldPath,
        field_names: &[&str],
    ) -> HashMap<String, bool> {
        let mut result = HashMap::new();
        for field in field_names {
            let field_path = source.append(*field);
            result.insert(field.to_string(), self.is_tainted(&field_path));
        }
        result
    }

    /// Handle spread with override: `{...obj, field: value}`
    ///
    /// Creates taint info for the resulting object, spreading all fields from `source`
    /// but overriding specific fields.
    pub fn handle_spread_with_override(
        &self,
        source: &FieldPath,
        overrides: &HashMap<String, bool>, // field name -> is_tainted
        result_base: &str,
        line: Option<usize>,
    ) -> FieldTaintMap {
        let mut result = FieldTaintMap::new();

        // Copy all tainted fields from source to result
        for (path, info) in &self.taint_map {
            if path.base == source.base {
                // Check if this field is overridden
                if let Some(field) = path.fields.first()
                    && overrides.contains_key(field)
                {
                    continue; // Skip, will be handled by override
                }

                // Copy taint to result object
                let new_path = FieldPath {
                    base: result_base.to_string(),
                    fields: path.fields.clone(),
                };
                result.taint_map.insert(new_path, info.clone());
                if info.status.is_tainted() {
                    result.tainted_bases.insert(result_base.to_string());
                }
            }
        }

        // Apply overrides
        for (field, is_tainted) in overrides {
            let path = FieldPath::with_field(result_base, field);
            if *is_tainted {
                result.mark_tainted(path, line, None);
            } else {
                result.mark_clean(&path);
            }
        }

        result
    }

    /// Handle array destructuring: `const [a, b] = arr`
    ///
    /// Returns taint status for each position.
    pub fn handle_array_destructuring(&self, source: &FieldPath, count: usize) -> Vec<bool> {
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let index_path = source.append(i.to_string());
            result.push(self.is_tainted(&index_path));
        }
        result
    }

    /// Handle computed property access: `obj[key]`
    ///
    /// If the key is a string literal, we can be precise.
    /// If the key is dynamic, we conservatively assume any field could be accessed.
    pub fn handle_computed_access(&self, source: &FieldPath, key: Option<&str>) -> bool {
        match key {
            Some(field) => {
                let field_path = source.append(field);
                self.is_tainted(&field_path)
            }
            None => {
                // Dynamic access: conservatively return true if any field is tainted
                self.has_any_tainted_field(&source.base)
            }
        }
    }

    /// Merge another map into this one
    ///
    /// Used when merging control flow paths. A field is tainted if it's
    /// tainted in either path.
    pub fn merge(&mut self, other: &FieldTaintMap) {
        for (path, info) in &other.taint_map {
            match self.taint_map.get(path) {
                Some(existing) => {
                    // Merge: tainted wins over clean (conservative)
                    if info.status.is_tainted() && !existing.status.is_tainted() {
                        self.taint_map.insert(path.clone(), info.clone());
                        self.tainted_bases.insert(path.base.clone());
                    }
                }
                None => {
                    self.taint_map.insert(path.clone(), info.clone());
                    if info.status.is_tainted() {
                        self.tainted_bases.insert(path.base.clone());
                    }
                }
            }
        }
    }

    /// Iterate over all entries
    pub fn iter(&self) -> impl Iterator<Item = (&FieldPath, &FieldTaintInfo)> {
        self.taint_map.iter()
    }

    /// Get the number of tracked paths
    pub fn len(&self) -> usize {
        self.taint_map.len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.taint_map.is_empty()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.taint_map.clear();
        self.tainted_bases.clear();
    }
}

/// Result of field-sensitive taint analysis
///
/// Extends the basic TaintResult with field-level precision.
#[derive(Debug, Clone, Default)]
pub struct FieldSensitiveTaintResult {
    /// Field-level taint information
    pub field_taint: FieldTaintMap,
    /// Variables that are wholly tainted (all fields)
    pub fully_tainted_vars: HashSet<String>,
    /// Detected field-level flows
    pub field_flows: Vec<FieldTaintFlow>,
}

/// A taint flow at the field level
#[derive(Debug, Clone)]
pub struct FieldTaintFlow {
    /// Source path (e.g., "req.query.id")
    pub source: FieldPath,
    /// Sink path (e.g., "query.text")
    pub sink: FieldPath,
    /// Line number of source
    pub source_line: usize,
    /// Line number of sink
    pub sink_line: usize,
    /// Intermediate assignments (for debugging)
    pub path: Vec<FieldPath>,
}

impl FieldSensitiveTaintResult {
    /// Create a new empty result
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a field path is tainted
    pub fn is_field_tainted(&self, path: &FieldPath) -> bool {
        // Check if the base variable is fully tainted
        if self.fully_tainted_vars.contains(&path.base) {
            return true;
        }
        // Check field-specific taint
        self.field_taint.is_tainted(path)
    }

    /// Check if a variable (base or field) is tainted
    pub fn is_tainted(&self, var_name: &str) -> bool {
        // Check if it's a fully tainted variable
        if self.fully_tainted_vars.contains(var_name) {
            return true;
        }
        // Parse as field path and check
        let path = FieldPath::from_dotted(var_name);
        self.is_field_tainted(&path)
    }

    /// Mark a variable as fully tainted
    pub fn mark_fully_tainted(&mut self, var_name: impl Into<String>) {
        self.fully_tainted_vars.insert(var_name.into());
    }

    /// Add a field-level flow
    pub fn add_flow(&mut self, flow: FieldTaintFlow) {
        self.field_flows.push(flow);
    }

    /// Get all detected flows
    pub fn flows(&self) -> &[FieldTaintFlow] {
        &self.field_flows
    }

    /// Get all tainted field paths
    pub fn all_tainted_paths(&self) -> Vec<FieldPath> {
        let mut paths: Vec<_> = self
            .field_taint
            .all_tainted()
            .into_iter()
            .cloned()
            .collect();

        // Add fully tainted variables as base paths
        for var in &self.fully_tainted_vars {
            paths.push(FieldPath::new(var));
        }

        paths
    }
}

/// Field-sensitive taint analyzer
///
/// Extends basic taint analysis with field-level tracking.
pub struct FieldSensitiveAnalyzer {
    /// The field taint map being built
    field_taint: FieldTaintMap,
    /// Fully tainted variables
    fully_tainted: HashSet<String>,
    /// Detected flows
    flows: Vec<FieldTaintFlow>,
}

impl FieldSensitiveAnalyzer {
    /// Create a new analyzer
    pub fn new() -> Self {
        Self {
            field_taint: FieldTaintMap::new(),
            fully_tainted: HashSet::new(),
            flows: Vec::new(),
        }
    }

    /// Process a property assignment: `obj.field = value`
    pub fn process_property_assignment(
        &mut self,
        target: &str,
        field: &str,
        value_source: Option<&FieldPath>,
        value_is_tainted: bool,
        line: usize,
    ) {
        let target_path = FieldPath::with_field(target, field);

        if value_is_tainted {
            let source = value_source.map(|p| p.to_dotted());
            self.field_taint
                .mark_tainted(target_path.clone(), Some(line), source);
        } else {
            self.field_taint.mark_clean(&target_path);
        }
    }

    /// Process a property read: `x = obj.field`
    pub fn process_property_read(&self, source: &str, field: &str) -> bool {
        let source_path = FieldPath::with_field(source, field);
        self.field_taint.is_tainted(&source_path)
    }

    /// Process destructuring: `const {a, b} = obj`
    pub fn process_destructuring(
        &mut self,
        source: &str,
        bindings: &[(&str, &str)], // (field_name, bound_var_name)
        line: usize,
    ) {
        let source_path = FieldPath::new(source);

        for (field, var_name) in bindings {
            let field_path = source_path.append(*field);
            let is_tainted = self.field_taint.is_tainted(&field_path);

            if is_tainted {
                // The destructured variable gets the field's taint
                self.field_taint.mark_tainted(
                    FieldPath::new(*var_name),
                    Some(line),
                    Some(field_path.to_dotted()),
                );
            }
        }
    }

    /// Process spread with override: `{...obj, field: value}`
    pub fn process_spread_with_override(
        &mut self,
        source: &str,
        overrides: Vec<(&str, bool)>, // (field_name, is_tainted)
        result_var: &str,
        line: usize,
    ) {
        let source_path = FieldPath::new(source);
        let override_map: HashMap<String, bool> = overrides
            .into_iter()
            .map(|(f, t)| (f.to_string(), t))
            .collect();

        let result_taint = self.field_taint.handle_spread_with_override(
            &source_path,
            &override_map,
            result_var,
            Some(line),
        );

        // Merge the result into our map
        self.field_taint.merge(&result_taint);
    }

    /// Mark a base variable as fully tainted (all fields)
    pub fn mark_fully_tainted(&mut self, var_name: &str, line: usize, source: Option<String>) {
        self.fully_tainted.insert(var_name.to_string());
        self.field_taint
            .mark_tainted(FieldPath::new(var_name), Some(line), source);
    }

    /// Check if a variable or field is tainted
    pub fn is_tainted(&self, path: &str) -> bool {
        let field_path = FieldPath::from_dotted(path);

        // Check if base is fully tainted
        if self.fully_tainted.contains(&field_path.base) {
            return true;
        }

        // Check field-specific taint
        self.field_taint.is_tainted(&field_path)
    }

    /// Record a detected flow
    pub fn record_flow(
        &mut self,
        source: FieldPath,
        sink: FieldPath,
        source_line: usize,
        sink_line: usize,
    ) {
        self.flows.push(FieldTaintFlow {
            source,
            sink,
            source_line,
            sink_line,
            path: Vec::new(),
        });
    }

    /// Build the final result
    pub fn build(self) -> FieldSensitiveTaintResult {
        FieldSensitiveTaintResult {
            field_taint: self.field_taint,
            fully_tainted_vars: self.fully_tainted,
            field_flows: self.flows,
        }
    }
}

impl Default for FieldSensitiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_path_creation() {
        let path = FieldPath::new("obj");
        assert_eq!(path.base, "obj");
        assert!(path.fields.is_empty());
        assert_eq!(path.to_dotted(), "obj");

        let path2 = FieldPath::with_field("obj", "field");
        assert_eq!(path2.to_dotted(), "obj.field");

        let path3 = FieldPath::from_dotted("obj.field.subfield");
        assert_eq!(path3.base, "obj");
        assert_eq!(path3.fields, vec!["field", "subfield"]);
    }

    #[test]
    fn test_field_path_append() {
        let path = FieldPath::new("obj");
        let path2 = path.append("field");
        assert_eq!(path2.to_dotted(), "obj.field");

        let path3 = path2.append("subfield");
        assert_eq!(path3.to_dotted(), "obj.field.subfield");
    }

    #[test]
    fn test_field_path_parent() {
        let path = FieldPath::from_dotted("obj.field.subfield");

        let parent = path.parent().unwrap();
        assert_eq!(parent.to_dotted(), "obj.field");

        let grandparent = parent.parent().unwrap();
        assert_eq!(grandparent.to_dotted(), "obj");

        assert!(grandparent.parent().is_none());
    }

    #[test]
    fn test_field_path_prefix() {
        let path1 = FieldPath::from_dotted("obj.field");
        let path2 = FieldPath::from_dotted("obj.field.subfield");
        let path3 = FieldPath::from_dotted("obj.other");

        assert!(path1.is_prefix_of(&path2));
        assert!(!path2.is_prefix_of(&path1));
        assert!(!path1.is_prefix_of(&path3));
    }

    #[test]
    fn test_field_taint_map_basic() {
        let mut map = FieldTaintMap::new();

        // Mark obj.field as tainted
        map.mark_tainted_dotted("obj.field", Some(10), Some("userInput".to_string()));

        assert!(map.is_tainted_dotted("obj.field"));
        assert!(!map.is_tainted_dotted("obj.other"));
        assert!(!map.is_tainted_dotted("obj")); // Base not tainted
    }

    #[test]
    fn test_field_taint_propagation_down() {
        let mut map = FieldTaintMap::new();

        // Mark base as tainted
        map.mark_tainted(FieldPath::new("obj"), Some(10), None);

        // All fields should be tainted
        assert!(map.is_tainted_dotted("obj.field"));
        assert!(map.is_tainted_dotted("obj.field.subfield"));
    }

    #[test]
    fn test_property_assignment() {
        let mut map = FieldTaintMap::new();

        // obj.field = tainted
        map.handle_property_assignment(
            FieldPath::with_field("obj", "field"),
            true,
            Some(10),
            Some("userInput".to_string()),
        );

        assert!(map.is_tainted_dotted("obj.field"));
        assert!(!map.is_tainted_dotted("obj.other"));

        // obj.field = clean (clears taint)
        map.handle_property_assignment(
            FieldPath::with_field("obj", "field"),
            false,
            Some(20),
            None,
        );

        assert!(!map.is_tainted_dotted("obj.field"));
    }

    #[test]
    fn test_property_read() {
        let mut map = FieldTaintMap::new();
        map.mark_tainted_dotted("obj.field", Some(10), None);

        // Read from tainted field
        let path = FieldPath::with_field("obj", "field");
        assert!(map.handle_property_read(&path));

        // Read from clean field
        let path2 = FieldPath::with_field("obj", "other");
        assert!(!map.handle_property_read(&path2));
    }

    #[test]
    fn test_destructuring() {
        let mut map = FieldTaintMap::new();
        map.mark_tainted_dotted("obj.tainted_field", Some(10), None);
        map.mark_clean(&FieldPath::with_field("obj", "clean_field"));

        let source = FieldPath::new("obj");
        let result = map.handle_destructuring(&source, &["tainted_field", "clean_field"]);

        assert_eq!(result.get("tainted_field"), Some(&true));
        assert_eq!(result.get("clean_field"), Some(&false));
    }

    #[test]
    fn test_spread_with_override() {
        let mut map = FieldTaintMap::new();
        map.mark_tainted_dotted("src.tainted", Some(10), None);
        map.mark_tainted_dotted("src.overridden", Some(10), None);

        let source = FieldPath::new("src");
        let mut overrides = HashMap::new();
        overrides.insert("overridden".to_string(), false); // Override with clean
        overrides.insert("new_tainted".to_string(), true); // Add new tainted

        let result = map.handle_spread_with_override(&source, &overrides, "dest", Some(20));

        assert!(result.is_tainted_dotted("dest.tainted"));
        assert!(!result.is_tainted_dotted("dest.overridden")); // Was overridden
        assert!(result.is_tainted_dotted("dest.new_tainted"));
    }

    #[test]
    fn test_computed_access() {
        let mut map = FieldTaintMap::new();
        map.mark_tainted_dotted("obj.secret", Some(10), None);

        let source = FieldPath::new("obj");

        // Static access with known key
        assert!(map.handle_computed_access(&source, Some("secret")));
        assert!(!map.handle_computed_access(&source, Some("other")));

        // Dynamic access (conservative: any tainted field means true)
        assert!(map.handle_computed_access(&source, None));
    }

    #[test]
    fn test_merge_maps() {
        let mut map1 = FieldTaintMap::new();
        map1.mark_tainted_dotted("obj.a", Some(10), None);

        let mut map2 = FieldTaintMap::new();
        map2.mark_tainted_dotted("obj.b", Some(20), None);

        map1.merge(&map2);

        assert!(map1.is_tainted_dotted("obj.a"));
        assert!(map1.is_tainted_dotted("obj.b"));
    }

    #[test]
    fn test_field_sensitive_analyzer() {
        let mut analyzer = FieldSensitiveAnalyzer::new();

        // obj.userInput = req.query.id (tainted)
        analyzer.process_property_assignment("obj", "userInput", None, true, 10);

        // obj.safe = "literal" (clean)
        analyzer.process_property_assignment("obj", "safe", None, false, 11);

        assert!(analyzer.is_tainted("obj.userInput"));
        assert!(!analyzer.is_tainted("obj.safe"));

        // Read from tainted field
        let is_tainted = analyzer.process_property_read("obj", "userInput");
        assert!(is_tainted);
    }

    #[test]
    fn test_analyzer_destructuring() {
        let mut analyzer = FieldSensitiveAnalyzer::new();

        // Mark source.tainted as tainted
        analyzer.process_property_assignment("source", "tainted", None, true, 10);

        // const { tainted: x, clean: y } = source
        analyzer.process_destructuring("source", &[("tainted", "x"), ("clean", "y")], 20);

        assert!(analyzer.is_tainted("x"));
        assert!(!analyzer.is_tainted("y"));
    }

    #[test]
    fn test_analyzer_spread() {
        let mut analyzer = FieldSensitiveAnalyzer::new();

        // Mark src.existing as tainted
        analyzer.process_property_assignment("src", "existing", None, true, 10);

        // const dest = { ...src, override: tainted, clean: "safe" }
        analyzer.process_spread_with_override(
            "src",
            vec![("override", true), ("clean", false)],
            "dest",
            20,
        );

        assert!(analyzer.is_tainted("dest.existing"));
        assert!(analyzer.is_tainted("dest.override"));
        assert!(!analyzer.is_tainted("dest.clean"));
    }

    #[test]
    fn test_fully_tainted_variable() {
        let mut analyzer = FieldSensitiveAnalyzer::new();

        // Mark entire variable as tainted
        analyzer.mark_fully_tainted("userInput", 10, Some("req.body".to_string()));

        // All fields should be tainted
        assert!(analyzer.is_tainted("userInput"));
        assert!(analyzer.is_tainted("userInput.anything"));
        assert!(analyzer.is_tainted("userInput.deep.nested.field"));
    }

    #[test]
    fn test_build_result() {
        let mut analyzer = FieldSensitiveAnalyzer::new();
        analyzer.process_property_assignment("obj", "field", None, true, 10);
        analyzer.mark_fully_tainted("tainted_var", 20, None);

        let result = analyzer.build();

        assert!(result.is_tainted("obj.field"));
        assert!(result.is_tainted("tainted_var"));
        assert!(result.is_tainted("tainted_var.any_field"));

        let all_tainted = result.all_tainted_paths();
        assert!(!all_tainted.is_empty());
    }

    #[test]
    fn test_field_taint_status() {
        assert!(FieldTaintStatus::Tainted.is_tainted());
        assert!(!FieldTaintStatus::Tainted.is_clean());

        assert!(!FieldTaintStatus::Clean.is_tainted());
        assert!(FieldTaintStatus::Clean.is_clean());

        assert!(!FieldTaintStatus::Sanitized.is_tainted());
        assert!(FieldTaintStatus::Sanitized.is_clean());

        assert!(!FieldTaintStatus::Unknown.is_tainted());
        assert!(!FieldTaintStatus::Unknown.is_clean());
    }

    #[test]
    fn test_tainted_fields_of() {
        let mut map = FieldTaintMap::new();
        map.mark_tainted_dotted("obj.a", Some(10), None);
        map.mark_tainted_dotted("obj.b", Some(20), None);
        map.mark_tainted_dotted("other.c", Some(30), None);

        let obj_fields = map.tainted_fields_of("obj");
        assert_eq!(obj_fields.len(), 2);

        let other_fields = map.tainted_fields_of("other");
        assert_eq!(other_fields.len(), 1);

        let empty_fields = map.tainted_fields_of("nonexistent");
        assert_eq!(empty_fields.len(), 0);
    }

    #[test]
    fn test_array_destructuring() {
        let mut map = FieldTaintMap::new();
        map.mark_tainted(FieldPath::with_field("arr", "0"), Some(10), None);
        map.mark_tainted(FieldPath::with_field("arr", "2"), Some(20), None);

        let source = FieldPath::new("arr");
        let results = map.handle_array_destructuring(&source, 4);

        assert_eq!(results, vec![true, false, true, false]);
    }

    #[test]
    fn test_sanitization() {
        let mut map = FieldTaintMap::new();
        map.mark_tainted_dotted("obj.field", Some(10), Some("userInput".to_string()));

        assert!(map.is_tainted_dotted("obj.field"));

        // Sanitize the field
        map.mark_sanitized(&FieldPath::with_field("obj", "field"), 20);

        assert!(!map.is_tainted_dotted("obj.field"));

        // Check the info
        let info = map
            .get_info(&FieldPath::with_field("obj", "field"))
            .unwrap();
        assert_eq!(info.status, FieldTaintStatus::Sanitized);
        assert_eq!(info.sanitized_line, Some(20));
    }
}
