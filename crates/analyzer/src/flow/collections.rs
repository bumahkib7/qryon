//! Collection-aware taint tracking for arrays, maps, and sets
//!
//! This module provides taint analysis that understands collection semantics:
//! - Arrays: push, pop, indexing, literals, spread operators
//! - Maps/Objects: get, set operations
//! - Sets: add, has, delete operations
//!
//! The key insight is that collections are "taint sinks" - if any tainted value
//! enters a collection, all values retrieved from that collection should be
//! considered potentially tainted.
//!
//! # Example
//!
//! ```text
//! const arr = [];
//! arr.push(taintedValue);  // arr becomes tainted
//! const x = arr[0];        // x is tainted (conservative)
//! const y = arr.pop();     // y is tainted
//! ```

use std::collections::{HashMap, HashSet};

/// Tracks the taint status of a collection (array, map, set)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionTaint {
    /// The collection variable name
    pub name: String,
    /// Whether any element in the collection is tainted
    pub is_tainted: bool,
    /// Indices/keys known to be tainted (for more precise tracking)
    /// None means "any access is tainted" (conservative)
    pub tainted_indices: Option<HashSet<CollectionKey>>,
    /// The type of collection
    pub collection_type: CollectionType,
    /// Variables that were added to this collection
    pub sources: Vec<String>,
}

/// Key type for collection element tracking
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CollectionKey {
    /// Numeric index (for arrays)
    Index(i64),
    /// String key (for maps/objects)
    Key(String),
    /// Unknown/dynamic key
    Dynamic,
}

/// Type of collection being tracked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionType {
    /// Array/List/Vec
    Array,
    /// Map/Object/Dict/HashMap
    Map,
    /// Set/HashSet
    Set,
    /// Unknown collection type
    Unknown,
}

/// Result of analyzing a collection operation
#[derive(Debug, Clone)]
pub enum CollectionOpResult {
    /// The operation taints the collection
    TaintsCollection { collection: String, source: String },
    /// The operation retrieves a potentially tainted value
    ReturnsTainted { collection: String },
    /// The operation has no taint effect
    NoEffect,
}

/// Collection taint analyzer
///
/// Tracks taint flow through collection operations to ensure that
/// tainted values placed into collections properly taint values
/// retrieved from those collections.
#[derive(Debug, Default)]
pub struct CollectionTaintTracker {
    /// Tracked collections (variable name -> taint info)
    collections: HashMap<String, CollectionTaint>,
    /// Variables derived from tainted collections
    derived_vars: HashMap<String, String>,
}

impl CollectionTaint {
    /// Create a new untainted collection
    pub fn new(name: impl Into<String>, collection_type: CollectionType) -> Self {
        Self {
            name: name.into(),
            is_tainted: false,
            tainted_indices: Some(HashSet::new()),
            collection_type,
            sources: Vec::new(),
        }
    }

    /// Create a tainted collection (all elements tainted)
    pub fn tainted(name: impl Into<String>, collection_type: CollectionType) -> Self {
        Self {
            name: name.into(),
            is_tainted: true,
            tainted_indices: None, // All indices tainted
            collection_type,
            sources: Vec::new(),
        }
    }

    /// Mark the entire collection as tainted
    pub fn mark_tainted(&mut self, source: Option<String>) {
        self.is_tainted = true;
        self.tainted_indices = None; // Conservative: all indices now tainted
        if let Some(src) = source
            && !self.sources.contains(&src)
        {
            self.sources.push(src);
        }
    }

    /// Mark a specific index/key as tainted
    pub fn mark_index_tainted(&mut self, key: CollectionKey, source: Option<String>) {
        self.is_tainted = true;
        if let Some(ref mut indices) = self.tainted_indices {
            indices.insert(key);
        }
        // If tainted_indices is None, collection is already fully tainted
        if let Some(src) = source
            && !self.sources.contains(&src)
        {
            self.sources.push(src);
        }
    }

    /// Check if accessing a specific index would return tainted data
    pub fn is_index_tainted(&self, key: &CollectionKey) -> bool {
        if !self.is_tainted {
            return false;
        }
        match &self.tainted_indices {
            None => true, // All indices tainted
            Some(indices) => {
                // Check specific key or dynamic access
                indices.contains(key) || indices.contains(&CollectionKey::Dynamic)
            }
        }
    }

    /// Check if any element access would be tainted (conservative)
    pub fn any_access_tainted(&self) -> bool {
        self.is_tainted
    }
}

impl CollectionTaintTracker {
    /// Create a new collection taint tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new collection variable
    pub fn register_collection(
        &mut self,
        name: impl Into<String>,
        collection_type: CollectionType,
    ) {
        let name = name.into();
        self.collections
            .insert(name.clone(), CollectionTaint::new(name, collection_type));
    }

    /// Register a collection that's initialized with tainted data
    pub fn register_tainted_collection(
        &mut self,
        name: impl Into<String>,
        collection_type: CollectionType,
        sources: Vec<String>,
    ) {
        let name = name.into();
        let mut taint = CollectionTaint::tainted(name.clone(), collection_type);
        taint.sources = sources;
        self.collections.insert(name, taint);
    }

    /// Get the taint status of a collection
    pub fn get_collection(&self, name: &str) -> Option<&CollectionTaint> {
        self.collections.get(name)
    }

    /// Check if a collection is tainted
    pub fn is_collection_tainted(&self, name: &str) -> bool {
        self.collections
            .get(name)
            .map(|c| c.is_tainted)
            .unwrap_or(false)
    }

    /// Check if a variable was derived from a tainted collection
    pub fn is_derived_from_tainted(&self, var_name: &str) -> bool {
        if let Some(collection_name) = self.derived_vars.get(var_name) {
            self.is_collection_tainted(collection_name)
        } else {
            false
        }
    }

    /// Get all tainted collection names
    pub fn tainted_collections(&self) -> Vec<&str> {
        self.collections
            .iter()
            .filter(|(_, c)| c.is_tainted)
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Get variables derived from a specific collection
    pub fn vars_from_collection(&self, collection_name: &str) -> Vec<&str> {
        self.derived_vars
            .iter()
            .filter(|(_, c)| c.as_str() == collection_name)
            .map(|(v, _)| v.as_str())
            .collect()
    }

    // =========================================================================
    // Array Operations
    // =========================================================================

    /// Handle array.push(value) - taints the array if value is tainted
    ///
    /// # Arguments
    /// * `array_name` - Name of the array variable
    /// * `value_name` - Name of the value being pushed
    /// * `is_value_tainted` - Whether the value is tainted
    ///
    /// # Returns
    /// CollectionOpResult indicating the taint effect
    pub fn handle_array_push(
        &mut self,
        array_name: &str,
        value_name: &str,
        is_value_tainted: bool,
    ) -> CollectionOpResult {
        if is_value_tainted {
            // Get or create the collection tracking
            let collection = self
                .collections
                .entry(array_name.to_string())
                .or_insert_with(|| CollectionTaint::new(array_name, CollectionType::Array));

            collection.mark_tainted(Some(value_name.to_string()));

            CollectionOpResult::TaintsCollection {
                collection: array_name.to_string(),
                source: value_name.to_string(),
            }
        } else {
            CollectionOpResult::NoEffect
        }
    }

    /// Handle array[index] access - returns tainted if array has tainted elements
    ///
    /// # Arguments
    /// * `array_name` - Name of the array variable
    /// * `index` - The index being accessed (None for dynamic/unknown index)
    /// * `result_var` - Optional name of the variable receiving the result
    ///
    /// # Returns
    /// CollectionOpResult indicating if the access returns tainted data
    pub fn handle_array_access(
        &mut self,
        array_name: &str,
        index: Option<i64>,
        result_var: Option<&str>,
    ) -> CollectionOpResult {
        let is_tainted = self
            .collections
            .get(array_name)
            .map(|c| {
                match index {
                    Some(i) => c.is_index_tainted(&CollectionKey::Index(i)),
                    None => c.any_access_tainted(), // Dynamic access - conservative
                }
            })
            .unwrap_or(false);

        if is_tainted {
            // Track the derived variable
            if let Some(var) = result_var {
                self.derived_vars
                    .insert(var.to_string(), array_name.to_string());
            }

            CollectionOpResult::ReturnsTainted {
                collection: array_name.to_string(),
            }
        } else {
            CollectionOpResult::NoEffect
        }
    }

    /// Handle array.pop() - returns tainted if array has tainted elements
    ///
    /// # Arguments
    /// * `array_name` - Name of the array variable
    /// * `result_var` - Optional name of the variable receiving the result
    ///
    /// # Returns
    /// CollectionOpResult indicating if pop() returns tainted data
    pub fn handle_array_pop(
        &mut self,
        array_name: &str,
        result_var: Option<&str>,
    ) -> CollectionOpResult {
        // Pop always potentially returns any element, so use conservative check
        let is_tainted = self
            .collections
            .get(array_name)
            .map(|c| c.any_access_tainted())
            .unwrap_or(false);

        if is_tainted {
            if let Some(var) = result_var {
                self.derived_vars
                    .insert(var.to_string(), array_name.to_string());
            }

            CollectionOpResult::ReturnsTainted {
                collection: array_name.to_string(),
            }
        } else {
            CollectionOpResult::NoEffect
        }
    }

    /// Handle array.shift() - returns tainted if array has tainted elements
    pub fn handle_array_shift(
        &mut self,
        array_name: &str,
        result_var: Option<&str>,
    ) -> CollectionOpResult {
        // shift() is similar to pop() but from the front
        self.handle_array_pop(array_name, result_var)
    }

    /// Handle array literal: [a, b, c] - tainted if any element is tainted
    ///
    /// # Arguments
    /// * `array_name` - Name of the variable being assigned the array
    /// * `elements` - List of (element_name, is_tainted) pairs
    ///
    /// # Returns
    /// CollectionOpResult indicating the taint effect
    pub fn handle_array_literal(
        &mut self,
        array_name: &str,
        elements: &[(String, bool)],
    ) -> CollectionOpResult {
        let tainted_sources: Vec<String> = elements
            .iter()
            .filter(|(_, is_tainted)| *is_tainted)
            .map(|(name, _)| name.clone())
            .collect();

        if !tainted_sources.is_empty() {
            let mut collection = CollectionTaint::new(array_name, CollectionType::Array);

            // Track which indices are tainted
            for (idx, (name, is_tainted)) in elements.iter().enumerate() {
                if *is_tainted {
                    collection
                        .mark_index_tainted(CollectionKey::Index(idx as i64), Some(name.clone()));
                }
            }

            self.collections.insert(array_name.to_string(), collection);

            CollectionOpResult::TaintsCollection {
                collection: array_name.to_string(),
                source: tainted_sources.join(", "),
            }
        } else {
            // Register as clean collection
            self.register_collection(array_name, CollectionType::Array);
            CollectionOpResult::NoEffect
        }
    }

    /// Handle spread operator: [...taintedArr] - result is tainted if source is
    ///
    /// # Arguments
    /// * `result_name` - Name of the resulting array variable
    /// * `source_arrays` - List of (source_name, is_tainted) for spread sources
    ///
    /// # Returns
    /// CollectionOpResult indicating the taint effect
    pub fn handle_array_spread(
        &mut self,
        result_name: &str,
        source_arrays: &[(String, bool)],
    ) -> CollectionOpResult {
        // Check if any source array is tainted
        let mut tainted_sources = Vec::new();

        for (source_name, explicit_taint) in source_arrays {
            // Check explicit taint or if the source collection is tracked as tainted
            let is_source_tainted = *explicit_taint || self.is_collection_tainted(source_name);
            if is_source_tainted {
                tainted_sources.push(source_name.clone());
            }
        }

        if !tainted_sources.is_empty() {
            self.register_tainted_collection(
                result_name,
                CollectionType::Array,
                tainted_sources.clone(),
            );

            CollectionOpResult::TaintsCollection {
                collection: result_name.to_string(),
                source: tainted_sources.join(", "),
            }
        } else {
            self.register_collection(result_name, CollectionType::Array);
            CollectionOpResult::NoEffect
        }
    }

    /// Handle array.concat() - result tainted if any source is tainted
    pub fn handle_array_concat(
        &mut self,
        result_name: &str,
        receiver: &str,
        args: &[(String, bool)],
    ) -> CollectionOpResult {
        let receiver_tainted = self.is_collection_tainted(receiver);

        let mut sources: Vec<(String, bool)> = vec![(receiver.to_string(), receiver_tainted)];
        sources.extend(args.iter().cloned());

        self.handle_array_spread(result_name, &sources)
    }

    /// Handle array.slice() - result tainted if source is tainted
    pub fn handle_array_slice(
        &mut self,
        result_name: &str,
        source_name: &str,
    ) -> CollectionOpResult {
        let is_source_tainted = self.is_collection_tainted(source_name);

        if is_source_tainted {
            self.register_tainted_collection(
                result_name,
                CollectionType::Array,
                vec![source_name.to_string()],
            );

            CollectionOpResult::TaintsCollection {
                collection: result_name.to_string(),
                source: source_name.to_string(),
            }
        } else {
            self.register_collection(result_name, CollectionType::Array);
            CollectionOpResult::NoEffect
        }
    }

    /// Handle array.map/filter/reduce - result tainted if source is tainted
    pub fn handle_array_transform(
        &mut self,
        result_name: &str,
        source_name: &str,
    ) -> CollectionOpResult {
        // Transformations preserve taint (conservative)
        self.handle_array_slice(result_name, source_name)
    }

    // =========================================================================
    // Map/Object Operations
    // =========================================================================

    /// Handle map.set(key, value) - taints map values if value is tainted
    ///
    /// # Arguments
    /// * `map_name` - Name of the map variable
    /// * `key` - The key being set (None for dynamic key)
    /// * `value_name` - Name of the value being set
    /// * `is_value_tainted` - Whether the value is tainted
    ///
    /// # Returns
    /// CollectionOpResult indicating the taint effect
    pub fn handle_map_set(
        &mut self,
        map_name: &str,
        key: Option<&str>,
        value_name: &str,
        is_value_tainted: bool,
    ) -> CollectionOpResult {
        if is_value_tainted {
            let collection = self
                .collections
                .entry(map_name.to_string())
                .or_insert_with(|| CollectionTaint::new(map_name, CollectionType::Map));

            let collection_key = match key {
                Some(k) => CollectionKey::Key(k.to_string()),
                None => CollectionKey::Dynamic,
            };

            collection.mark_index_tainted(collection_key, Some(value_name.to_string()));

            CollectionOpResult::TaintsCollection {
                collection: map_name.to_string(),
                source: value_name.to_string(),
            }
        } else {
            CollectionOpResult::NoEffect
        }
    }

    /// Handle map.get(key) - returns tainted if map values are tainted
    ///
    /// # Arguments
    /// * `map_name` - Name of the map variable
    /// * `key` - The key being accessed (None for dynamic key)
    /// * `result_var` - Optional name of the variable receiving the result
    ///
    /// # Returns
    /// CollectionOpResult indicating if get() returns tainted data
    pub fn handle_map_get(
        &mut self,
        map_name: &str,
        key: Option<&str>,
        result_var: Option<&str>,
    ) -> CollectionOpResult {
        let is_tainted = self
            .collections
            .get(map_name)
            .map(|c| {
                match key {
                    Some(k) => c.is_index_tainted(&CollectionKey::Key(k.to_string())),
                    None => c.any_access_tainted(), // Dynamic key - conservative
                }
            })
            .unwrap_or(false);

        if is_tainted {
            if let Some(var) = result_var {
                self.derived_vars
                    .insert(var.to_string(), map_name.to_string());
            }

            CollectionOpResult::ReturnsTainted {
                collection: map_name.to_string(),
            }
        } else {
            CollectionOpResult::NoEffect
        }
    }

    /// Handle object property access: obj.prop or obj[key]
    pub fn handle_object_access(
        &mut self,
        obj_name: &str,
        property: Option<&str>,
        result_var: Option<&str>,
    ) -> CollectionOpResult {
        self.handle_map_get(obj_name, property, result_var)
    }

    /// Handle object property assignment: obj.prop = value or obj[key] = value
    pub fn handle_object_assign(
        &mut self,
        obj_name: &str,
        property: Option<&str>,
        value_name: &str,
        is_value_tainted: bool,
    ) -> CollectionOpResult {
        self.handle_map_set(obj_name, property, value_name, is_value_tainted)
    }

    /// Handle object literal: { key: value, ... }
    pub fn handle_object_literal(
        &mut self,
        obj_name: &str,
        properties: &[(String, String, bool)], // (key, value_name, is_tainted)
    ) -> CollectionOpResult {
        let tainted_sources: Vec<String> = properties
            .iter()
            .filter(|(_, _, is_tainted)| *is_tainted)
            .map(|(_, value_name, _)| value_name.clone())
            .collect();

        if !tainted_sources.is_empty() {
            let mut collection = CollectionTaint::new(obj_name, CollectionType::Map);

            for (key, value_name, is_tainted) in properties {
                if *is_tainted {
                    collection.mark_index_tainted(
                        CollectionKey::Key(key.clone()),
                        Some(value_name.clone()),
                    );
                }
            }

            self.collections.insert(obj_name.to_string(), collection);

            CollectionOpResult::TaintsCollection {
                collection: obj_name.to_string(),
                source: tainted_sources.join(", "),
            }
        } else {
            self.register_collection(obj_name, CollectionType::Map);
            CollectionOpResult::NoEffect
        }
    }

    /// Handle object spread: { ...obj1, ...obj2 }
    pub fn handle_object_spread(
        &mut self,
        result_name: &str,
        source_objects: &[(String, bool)],
    ) -> CollectionOpResult {
        let mut tainted_sources = Vec::new();

        for (source_name, explicit_taint) in source_objects {
            let is_source_tainted = *explicit_taint || self.is_collection_tainted(source_name);
            if is_source_tainted {
                tainted_sources.push(source_name.clone());
            }
        }

        if !tainted_sources.is_empty() {
            self.register_tainted_collection(
                result_name,
                CollectionType::Map,
                tainted_sources.clone(),
            );

            CollectionOpResult::TaintsCollection {
                collection: result_name.to_string(),
                source: tainted_sources.join(", "),
            }
        } else {
            self.register_collection(result_name, CollectionType::Map);
            CollectionOpResult::NoEffect
        }
    }

    // =========================================================================
    // Set Operations
    // =========================================================================

    /// Handle set.add(value) - taints the set if value is tainted
    pub fn handle_set_add(
        &mut self,
        set_name: &str,
        value_name: &str,
        is_value_tainted: bool,
    ) -> CollectionOpResult {
        if is_value_tainted {
            let collection = self
                .collections
                .entry(set_name.to_string())
                .or_insert_with(|| CollectionTaint::new(set_name, CollectionType::Set));

            collection.mark_tainted(Some(value_name.to_string()));

            CollectionOpResult::TaintsCollection {
                collection: set_name.to_string(),
                source: value_name.to_string(),
            }
        } else {
            CollectionOpResult::NoEffect
        }
    }

    /// Handle iteration over set (for...of, forEach, etc.)
    pub fn handle_set_iteration(
        &mut self,
        set_name: &str,
        iterator_var: &str,
    ) -> CollectionOpResult {
        let is_tainted = self.is_collection_tainted(set_name);

        if is_tainted {
            self.derived_vars
                .insert(iterator_var.to_string(), set_name.to_string());

            CollectionOpResult::ReturnsTainted {
                collection: set_name.to_string(),
            }
        } else {
            CollectionOpResult::NoEffect
        }
    }

    // =========================================================================
    // Integration with TaintResult
    // =========================================================================

    /// Merge collection taint into a set of tainted variables
    ///
    /// This should be called after collection analysis to add derived
    /// tainted variables to the main taint result.
    pub fn merge_into_tainted_vars(&self, tainted_vars: &mut HashSet<String>) {
        // Add all variables derived from tainted collections
        for (var, collection) in &self.derived_vars {
            if self.is_collection_tainted(collection) {
                tainted_vars.insert(var.clone());
            }
        }

        // Also mark tainted collections themselves
        for (name, taint) in &self.collections {
            if taint.is_tainted {
                tainted_vars.insert(name.clone());
            }
        }
    }

    /// Get all additional tainted variables from collection analysis
    pub fn get_tainted_vars(&self) -> HashSet<String> {
        let mut result = HashSet::new();
        self.merge_into_tainted_vars(&mut result);
        result
    }

    /// Check if a variable is tainted (either a collection or derived from one)
    pub fn is_tainted(&self, var_name: &str) -> bool {
        self.is_collection_tainted(var_name) || self.is_derived_from_tainted(var_name)
    }
}

/// Identifies collection operations in code for taint tracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectionOperation {
    /// Array push: arr.push(value)
    ArrayPush { array: String, value: String },
    /// Array pop: arr.pop()
    ArrayPop { array: String },
    /// Array shift: arr.shift()
    ArrayShift { array: String },
    /// Array access: arr[index]
    ArrayAccess { array: String, index: Option<i64> },
    /// Array literal: [a, b, c]
    ArrayLiteral { elements: Vec<String> },
    /// Array spread: [...arr1, ...arr2]
    ArraySpread { sources: Vec<String> },
    /// Array concat: arr1.concat(arr2)
    ArrayConcat { receiver: String, args: Vec<String> },
    /// Array slice: arr.slice(start, end)
    ArraySlice { source: String },
    /// Array transform: arr.map/filter/reduce
    ArrayTransform { source: String, method: String },
    /// Map set: map.set(key, value)
    MapSet {
        map: String,
        key: Option<String>,
        value: String,
    },
    /// Map get: map.get(key)
    MapGet { map: String, key: Option<String> },
    /// Object property access: obj.prop
    ObjectAccess {
        object: String,
        property: Option<String>,
    },
    /// Object property assign: obj.prop = value
    ObjectAssign {
        object: String,
        property: Option<String>,
        value: String,
    },
    /// Object literal: { key: value }
    ObjectLiteral {
        properties: Vec<(String, String)>, // (key, value)
    },
    /// Object spread: { ...obj1, ...obj2 }
    ObjectSpread { sources: Vec<String> },
    /// Set add: set.add(value)
    SetAdd { set: String, value: String },
    /// Set iteration: for (x of set)
    SetIteration { set: String, iterator: String },
}

impl CollectionOperation {
    /// Check if this operation is an array method
    pub fn is_array_method(method_name: &str) -> bool {
        matches!(
            method_name.to_lowercase().as_str(),
            "push"
                | "pop"
                | "shift"
                | "unshift"
                | "splice"
                | "concat"
                | "slice"
                | "map"
                | "filter"
                | "reduce"
                | "find"
                | "findindex"
                | "some"
                | "every"
                | "foreach"
                | "flat"
                | "flatmap"
                | "fill"
                | "copywithin"
                | "reverse"
                | "sort"
                | "includes"
                | "indexof"
                | "lastindexof"
                | "join"
        )
    }

    /// Check if this operation is a map/object method
    pub fn is_map_method(method_name: &str) -> bool {
        matches!(
            method_name.to_lowercase().as_str(),
            "get" | "set" | "has" | "delete" | "clear" | "keys" | "values" | "entries" | "foreach"
        )
    }

    /// Check if this operation is a set method
    pub fn is_set_method(method_name: &str) -> bool {
        matches!(
            method_name.to_lowercase().as_str(),
            "add" | "has" | "delete" | "clear" | "keys" | "values" | "entries" | "foreach"
        )
    }

    /// Check if a method returns tainted data when called on a tainted collection
    pub fn method_propagates_taint(method_name: &str) -> bool {
        matches!(
            method_name.to_lowercase().as_str(),
            "pop"
                | "shift"
                | "splice"
                | "slice"
                | "concat"
                | "map"
                | "filter"
                | "reduce"
                | "find"
                | "flat"
                | "flatmap"
                | "get"
                | "values"
                | "entries"
                | "keys"
                | "join"
                | "tostring"
        )
    }

    /// Check if a method taints the collection when given tainted input
    pub fn method_taints_collection(method_name: &str) -> bool {
        matches!(
            method_name.to_lowercase().as_str(),
            "push" | "unshift" | "splice" | "set" | "add" | "fill"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_array_push_taints_collection() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("arr", CollectionType::Array);

        let result = tracker.handle_array_push("arr", "tainted_value", true);

        assert!(matches!(
            result,
            CollectionOpResult::TaintsCollection { .. }
        ));
        assert!(tracker.is_collection_tainted("arr"));
    }

    #[test]
    fn test_array_push_clean_no_taint() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("arr", CollectionType::Array);

        let result = tracker.handle_array_push("arr", "clean_value", false);

        assert!(matches!(result, CollectionOpResult::NoEffect));
        assert!(!tracker.is_collection_tainted("arr"));
    }

    #[test]
    fn test_array_access_returns_tainted() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("arr", CollectionType::Array);
        tracker.handle_array_push("arr", "tainted", true);

        let result = tracker.handle_array_access("arr", Some(0), Some("x"));

        assert!(matches!(result, CollectionOpResult::ReturnsTainted { .. }));
        assert!(tracker.is_derived_from_tainted("x"));
    }

    #[test]
    fn test_array_pop_returns_tainted() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("arr", CollectionType::Array);
        tracker.handle_array_push("arr", "tainted", true);

        let result = tracker.handle_array_pop("arr", Some("popped"));

        assert!(matches!(result, CollectionOpResult::ReturnsTainted { .. }));
        assert!(tracker.is_tainted("popped"));
    }

    #[test]
    fn test_array_literal_with_tainted_element() {
        let mut tracker = CollectionTaintTracker::new();

        let elements = vec![
            ("safe".to_string(), false),
            ("tainted".to_string(), true),
            ("also_safe".to_string(), false),
        ];

        let result = tracker.handle_array_literal("arr", &elements);

        assert!(matches!(
            result,
            CollectionOpResult::TaintsCollection { .. }
        ));
        assert!(tracker.is_collection_tainted("arr"));
    }

    #[test]
    fn test_array_spread_propagates_taint() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_tainted_collection(
            "tainted_arr",
            CollectionType::Array,
            vec!["source".to_string()],
        );
        tracker.register_collection("clean_arr", CollectionType::Array);

        let sources = vec![
            ("clean_arr".to_string(), false),
            ("tainted_arr".to_string(), false), // Not explicitly tainted, but tracked
        ];

        let result = tracker.handle_array_spread("result", &sources);

        assert!(matches!(
            result,
            CollectionOpResult::TaintsCollection { .. }
        ));
        assert!(tracker.is_collection_tainted("result"));
    }

    #[test]
    fn test_map_set_taints_map() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("map", CollectionType::Map);

        let result = tracker.handle_map_set("map", Some("key"), "tainted_value", true);

        assert!(matches!(
            result,
            CollectionOpResult::TaintsCollection { .. }
        ));
        assert!(tracker.is_collection_tainted("map"));
    }

    #[test]
    fn test_map_get_returns_tainted() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("map", CollectionType::Map);
        tracker.handle_map_set("map", Some("key"), "tainted", true);

        let result = tracker.handle_map_get("map", Some("key"), Some("value"));

        assert!(matches!(result, CollectionOpResult::ReturnsTainted { .. }));
        assert!(tracker.is_tainted("value"));
    }

    #[test]
    fn test_object_literal_with_tainted_property() {
        let mut tracker = CollectionTaintTracker::new();

        let properties = vec![
            ("safe_key".to_string(), "safe_value".to_string(), false),
            ("tainted_key".to_string(), "tainted_value".to_string(), true),
        ];

        let result = tracker.handle_object_literal("obj", &properties);

        assert!(matches!(
            result,
            CollectionOpResult::TaintsCollection { .. }
        ));
        assert!(tracker.is_collection_tainted("obj"));
    }

    #[test]
    fn test_set_add_taints_set() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("set", CollectionType::Set);

        let result = tracker.handle_set_add("set", "tainted_value", true);

        assert!(matches!(
            result,
            CollectionOpResult::TaintsCollection { .. }
        ));
        assert!(tracker.is_collection_tainted("set"));
    }

    #[test]
    fn test_set_iteration_propagates_taint() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_tainted_collection("set", CollectionType::Set, vec!["source".to_string()]);

        let result = tracker.handle_set_iteration("set", "item");

        assert!(matches!(result, CollectionOpResult::ReturnsTainted { .. }));
        assert!(tracker.is_tainted("item"));
    }

    #[test]
    fn test_merge_into_tainted_vars() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("arr", CollectionType::Array);
        tracker.handle_array_push("arr", "tainted", true);
        tracker.handle_array_access("arr", Some(0), Some("x"));

        let mut tainted_vars = HashSet::new();
        tracker.merge_into_tainted_vars(&mut tainted_vars);

        assert!(tainted_vars.contains("arr"));
        assert!(tainted_vars.contains("x"));
    }

    #[test]
    fn test_collection_operation_method_detection() {
        assert!(CollectionOperation::is_array_method("push"));
        assert!(CollectionOperation::is_array_method("map"));
        assert!(CollectionOperation::is_array_method("filter"));
        assert!(!CollectionOperation::is_array_method("get"));

        assert!(CollectionOperation::is_map_method("get"));
        assert!(CollectionOperation::is_map_method("set"));
        assert!(!CollectionOperation::is_map_method("push"));

        assert!(CollectionOperation::is_set_method("add"));
        assert!(CollectionOperation::is_set_method("has"));
        assert!(!CollectionOperation::is_set_method("push"));
    }

    #[test]
    fn test_method_taint_propagation() {
        assert!(CollectionOperation::method_propagates_taint("pop"));
        assert!(CollectionOperation::method_propagates_taint("map"));
        assert!(CollectionOperation::method_propagates_taint("get"));
        assert!(!CollectionOperation::method_propagates_taint("has"));

        assert!(CollectionOperation::method_taints_collection("push"));
        assert!(CollectionOperation::method_taints_collection("set"));
        assert!(CollectionOperation::method_taints_collection("add"));
        assert!(!CollectionOperation::method_taints_collection("pop"));
    }

    #[test]
    fn test_dynamic_index_access() {
        let mut tracker = CollectionTaintTracker::new();
        tracker.register_collection("arr", CollectionType::Array);
        tracker.handle_array_push("arr", "tainted", true);

        // Dynamic access (index unknown) should still return tainted
        let result = tracker.handle_array_access("arr", None, Some("x"));

        assert!(matches!(result, CollectionOpResult::ReturnsTainted { .. }));
    }

    #[test]
    fn test_specific_index_taint_tracking() {
        let mut tracker = CollectionTaintTracker::new();

        let elements = vec![("safe".to_string(), false), ("tainted".to_string(), true)];

        tracker.handle_array_literal("arr", &elements);

        // Accessing the tainted index
        let collection = tracker.get_collection("arr").unwrap();
        assert!(collection.is_index_tainted(&CollectionKey::Index(1)));
        // Index 0 should not be tainted specifically
        assert!(!collection.is_index_tainted(&CollectionKey::Index(0)));
    }
}
