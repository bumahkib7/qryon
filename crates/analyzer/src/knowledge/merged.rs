//! Merged knowledge from multiple framework profiles
//!
//! Provides efficient lookup structures for sources, sinks, and sanitizers
//! across all detected frameworks. Optimized for large codebases with
//! lazy initialization and caching.

use super::types::*;
use rma_common::Language;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// Merged knowledge from all detected framework profiles
///
/// This struct combines knowledge from multiple frameworks into efficient
/// lookup structures. It's designed for production use with:
/// - O(1) pattern matching via hash sets
/// - Lazy compilation of regex patterns
/// - Memory-efficient static string references
#[derive(Debug)]
pub struct MergedKnowledge {
    /// Language this knowledge applies to
    pub language: Language,

    /// Names of active framework profiles
    pub active_frameworks: Vec<&'static str>,

    /// Fast lookup for source function calls
    source_functions: HashSet<&'static str>,

    /// Fast lookup for source member access patterns
    source_members: HashSet<&'static str>,

    /// Fast lookup for type extractors
    source_type_extractors: HashSet<&'static str>,

    /// Method on type patterns (type_pattern -> method)
    source_method_on_type: HashMap<&'static str, Vec<&'static str>>,

    /// Whether parameters are considered sources
    parameters_are_sources: bool,

    /// Full source definitions for detailed info
    all_sources: Vec<&'static SourceDef>,

    /// Fast lookup for sink function calls
    sink_functions: HashSet<&'static str>,

    /// Fast lookup for sink method calls
    sink_methods: HashSet<&'static str>,

    /// Fast lookup for sink macro invocations
    sink_macros: HashSet<&'static str>,

    /// Fast lookup for sink response body patterns
    sink_response_bodies: HashSet<&'static str>,

    /// Full sink definitions for detailed info
    all_sinks: Vec<&'static SinkDef>,

    /// Fast lookup for sanitizer functions
    sanitizer_functions: HashSet<&'static str>,

    /// Fast lookup for sanitizer method calls
    sanitizer_methods: HashSet<&'static str>,

    /// Fast lookup for sanitizer macros
    sanitizer_macros: HashSet<&'static str>,

    /// Sanitizer -> what it sanitizes (e.g., "html", "sql", "shell")
    sanitizer_targets: HashMap<&'static str, &'static str>,

    /// Full sanitizer definitions
    all_sanitizers: Vec<&'static SanitizerDef>,

    /// Safe pattern names for quick reference
    safe_patterns: HashSet<&'static str>,

    /// Full safe pattern definitions
    all_safe_patterns: Vec<&'static SafePattern>,

    /// Dangerous pattern definitions
    all_dangerous_patterns: Vec<&'static DangerousPattern>,

    /// Resource types that need lifecycle management
    all_resource_types: Vec<&'static ResourceType>,
}

impl MergedKnowledge {
    /// Create merged knowledge from a list of framework profiles
    ///
    /// This is the primary constructor used during flow analysis.
    pub fn from_profiles(language: Language, profiles: Vec<&'static FrameworkProfile>) -> Self {
        let mut merged = Self {
            language,
            active_frameworks: Vec::with_capacity(profiles.len()),
            source_functions: HashSet::new(),
            source_members: HashSet::new(),
            source_type_extractors: HashSet::new(),
            source_method_on_type: HashMap::new(),
            parameters_are_sources: false,
            all_sources: Vec::new(),
            sink_functions: HashSet::new(),
            sink_methods: HashSet::new(),
            sink_macros: HashSet::new(),
            sink_response_bodies: HashSet::new(),
            all_sinks: Vec::new(),
            sanitizer_functions: HashSet::new(),
            sanitizer_methods: HashSet::new(),
            sanitizer_macros: HashSet::new(),
            sanitizer_targets: HashMap::new(),
            all_sanitizers: Vec::new(),
            safe_patterns: HashSet::new(),
            all_safe_patterns: Vec::new(),
            all_dangerous_patterns: Vec::new(),
            all_resource_types: Vec::new(),
        };

        for profile in profiles {
            merged.merge_profile(profile);
        }

        merged
    }

    /// Create empty knowledge (for unknown languages)
    pub fn empty(language: Language) -> Self {
        Self {
            language,
            active_frameworks: Vec::new(),
            source_functions: HashSet::new(),
            source_members: HashSet::new(),
            source_type_extractors: HashSet::new(),
            source_method_on_type: HashMap::new(),
            parameters_are_sources: false,
            all_sources: Vec::new(),
            sink_functions: HashSet::new(),
            sink_methods: HashSet::new(),
            sink_macros: HashSet::new(),
            sink_response_bodies: HashSet::new(),
            all_sinks: Vec::new(),
            sanitizer_functions: HashSet::new(),
            sanitizer_methods: HashSet::new(),
            sanitizer_macros: HashSet::new(),
            sanitizer_targets: HashMap::new(),
            all_sanitizers: Vec::new(),
            safe_patterns: HashSet::new(),
            all_safe_patterns: Vec::new(),
            all_dangerous_patterns: Vec::new(),
            all_resource_types: Vec::new(),
        }
    }

    /// Merge a single framework profile into this knowledge base
    fn merge_profile(&mut self, profile: &'static FrameworkProfile) {
        self.active_frameworks.push(profile.name);

        // Merge sources
        for source in profile.sources {
            self.all_sources.push(source);

            match &source.pattern {
                SourceKind::FunctionCall(name) => {
                    self.source_functions.insert(name);
                }
                SourceKind::MemberAccess(path) => {
                    self.source_members.insert(path);
                }
                SourceKind::TypeExtractor(name) => {
                    self.source_type_extractors.insert(name);
                }
                SourceKind::MethodOnType {
                    type_pattern,
                    method,
                } => {
                    self.source_method_on_type
                        .entry(type_pattern)
                        .or_default()
                        .push(method);
                }
                SourceKind::Parameter => {
                    self.parameters_are_sources = true;
                }
            }
        }

        // Merge sinks
        for sink in profile.sinks {
            self.all_sinks.push(sink);

            match &sink.pattern {
                SinkKind::FunctionCall(name) => {
                    self.sink_functions.insert(name);
                }
                SinkKind::MethodCall(name) => {
                    self.sink_methods.insert(name);
                }
                SinkKind::MacroInvocation(name) => {
                    self.sink_macros.insert(name);
                }
                SinkKind::ResponseBody(name) => {
                    self.sink_response_bodies.insert(name);
                }
                SinkKind::PropertyAssignment(_) | SinkKind::TemplateInsertion => {
                    // These require different lookup strategies
                }
            }
        }

        // Merge sanitizers
        for sanitizer in profile.sanitizers {
            self.all_sanitizers.push(sanitizer);

            let key = match &sanitizer.pattern {
                SanitizerKind::Function(name) => {
                    self.sanitizer_functions.insert(name);
                    *name
                }
                SanitizerKind::MethodCall(name) => {
                    self.sanitizer_methods.insert(name);
                    *name
                }
                SanitizerKind::Macro(name) => {
                    self.sanitizer_macros.insert(name);
                    *name
                }
                SanitizerKind::TemplateEngine(name) => {
                    self.sanitizer_functions.insert(name);
                    *name
                }
            };

            self.sanitizer_targets.insert(key, sanitizer.sanitizes);
        }

        // Merge safe patterns
        for pattern in profile.safe_patterns {
            self.safe_patterns.insert(pattern.name);
            self.all_safe_patterns.push(pattern);
        }

        // Merge dangerous patterns
        self.all_dangerous_patterns
            .extend(profile.dangerous_patterns.iter());

        // Merge resource types
        self.all_resource_types
            .extend(profile.resource_types.iter());
    }

    // =========================================================================
    // Source queries (O(1) lookups)
    // =========================================================================

    /// Check if a function call is a taint source
    #[inline]
    pub fn is_source_function(&self, func_name: &str) -> bool {
        // Direct match
        if self.source_functions.contains(func_name) {
            return true;
        }

        // Check if it ends with any known source (e.g., "obj.method")
        for &source in &self.source_functions {
            if func_name.ends_with(source) {
                return true;
            }
        }

        false
    }

    /// Check if a member access is a taint source
    #[inline]
    pub fn is_source_member(&self, member_path: &str) -> bool {
        // Direct match
        if self.source_members.contains(member_path) {
            return true;
        }

        // Substring matching for nested paths
        for &source in &self.source_members {
            if member_path.contains(source) || member_path.ends_with(source) {
                return true;
            }
        }

        false
    }

    /// Check if a type extractor is a taint source
    #[inline]
    pub fn is_source_type_extractor(&self, type_name: &str) -> bool {
        self.source_type_extractors.contains(type_name)
            || self
                .source_type_extractors
                .iter()
                .any(|&t| type_name.contains(t))
    }

    /// Check if parameters should be treated as sources
    #[inline]
    pub fn parameters_are_sources(&self) -> bool {
        self.parameters_are_sources
    }

    /// Get source definition by pattern match
    pub fn get_source(&self, pattern: &str) -> Option<&'static SourceDef> {
        self.all_sources
            .iter()
            .find(|s| match &s.pattern {
                SourceKind::FunctionCall(p) => pattern.contains(*p),
                SourceKind::MemberAccess(p) => pattern.contains(*p),
                SourceKind::TypeExtractor(p) => pattern.contains(*p),
                SourceKind::MethodOnType { method, .. } => pattern.contains(*method),
                SourceKind::Parameter => false,
            })
            .copied()
    }

    // =========================================================================
    // Sink queries (O(1) lookups)
    // =========================================================================

    /// Check if a function call is a sink
    #[inline]
    pub fn is_sink_function(&self, func_name: &str) -> bool {
        if self.sink_functions.contains(func_name) {
            return true;
        }

        for &sink in &self.sink_functions {
            if func_name.ends_with(sink) || func_name.contains(sink) {
                return true;
            }
        }

        false
    }

    /// Check if a method call is a sink
    #[inline]
    pub fn is_sink_method(&self, method_name: &str) -> bool {
        if self.sink_methods.contains(method_name) {
            return true;
        }

        for &sink in &self.sink_methods {
            if method_name.ends_with(sink) {
                return true;
            }
        }

        false
    }

    /// Check if a macro is a sink
    #[inline]
    pub fn is_sink_macro(&self, macro_name: &str) -> bool {
        self.sink_macros.contains(macro_name)
    }

    /// Check if a property assignment is a sink
    pub fn is_sink_property(&self, prop_name: &str) -> bool {
        self.all_sinks.iter().any(|s| match &s.pattern {
            SinkKind::PropertyAssignment(p) => prop_name == *p,
            _ => false,
        })
    }

    /// Get sink definition by pattern match
    pub fn get_sink(&self, pattern: &str) -> Option<&'static SinkDef> {
        self.all_sinks
            .iter()
            .find(|s| match &s.pattern {
                SinkKind::FunctionCall(p) => pattern.contains(*p),
                SinkKind::MethodCall(p) => pattern.contains(*p),
                SinkKind::MacroInvocation(p) => pattern.contains(*p),
                SinkKind::PropertyAssignment(p) => pattern == *p,
                SinkKind::ResponseBody(p) => pattern.contains(*p),
                SinkKind::TemplateInsertion => false,
            })
            .copied()
    }

    // =========================================================================
    // Sanitizer queries (O(1) lookups)
    // =========================================================================

    /// Check if a function is a sanitizer
    #[inline]
    pub fn is_sanitizer(&self, func_name: &str) -> bool {
        // Direct match
        if self.sanitizer_functions.contains(func_name)
            || self.sanitizer_methods.contains(func_name)
            || self.sanitizer_macros.contains(func_name)
        {
            return true;
        }

        // Check with substring matching
        for &sanitizer in &self.sanitizer_functions {
            if func_name.contains(sanitizer) || func_name.ends_with(sanitizer) {
                return true;
            }
        }

        for &sanitizer in &self.sanitizer_methods {
            if func_name.ends_with(sanitizer) {
                return true;
            }
        }

        false
    }

    /// Check if function sanitizes a specific type of taint
    pub fn sanitizes_type(&self, func_name: &str, taint_type: &str) -> bool {
        // Find the sanitizer and check what it sanitizes
        for (&key, &target) in &self.sanitizer_targets {
            if func_name.contains(key) {
                return target == taint_type || target == "*";
            }
        }
        false
    }

    /// Get sanitizer definition
    pub fn get_sanitizer(&self, func_name: &str) -> Option<&'static SanitizerDef> {
        self.all_sanitizers
            .iter()
            .find(|s| match &s.pattern {
                SanitizerKind::Function(p) => func_name.contains(*p),
                SanitizerKind::MethodCall(p) => func_name.contains(*p),
                SanitizerKind::Macro(p) => func_name == *p,
                SanitizerKind::TemplateEngine(p) => func_name.contains(*p),
            })
            .copied()
    }

    // =========================================================================
    // Pattern queries
    // =========================================================================

    /// Check if a pattern is known to be safe
    #[inline]
    pub fn is_safe_pattern(&self, pattern_name: &str) -> bool {
        self.safe_patterns.contains(pattern_name)
    }

    /// Get all dangerous patterns to check
    pub fn dangerous_patterns(&self) -> &[&'static DangerousPattern] {
        &self.all_dangerous_patterns
    }

    /// Get all resource types
    pub fn resource_types(&self) -> &[&'static ResourceType] {
        &self.all_resource_types
    }

    // =========================================================================
    // Statistics and debugging
    // =========================================================================

    /// Get count of registered sources
    pub fn source_count(&self) -> usize {
        self.all_sources.len()
    }

    /// Get count of registered sinks
    pub fn sink_count(&self) -> usize {
        self.all_sinks.len()
    }

    /// Get count of registered sanitizers
    pub fn sanitizer_count(&self) -> usize {
        self.all_sanitizers.len()
    }

    /// Check if any frameworks are active
    pub fn has_frameworks(&self) -> bool {
        !self.active_frameworks.is_empty()
    }

    /// Get all source patterns as strings (for debugging/testing)
    pub fn all_source_patterns(&self) -> Vec<Cow<'static, str>> {
        let mut patterns = Vec::new();

        for &p in &self.source_functions {
            patterns.push(Cow::Borrowed(p));
        }
        for &p in &self.source_members {
            patterns.push(Cow::Borrowed(p));
        }
        for &p in &self.source_type_extractors {
            patterns.push(Cow::Borrowed(p));
        }

        patterns
    }
}

/// Builder for creating MergedKnowledge from source content
pub struct KnowledgeBuilder {
    language: Language,
}

impl KnowledgeBuilder {
    /// Create a new builder for a language
    pub fn new(language: Language) -> Self {
        Self { language }
    }

    /// Build merged knowledge by detecting frameworks from source content
    pub fn from_content(&self, content: &str) -> MergedKnowledge {
        let profiles = super::detect_frameworks(self.language, content);
        MergedKnowledge::from_profiles(self.language, profiles)
    }

    /// Build merged knowledge from a list of import strings
    pub fn from_imports(&self, imports: &[&str]) -> MergedKnowledge {
        let profiles = super::detect_frameworks_from_imports(self.language, imports);
        MergedKnowledge::from_profiles(self.language, profiles)
    }

    /// Build merged knowledge using all known profiles for the language
    pub fn all_profiles(&self) -> MergedKnowledge {
        let profiles = super::profiles_for_language(self.language);
        MergedKnowledge::from_profiles(self.language, profiles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merged_knowledge_javascript() {
        let builder = KnowledgeBuilder::new(Language::JavaScript);
        let knowledge = builder.all_profiles();

        assert!(knowledge.has_frameworks());
        assert!(knowledge.source_count() > 0);
        assert!(knowledge.sink_count() > 0);
        assert!(knowledge.sanitizer_count() > 0);

        // Test source detection
        assert!(knowledge.is_source_member("req.query"));
        assert!(knowledge.is_source_member("req.body"));
        assert!(knowledge.is_source_member("location.search"));

        // Test sink detection
        assert!(knowledge.is_sink_property("innerHTML"));
        assert!(knowledge.is_sink_function("eval"));

        // Test sanitizer detection
        assert!(knowledge.is_sanitizer("DOMPurify.sanitize"));
        assert!(knowledge.is_sanitizer("encodeURIComponent"));
    }

    #[test]
    fn test_merged_knowledge_rust() {
        let builder = KnowledgeBuilder::new(Language::Rust);
        let knowledge = builder.all_profiles();

        assert!(knowledge.has_frameworks());

        // Test source detection
        assert!(knowledge.is_source_function("env::var"));

        // Test sink detection
        assert!(knowledge.is_sink_function("Command::new"));

        // Test sanitizer detection
        assert!(knowledge.is_sanitizer("ammonia::clean"));
    }

    #[test]
    fn test_framework_detection() {
        let express_code = r#"
import express from 'express';
const app = express();
app.get('/user', (req, res) => {
    const query = req.query.name;
});
"#;

        let builder = KnowledgeBuilder::new(Language::JavaScript);
        let knowledge = builder.from_content(express_code);

        assert!(knowledge.active_frameworks.contains(&"express"));
    }

    #[test]
    fn test_empty_knowledge() {
        let knowledge = MergedKnowledge::empty(Language::Unknown);

        assert!(!knowledge.has_frameworks());
        assert_eq!(knowledge.source_count(), 0);
        assert_eq!(knowledge.sink_count(), 0);
        assert!(!knowledge.is_source_function("anything"));
        assert!(!knowledge.is_sink_function("anything"));
    }
}
