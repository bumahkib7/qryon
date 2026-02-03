//! Language Adapter Layer
//!
//! Maps tree-sitter node kinds from each language grammar to generic
//! semantic concepts (declaration, assignment, branch, loop, call, etc.).
//!
//! This module provides a unified abstraction over different programming languages,
//! allowing analysis rules to work with generic concepts rather than language-specific
//! node kinds. Each language module defines a static `LanguageSemantics` instance
//! that maps tree-sitter node kinds to these generic concepts.

use rma_common::Language;

pub mod go;
pub mod java;
pub mod javascript;
pub mod python;
pub mod rust_lang;

/// Generic semantic concepts mapped from tree-sitter node kinds.
///
/// This struct provides a language-agnostic view of code structure,
/// mapping each language's specific syntax to common programming concepts.
#[derive(Debug, Clone)]
pub struct LanguageSemantics {
    /// Language name (lowercase)
    pub language: &'static str,

    // =========================================================================
    // Node kinds that represent the same concept across languages
    // =========================================================================
    /// Function/method definition node kinds
    /// Examples: "function_declaration", "fn_item", "function_definition"
    pub function_def_kinds: &'static [&'static str],

    /// Conditional branch node kinds
    /// Examples: "if_statement", "if_expression", "if_let_expression"
    pub if_kinds: &'static [&'static str],

    /// Loop construct node kinds
    /// Examples: "for_statement", "while_statement", "loop_expression"
    pub loop_kinds: &'static [&'static str],

    /// Variable declaration node kinds
    /// Examples: "variable_declaration", "let_declaration", "var_spec"
    pub variable_declaration_kinds: &'static [&'static str],

    /// Simple assignment node kinds
    /// Examples: "assignment_expression", "assignment_statement"
    pub assignment_kinds: &'static [&'static str],

    /// Augmented assignment node kinds (+=, -=, etc.)
    /// Examples: "augmented_assignment_expression", "compound_assignment_expr"
    pub augmented_assignment_kinds: &'static [&'static str],

    /// Return statement node kinds
    /// Examples: "return_statement", "return_expression"
    pub return_kinds: &'static [&'static str],

    /// Function/method call node kinds
    /// Examples: "call_expression", "method_invocation"
    pub call_kinds: &'static [&'static str],

    /// Try/catch/finally construct node kinds
    /// Examples: "try_statement", "try_expression"
    pub try_catch_kinds: &'static [&'static str],

    /// Throw/raise node kinds
    /// Examples: "throw_statement", "raise_statement"
    pub throw_kinds: &'static [&'static str],

    /// String literal node kinds
    /// Examples: "string", "string_literal", "template_string"
    pub string_literal_kinds: &'static [&'static str],

    /// Numeric literal node kinds
    /// Examples: "number", "integer_literal", "float_literal"
    pub numeric_literal_kinds: &'static [&'static str],

    /// Boolean literal node kinds
    /// Examples: "true", "false", "boolean"
    pub boolean_literal_kinds: &'static [&'static str],

    /// Null/nil/None literal node kinds
    /// Examples: "null", "nil", "None"
    pub null_literal_kinds: &'static [&'static str],

    /// Parameter definition node kinds
    /// Examples: "formal_parameters", "parameter", "required_parameter"
    pub parameter_kinds: &'static [&'static str],

    /// Class/struct definition node kinds
    /// Examples: "class_declaration", "struct_item", "type_spec"
    pub class_kinds: &'static [&'static str],

    /// Import/use statement node kinds
    /// Examples: "import_declaration", "use_declaration", "import_statement"
    pub import_kinds: &'static [&'static str],

    /// Block scope node kinds (introduces a new scope)
    /// Examples: "block", "statement_block", "compound_statement"
    pub block_scope_kinds: &'static [&'static str],

    /// Break statement node kinds
    /// Examples: "break_statement", "break_expression"
    pub break_kinds: &'static [&'static str],

    /// Continue statement node kinds
    /// Examples: "continue_statement", "continue_expression"
    pub continue_kinds: &'static [&'static str],

    /// Switch/match statement node kinds
    /// Examples: "switch_statement", "match_expression"
    pub switch_kinds: &'static [&'static str],

    /// Case/arm node kinds in switch/match
    /// Examples: "case_clause", "switch_case", "match_arm"
    pub case_kinds: &'static [&'static str],

    /// Member/property access node kinds
    /// Examples: "member_expression", "field_expression", "selector_expression"
    pub member_access_kinds: &'static [&'static str],

    /// Binary expression node kinds
    /// Examples: "binary_expression", "binary_operator"
    pub binary_expression_kinds: &'static [&'static str],

    /// Identifier node kinds
    /// Examples: "identifier", "name"
    pub identifier_kinds: &'static [&'static str],

    /// Unsafe block node kinds (language-specific safety boundaries)
    /// Examples: "unsafe_block" (Rust)
    pub unsafe_block_kinds: &'static [&'static str],

    /// Deferred execution node kinds
    /// Examples: "defer_statement" (Go)
    pub defer_kinds: &'static [&'static str],

    /// Spawn/async task creation node kinds
    /// Examples: "spawn_expression", "go_statement"
    pub spawn_kinds: &'static [&'static str],

    // =========================================================================
    // Tree-sitter field names for accessing child nodes
    // =========================================================================
    /// Field name for condition in if/while/for statements
    pub condition_field: &'static str,

    /// Field name for the "then" branch
    pub consequence_field: &'static str,

    /// Field name for the "else" branch
    pub alternative_field: &'static str,

    /// Field name for function/loop body
    pub body_field: &'static str,

    /// Field name for variable initializer
    pub initializer_field: &'static str,

    /// Field name for left side of binary/assignment expressions
    pub left_field: &'static str,

    /// Field name for right side of binary/assignment expressions
    pub right_field: &'static str,

    /// Field name for names (function name, variable name, etc.)
    pub name_field: &'static str,

    /// Field name for function call arguments
    pub arguments_field: &'static str,

    /// Field name for values (return value, etc.)
    pub value_field: &'static str,

    /// Field name for operators
    pub operator_field: &'static str,

    /// Field name for object in member access
    pub object_field: &'static str,

    /// Field name for property in member access
    pub property_field: &'static str,

    /// Field name for function in call expression
    pub function_field: &'static str,

    /// Field name for function parameters
    pub parameters_field: &'static str,

    /// Field name for return type annotation
    pub return_type_field: &'static str,

    /// Field name for type annotation
    pub type_field: &'static str,

    /// Field name for exception handler in try/catch
    pub handler_field: &'static str,

    /// Field name for finalizer (finally block)
    pub finalizer_field: &'static str,
}

impl LanguageSemantics {
    /// Get the semantic mapping for a specific language
    pub fn for_language(language: Language) -> &'static LanguageSemantics {
        match language {
            Language::JavaScript | Language::TypeScript => &javascript::JAVASCRIPT_SEMANTICS,
            Language::Rust => &rust_lang::RUST_SEMANTICS,
            Language::Go => &go::GO_SEMANTICS,
            Language::Python => &python::PYTHON_SEMANTICS,
            Language::Java => &java::JAVA_SEMANTICS,
            // Fallback to JavaScript semantics for other languages
            _ => &javascript::JAVASCRIPT_SEMANTICS,
        }
    }

    /// Convert the language string to a Language enum
    pub fn language_enum(&self) -> Language {
        match self.language {
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "rust" => Language::Rust,
            "go" => Language::Go,
            "python" => Language::Python,
            "java" => Language::Java,
            _ => Language::Unknown,
        }
    }

    // =========================================================================
    // Helper methods to check if a node kind represents a specific concept
    // =========================================================================

    /// Check if a node kind represents a function definition
    pub fn is_function_def(&self, kind: &str) -> bool {
        self.function_def_kinds.contains(&kind)
    }

    /// Check if a node kind represents a conditional branch (if)
    pub fn is_if(&self, kind: &str) -> bool {
        self.if_kinds.contains(&kind)
    }

    /// Check if a node kind represents a loop construct
    pub fn is_loop(&self, kind: &str) -> bool {
        self.loop_kinds.contains(&kind)
    }

    /// Check if a node kind represents a variable declaration
    pub fn is_variable_declaration(&self, kind: &str) -> bool {
        self.variable_declaration_kinds.contains(&kind)
    }

    /// Check if a node kind represents an assignment
    pub fn is_assignment(&self, kind: &str) -> bool {
        self.assignment_kinds.contains(&kind)
    }

    /// Check if a node kind represents an augmented assignment (+=, etc.)
    pub fn is_augmented_assignment(&self, kind: &str) -> bool {
        self.augmented_assignment_kinds.contains(&kind)
    }

    /// Check if a node kind represents a return statement
    pub fn is_return(&self, kind: &str) -> bool {
        self.return_kinds.contains(&kind)
    }

    /// Check if a node kind represents a function/method call
    pub fn is_call(&self, kind: &str) -> bool {
        self.call_kinds.contains(&kind)
    }

    /// Check if a node kind represents a try/catch construct
    pub fn is_try_catch(&self, kind: &str) -> bool {
        self.try_catch_kinds.contains(&kind)
    }

    /// Check if a node kind represents a throw/raise statement
    pub fn is_throw(&self, kind: &str) -> bool {
        self.throw_kinds.contains(&kind)
    }

    /// Check if a node kind represents a string literal
    pub fn is_string_literal(&self, kind: &str) -> bool {
        self.string_literal_kinds.contains(&kind)
    }

    /// Check if a node kind represents a numeric literal
    pub fn is_numeric_literal(&self, kind: &str) -> bool {
        self.numeric_literal_kinds.contains(&kind)
    }

    /// Check if a node kind represents a boolean literal
    pub fn is_boolean_literal(&self, kind: &str) -> bool {
        self.boolean_literal_kinds.contains(&kind)
    }

    /// Check if a node kind represents a null/nil literal
    pub fn is_null_literal(&self, kind: &str) -> bool {
        self.null_literal_kinds.contains(&kind)
    }

    /// Check if a node kind represents any literal value
    pub fn is_literal(&self, kind: &str) -> bool {
        self.is_string_literal(kind)
            || self.is_numeric_literal(kind)
            || self.is_boolean_literal(kind)
            || self.is_null_literal(kind)
    }

    /// Check if a node kind represents a parameter definition
    pub fn is_parameter(&self, kind: &str) -> bool {
        self.parameter_kinds.contains(&kind)
    }

    /// Check if a node kind represents a class/struct definition
    pub fn is_class(&self, kind: &str) -> bool {
        self.class_kinds.contains(&kind)
    }

    /// Check if a node kind represents an import statement
    pub fn is_import(&self, kind: &str) -> bool {
        self.import_kinds.contains(&kind)
    }

    /// Check if a node kind represents a block scope
    pub fn is_block_scope(&self, kind: &str) -> bool {
        self.block_scope_kinds.contains(&kind)
    }

    /// Check if a node kind represents a break statement
    pub fn is_break(&self, kind: &str) -> bool {
        self.break_kinds.contains(&kind)
    }

    /// Check if a node kind represents a continue statement
    pub fn is_continue(&self, kind: &str) -> bool {
        self.continue_kinds.contains(&kind)
    }

    /// Check if a node kind represents a switch/match statement
    pub fn is_switch(&self, kind: &str) -> bool {
        self.switch_kinds.contains(&kind)
    }

    /// Check if a node kind represents a case/arm in a switch/match
    pub fn is_case(&self, kind: &str) -> bool {
        self.case_kinds.contains(&kind)
    }

    /// Check if a node kind represents a member/property access
    pub fn is_member_access(&self, kind: &str) -> bool {
        self.member_access_kinds.contains(&kind)
    }

    /// Check if a node kind represents a binary expression
    pub fn is_binary_expression(&self, kind: &str) -> bool {
        self.binary_expression_kinds.contains(&kind)
    }

    /// Check if a node kind represents an identifier
    pub fn is_identifier(&self, kind: &str) -> bool {
        self.identifier_kinds.contains(&kind)
    }

    /// Check if a node kind represents an unsafe block
    pub fn is_unsafe_block(&self, kind: &str) -> bool {
        self.unsafe_block_kinds.contains(&kind)
    }

    /// Check if a node kind represents a defer statement
    pub fn is_defer(&self, kind: &str) -> bool {
        self.defer_kinds.contains(&kind)
    }

    /// Check if a node kind represents a spawn/go statement
    pub fn is_spawn(&self, kind: &str) -> bool {
        self.spawn_kinds.contains(&kind)
    }

    /// Check if a node kind represents any control flow statement
    pub fn is_control_flow(&self, kind: &str) -> bool {
        self.is_if(kind)
            || self.is_loop(kind)
            || self.is_switch(kind)
            || self.is_try_catch(kind)
            || self.is_return(kind)
            || self.is_break(kind)
            || self.is_continue(kind)
            || self.is_throw(kind)
    }

    /// Check if a node kind represents any branching construct
    pub fn is_branch(&self, kind: &str) -> bool {
        self.is_if(kind) || self.is_switch(kind) || self.is_try_catch(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_semantics_lookup() {
        let js_semantics = LanguageSemantics::for_language(Language::JavaScript);
        assert_eq!(js_semantics.language, "javascript");

        let rust_semantics = LanguageSemantics::for_language(Language::Rust);
        assert_eq!(rust_semantics.language, "rust");

        let go_semantics = LanguageSemantics::for_language(Language::Go);
        assert_eq!(go_semantics.language, "go");

        let python_semantics = LanguageSemantics::for_language(Language::Python);
        assert_eq!(python_semantics.language, "python");

        let java_semantics = LanguageSemantics::for_language(Language::Java);
        assert_eq!(java_semantics.language, "java");
    }

    #[test]
    fn test_javascript_function_detection() {
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        assert!(semantics.is_function_def("function_declaration"));
        assert!(semantics.is_function_def("arrow_function"));
        assert!(!semantics.is_function_def("call_expression"));
    }

    #[test]
    fn test_rust_unsafe_detection() {
        let semantics = LanguageSemantics::for_language(Language::Rust);
        assert!(semantics.is_unsafe_block("unsafe_block"));
        assert!(!semantics.is_unsafe_block("block"));
    }

    #[test]
    fn test_control_flow_detection() {
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        assert!(semantics.is_control_flow("if_statement"));
        assert!(semantics.is_control_flow("for_statement"));
        assert!(semantics.is_control_flow("return_statement"));
        assert!(!semantics.is_control_flow("call_expression"));
    }
}
