//! Language support module - provides tree-sitter grammars for 30+ languages
//!
//! This module provides maximum language coverage with tree-sitter grammars,
//! optimized for fast parsing and security analysis.

use anyhow::Result;
use rma_common::{Language, RmaError};
use tree_sitter::Language as TsLanguage;

/// Get the tree-sitter language for a given language enum
///
/// Performance: Uses static references to avoid repeated allocations
#[inline]
pub fn get_language(lang: Language) -> Result<TsLanguage> {
    match lang {
        // Systems languages
        Language::Rust => Ok(tree_sitter_rust::LANGUAGE.into()),
        Language::C => Ok(tree_sitter_c::LANGUAGE.into()),
        Language::Cpp => Ok(tree_sitter_cpp::LANGUAGE.into()),
        Language::Zig => {
            Err(RmaError::UnsupportedLanguage("zig - grammar not yet available".into()).into())
        }

        // JVM languages
        Language::Java => Ok(tree_sitter_java::LANGUAGE.into()),
        Language::Kotlin => Ok(tree_sitter_kotlin::LANGUAGE.into()),
        Language::Scala => Ok(tree_sitter_scala::LANGUAGE.into()),

        // Web languages
        Language::JavaScript => Ok(tree_sitter_javascript::LANGUAGE.into()),
        Language::TypeScript => Ok(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Language::Html => Ok(tree_sitter_html::LANGUAGE.into()),
        Language::Css => Ok(tree_sitter_css::LANGUAGE.into()),
        Language::Scss => Ok(tree_sitter_css::LANGUAGE.into()), // Reuse CSS grammar for SCSS
        Language::Vue => {
            Err(RmaError::UnsupportedLanguage("vue - grammar not yet available".into()).into())
        }
        Language::Svelte => {
            Err(RmaError::UnsupportedLanguage("svelte - grammar not yet available".into()).into())
        }

        // Scripting languages
        Language::Python => Ok(tree_sitter_python::LANGUAGE.into()),
        Language::Ruby => Ok(tree_sitter_ruby::LANGUAGE.into()),
        Language::Php => Ok(tree_sitter_php::LANGUAGE_PHP.into()),
        Language::Lua => Ok(tree_sitter_lua::LANGUAGE.into()),
        Language::Perl => {
            Err(RmaError::UnsupportedLanguage("perl - grammar not yet available".into()).into())
        }

        // Functional languages
        Language::Haskell => Ok(tree_sitter_haskell::LANGUAGE.into()),
        Language::OCaml => Ok(tree_sitter_ocaml::LANGUAGE_OCAML.into()),
        Language::Elixir => Ok(tree_sitter_elixir::LANGUAGE.into()),
        Language::Erlang => {
            Err(RmaError::UnsupportedLanguage("erlang - grammar not yet available".into()).into())
        }

        // Other compiled languages
        Language::Go => Ok(tree_sitter_go::LANGUAGE.into()),
        Language::Swift => Ok(tree_sitter_swift::LANGUAGE.into()),
        Language::CSharp => Ok(tree_sitter_c_sharp::LANGUAGE.into()),
        Language::Dart => {
            Err(RmaError::UnsupportedLanguage("dart - grammar not yet available".into()).into())
        }

        // Data/Config languages
        Language::Json => Ok(tree_sitter_json::LANGUAGE.into()),
        Language::Yaml => Ok(tree_sitter_yaml::LANGUAGE.into()),
        Language::Toml => Ok(tree_sitter_toml::LANGUAGE.into()),
        Language::Sql => Err(RmaError::UnsupportedLanguage(
            "sql - grammar incompatible with tree-sitter 0.24".into(),
        )
        .into()),
        Language::GraphQL => {
            Err(RmaError::UnsupportedLanguage("graphql - grammar not yet available".into()).into())
        }

        // Infrastructure
        Language::Bash => Ok(tree_sitter_bash::LANGUAGE.into()),
        Language::Dockerfile => Err(RmaError::UnsupportedLanguage(
            "dockerfile - grammar incompatible with tree-sitter 0.24".into(),
        )
        .into()),
        Language::Hcl => Ok(tree_sitter_hcl::LANGUAGE.into()),
        Language::Nix => {
            Err(RmaError::UnsupportedLanguage("nix - grammar not yet available".into()).into())
        }

        // Markup
        Language::Markdown => Ok(tree_sitter_markdown::LANGUAGE.into()),
        Language::Latex => {
            Err(RmaError::UnsupportedLanguage("latex - grammar not yet available".into()).into())
        }

        // Other
        Language::Solidity => Ok(tree_sitter_solidity::LANGUAGE.into()),
        Language::Wasm => {
            Err(RmaError::UnsupportedLanguage("wasm - grammar not yet available".into()).into())
        }
        Language::Protobuf => Err(RmaError::UnsupportedLanguage(
            "protobuf - grammar incompatible with tree-sitter 0.24".into(),
        )
        .into()),

        Language::Unknown => Err(RmaError::UnsupportedLanguage("unknown".into()).into()),
    }
}

/// Check if a language has tree-sitter support
#[inline]
pub fn has_grammar(lang: Language) -> bool {
    get_language(lang).is_ok()
}

/// Get all languages with tree-sitter support
pub fn supported_languages() -> Vec<Language> {
    vec![
        Language::Rust,
        Language::C,
        Language::Cpp,
        Language::Java,
        Language::Kotlin,
        Language::Scala,
        Language::JavaScript,
        Language::TypeScript,
        Language::Html,
        Language::Css,
        Language::Python,
        Language::Ruby,
        Language::Php,
        Language::Lua,
        Language::Haskell,
        Language::OCaml,
        Language::Elixir,
        Language::Go,
        Language::Swift,
        Language::CSharp,
        Language::Json,
        Language::Yaml,
        Language::Toml,
        // Language::Sql disabled - no compatible crate for tree-sitter 0.24
        Language::Bash,
        // Language::Dockerfile disabled - no compatible crate for tree-sitter 0.24
        Language::Hcl,
        Language::Markdown,
        Language::Solidity,
        // Language::Protobuf disabled - no compatible crate for tree-sitter 0.24
    ]
}

/// Get query patterns for common constructs in each language
pub mod queries {
    use rma_common::Language;

    /// Function definition query for each language
    pub fn function_query(lang: Language) -> Option<&'static str> {
        match lang {
            Language::Rust => Some(
                r#"
                (function_item name: (identifier) @name) @function
                (impl_item (function_item name: (identifier) @name)) @method
                "#,
            ),
            Language::C | Language::Cpp => Some(
                r#"
                (function_definition declarator: (function_declarator declarator: (identifier) @name)) @function
                "#,
            ),
            Language::JavaScript | Language::TypeScript => Some(
                r#"
                (function_declaration name: (identifier) @name) @function
                (method_definition name: (property_identifier) @name) @method
                (arrow_function) @arrow
                "#,
            ),
            Language::Python => Some(
                r#"
                (function_definition name: (identifier) @name) @function
                (class_definition body: (block (function_definition name: (identifier) @name))) @method
                "#,
            ),
            Language::Go => Some(
                r#"
                (function_declaration name: (identifier) @name) @function
                (method_declaration name: (field_identifier) @name) @method
                "#,
            ),
            Language::Java | Language::Kotlin | Language::Scala => Some(
                r#"
                (method_declaration name: (identifier) @name) @method
                (constructor_declaration name: (identifier) @name) @constructor
                "#,
            ),
            Language::Ruby => Some(
                r#"
                (method name: (identifier) @name) @method
                "#,
            ),
            Language::Php => Some(
                r#"
                (function_definition name: (name) @name) @function
                (method_declaration name: (name) @name) @method
                "#,
            ),
            Language::Swift => Some(
                r#"
                (function_declaration name: (simple_identifier) @name) @function
                "#,
            ),
            Language::CSharp => Some(
                r#"
                (method_declaration name: (identifier) @name) @method
                "#,
            ),
            Language::Haskell => Some(
                r#"
                (function name: (variable) @name) @function
                "#,
            ),
            Language::Elixir => Some(
                r#"
                (call target: (identifier) @keyword arguments: (arguments (identifier) @name)) @function
                "#,
            ),
            Language::Lua => Some(
                r#"
                (function_declaration name: (identifier) @name) @function
                "#,
            ),
            Language::Bash => Some(
                r#"
                (function_definition name: (word) @name) @function
                "#,
            ),
            Language::Solidity => Some(
                r#"
                (function_definition name: (identifier) @name) @function
                "#,
            ),
            _ => None,
        }
    }

    /// Class/struct definition query for each language
    pub fn class_query(lang: Language) -> Option<&'static str> {
        match lang {
            Language::Rust => Some(
                r#"
                (struct_item name: (type_identifier) @name) @struct
                (enum_item name: (type_identifier) @name) @enum
                (impl_item type: (type_identifier) @name) @impl
                "#,
            ),
            Language::C | Language::Cpp => Some(
                r#"
                (struct_specifier name: (type_identifier) @name) @struct
                (class_specifier name: (type_identifier) @name) @class
                "#,
            ),
            Language::JavaScript | Language::TypeScript => Some(
                r#"
                (class_declaration name: (identifier) @name) @class
                "#,
            ),
            Language::Python => Some(
                r#"
                (class_definition name: (identifier) @name) @class
                "#,
            ),
            Language::Go => Some(
                r#"
                (type_declaration (type_spec name: (type_identifier) @name)) @type
                "#,
            ),
            Language::Java | Language::Kotlin | Language::Scala => Some(
                r#"
                (class_declaration name: (identifier) @name) @class
                (interface_declaration name: (identifier) @name) @interface
                "#,
            ),
            Language::Ruby => Some(
                r#"
                (class name: (constant) @name) @class
                (module name: (constant) @name) @module
                "#,
            ),
            Language::Php => Some(
                r#"
                (class_declaration name: (name) @name) @class
                (interface_declaration name: (name) @name) @interface
                "#,
            ),
            Language::Swift => Some(
                r#"
                (class_declaration name: (type_identifier) @name) @class
                (struct_declaration name: (type_identifier) @name) @struct
                "#,
            ),
            Language::CSharp => Some(
                r#"
                (class_declaration name: (identifier) @name) @class
                (interface_declaration name: (identifier) @name) @interface
                "#,
            ),
            Language::Solidity => Some(
                r#"
                (contract_declaration name: (identifier) @name) @contract
                "#,
            ),
            _ => None,
        }
    }

    /// Import/use statement query for each language
    pub fn import_query(lang: Language) -> Option<&'static str> {
        match lang {
            Language::Rust => Some(
                r#"
                (use_declaration) @import
                (extern_crate_declaration) @import
                "#,
            ),
            Language::C | Language::Cpp => Some(
                r#"
                (preproc_include) @import
                "#,
            ),
            Language::JavaScript | Language::TypeScript => Some(
                r#"
                (import_statement) @import
                (import_clause) @import
                "#,
            ),
            Language::Python => Some(
                r#"
                (import_statement) @import
                (import_from_statement) @import
                "#,
            ),
            Language::Go => Some(
                r#"
                (import_declaration) @import
                "#,
            ),
            Language::Java | Language::Kotlin | Language::Scala => Some(
                r#"
                (import_declaration) @import
                "#,
            ),
            Language::Ruby => Some(
                r#"
                (call method: (identifier) @method (#match? @method "require|require_relative|include|extend")) @import
                "#,
            ),
            Language::Php => Some(
                r#"
                (namespace_use_declaration) @import
                "#,
            ),
            Language::Swift => Some(
                r#"
                (import_declaration) @import
                "#,
            ),
            Language::CSharp => Some(
                r#"
                (using_directive) @import
                "#,
            ),
            Language::Elixir => Some(
                r#"
                (call target: (identifier) @keyword (#match? @keyword "import|require|use|alias")) @import
                "#,
            ),
            Language::Solidity => Some(
                r#"
                (import_directive) @import
                "#,
            ),
            _ => None,
        }
    }

    /// Call expression query for taint tracking
    pub fn call_query(lang: Language) -> Option<&'static str> {
        match lang {
            Language::Rust => Some(
                r#"
                (call_expression function: (identifier) @callee) @call
                (call_expression function: (field_expression field: (field_identifier) @callee)) @call
                "#,
            ),
            Language::C | Language::Cpp => Some(
                r#"
                (call_expression function: (identifier) @callee) @call
                "#,
            ),
            Language::JavaScript | Language::TypeScript => Some(
                r#"
                (call_expression function: (identifier) @callee) @call
                (call_expression function: (member_expression property: (property_identifier) @callee)) @call
                "#,
            ),
            Language::Python => Some(
                r#"
                (call function: (identifier) @callee) @call
                (call function: (attribute attribute: (identifier) @callee)) @call
                "#,
            ),
            Language::Go => Some(
                r#"
                (call_expression function: (identifier) @callee) @call
                (call_expression function: (selector_expression field: (field_identifier) @callee)) @call
                "#,
            ),
            Language::Java | Language::Kotlin => Some(
                r#"
                (method_invocation name: (identifier) @callee) @call
                "#,
            ),
            Language::Ruby => Some(
                r#"
                (call method: (identifier) @callee) @call
                "#,
            ),
            Language::Php => Some(
                r#"
                (function_call_expression function: (name) @callee) @call
                (method_call_expression name: (name) @callee) @call
                "#,
            ),
            Language::Swift => Some(
                r#"
                (call_expression (simple_identifier) @callee) @call
                "#,
            ),
            _ => None,
        }
    }

    /// Assignment expression query for taint tracking
    pub fn assignment_query(lang: Language) -> Option<&'static str> {
        match lang {
            Language::Rust => Some(
                r#"
                (assignment_expression left: (identifier) @lhs) @assignment
                (let_declaration pattern: (identifier) @lhs) @declaration
                "#,
            ),
            Language::C | Language::Cpp => Some(
                r#"
                (assignment_expression left: (identifier) @lhs) @assignment
                (declaration declarator: (init_declarator declarator: (identifier) @lhs)) @declaration
                "#,
            ),
            Language::JavaScript | Language::TypeScript => Some(
                r#"
                (assignment_expression left: (identifier) @lhs) @assignment
                (variable_declarator name: (identifier) @lhs) @declaration
                "#,
            ),
            Language::Python => Some(
                r#"
                (assignment left: (identifier) @lhs) @assignment
                "#,
            ),
            Language::Go => Some(
                r#"
                (assignment_statement left: (identifier) @lhs) @assignment
                (short_var_declaration left: (expression_list (identifier) @lhs)) @declaration
                "#,
            ),
            Language::Java | Language::Kotlin => Some(
                r#"
                (assignment_expression left: (identifier) @lhs) @assignment
                (variable_declarator name: (identifier) @lhs) @declaration
                "#,
            ),
            Language::Ruby => Some(
                r#"
                (assignment left: (identifier) @lhs) @assignment
                "#,
            ),
            Language::Php => Some(
                r#"
                (assignment_expression left: (variable_name) @lhs) @assignment
                "#,
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_language() {
        assert!(get_language(Language::Rust).is_ok());
        assert!(get_language(Language::JavaScript).is_ok());
        assert!(get_language(Language::Python).is_ok());
        assert!(get_language(Language::Go).is_ok());
        assert!(get_language(Language::Java).is_ok());
        assert!(get_language(Language::C).is_ok());
        assert!(get_language(Language::Cpp).is_ok());
        assert!(get_language(Language::Ruby).is_ok());
        assert!(get_language(Language::Php).is_ok());
        assert!(get_language(Language::Unknown).is_err());
    }

    #[test]
    fn test_supported_languages_count() {
        let supported = supported_languages();
        assert!(
            supported.len() >= 25,
            "Expected at least 25 supported languages"
        );
    }

    #[test]
    fn test_function_queries_exist() {
        assert!(queries::function_query(Language::Rust).is_some());
        assert!(queries::function_query(Language::JavaScript).is_some());
        assert!(queries::function_query(Language::Python).is_some());
        assert!(queries::function_query(Language::C).is_some());
        assert!(queries::function_query(Language::Unknown).is_none());
    }

    #[test]
    fn test_has_grammar() {
        assert!(has_grammar(Language::Rust));
        assert!(has_grammar(Language::Python));
        assert!(has_grammar(Language::Go));
        assert!(!has_grammar(Language::Unknown));
    }
}
