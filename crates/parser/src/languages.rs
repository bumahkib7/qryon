//! Language support module - provides tree-sitter grammars for each language

use anyhow::Result;
use rma_common::{Language, RmaError};
use tree_sitter::Language as TsLanguage;

/// Get the tree-sitter language for a given language enum
pub fn get_language(lang: Language) -> Result<TsLanguage> {
    match lang {
        Language::Rust => Ok(tree_sitter_rust::LANGUAGE.into()),
        Language::JavaScript => Ok(tree_sitter_javascript::LANGUAGE.into()),
        Language::TypeScript => Ok(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Language::Python => Ok(tree_sitter_python::LANGUAGE.into()),
        Language::Go => Ok(tree_sitter_go::LANGUAGE.into()),
        Language::Java => Ok(tree_sitter_java::LANGUAGE.into()),
        Language::Unknown => Err(RmaError::UnsupportedLanguage("unknown".into()).into()),
    }
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
            Language::Java => Some(
                r#"
                (method_declaration name: (identifier) @name) @method
                (constructor_declaration name: (identifier) @name) @constructor
                "#,
            ),
            Language::Unknown => None,
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
            Language::Java => Some(
                r#"
                (class_declaration name: (identifier) @name) @class
                (interface_declaration name: (identifier) @name) @interface
                "#,
            ),
            Language::Unknown => None,
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
            Language::Java => Some(
                r#"
                (import_declaration) @import
                "#,
            ),
            Language::Unknown => None,
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
        assert!(get_language(Language::Unknown).is_err());
    }

    #[test]
    fn test_function_queries_exist() {
        assert!(queries::function_query(Language::Rust).is_some());
        assert!(queries::function_query(Language::JavaScript).is_some());
        assert!(queries::function_query(Language::Python).is_some());
        assert!(queries::function_query(Language::Unknown).is_none());
    }
}
