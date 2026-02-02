//! Rust semantic mappings
//!
//! Maps tree-sitter-rust node kinds to generic semantic concepts.

use super::LanguageSemantics;

/// Rust semantic mappings
pub static RUST_SEMANTICS: LanguageSemantics = LanguageSemantics {
    language: "rust",

    // Node kinds
    function_def_kinds: &["function_item", "closure_expression"],
    if_kinds: &["if_expression", "if_let_expression"],
    loop_kinds: &[
        "loop_expression",
        "while_expression",
        "while_let_expression",
        "for_expression",
    ],
    variable_declaration_kinds: &["let_declaration"],
    assignment_kinds: &["assignment_expression"],
    augmented_assignment_kinds: &["compound_assignment_expr"],
    return_kinds: &["return_expression"],
    call_kinds: &["call_expression", "macro_invocation"],
    try_catch_kinds: &[], // Rust uses Result, not try/catch
    throw_kinds: &[],     // Rust uses panic! macro
    string_literal_kinds: &["string_literal", "raw_string_literal", "char_literal"],
    numeric_literal_kinds: &["integer_literal", "float_literal"],
    boolean_literal_kinds: &["boolean_literal"],
    null_literal_kinds: &[], // Rust has no null
    parameter_kinds: &["parameter", "self_parameter"],
    class_kinds: &["struct_item", "enum_item", "impl_item", "trait_item"],
    import_kinds: &["use_declaration", "extern_crate_declaration"],
    block_scope_kinds: &["block"],
    break_kinds: &["break_expression"],
    continue_kinds: &["continue_expression"],
    switch_kinds: &["match_expression"],
    case_kinds: &["match_arm"],
    member_access_kinds: &["field_expression"],
    binary_expression_kinds: &["binary_expression"],
    identifier_kinds: &["identifier", "field_identifier", "type_identifier"],
    unsafe_block_kinds: &["unsafe_block"],
    defer_kinds: &[], // Rust uses Drop trait, not defer
    spawn_kinds: &[], // spawn is a library function, not syntax

    // Field names
    condition_field: "condition",
    consequence_field: "consequence",
    alternative_field: "alternative",
    body_field: "body",
    initializer_field: "value",
    left_field: "left",
    right_field: "right",
    name_field: "name",
    arguments_field: "arguments",
    value_field: "value",
    operator_field: "operator",
    object_field: "value", // Rust uses "value" for the object in field_expression
    property_field: "field",
    function_field: "function",
    parameters_field: "parameters",
    return_type_field: "return_type",
    type_field: "type",
    handler_field: "",   // N/A for Rust
    finalizer_field: "", // N/A for Rust
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_function_kinds() {
        assert!(RUST_SEMANTICS.is_function_def("function_item"));
        assert!(RUST_SEMANTICS.is_function_def("closure_expression"));
    }

    #[test]
    fn test_rust_loop_kinds() {
        assert!(RUST_SEMANTICS.is_loop("loop_expression"));
        assert!(RUST_SEMANTICS.is_loop("while_expression"));
        assert!(RUST_SEMANTICS.is_loop("for_expression"));
    }

    #[test]
    fn test_rust_unsafe_block() {
        assert!(RUST_SEMANTICS.is_unsafe_block("unsafe_block"));
        assert!(!RUST_SEMANTICS.is_unsafe_block("block"));
    }

    #[test]
    fn test_rust_match() {
        assert!(RUST_SEMANTICS.is_switch("match_expression"));
        assert!(RUST_SEMANTICS.is_case("match_arm"));
    }

    #[test]
    fn test_rust_no_null() {
        // Rust has no null literals
        assert!(!RUST_SEMANTICS.is_null_literal("null"));
        assert!(RUST_SEMANTICS.null_literal_kinds.is_empty());
    }
}
