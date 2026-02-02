//! Go semantic mappings
//!
//! Maps tree-sitter-go node kinds to generic semantic concepts.

use super::LanguageSemantics;

/// Go semantic mappings
pub static GO_SEMANTICS: LanguageSemantics = LanguageSemantics {
    language: "go",

    // Node kinds
    function_def_kinds: &["function_declaration", "method_declaration", "func_literal"],
    if_kinds: &["if_statement"],
    loop_kinds: &["for_statement"],
    variable_declaration_kinds: &[
        "var_declaration",
        "var_spec",
        "short_var_declaration",
        "const_declaration",
        "const_spec",
    ],
    assignment_kinds: &["assignment_statement"],
    augmented_assignment_kinds: &[], // Go uses assignment_statement with +=, etc.
    return_kinds: &["return_statement"],
    call_kinds: &["call_expression"],
    try_catch_kinds: &[], // Go uses defer/recover, not try/catch
    throw_kinds: &[],     // Go uses panic()
    string_literal_kinds: &[
        "raw_string_literal",
        "interpreted_string_literal",
        "rune_literal",
    ],
    numeric_literal_kinds: &["int_literal", "float_literal", "imaginary_literal"],
    boolean_literal_kinds: &["true", "false"],
    null_literal_kinds: &["nil"],
    parameter_kinds: &["parameter_declaration", "variadic_parameter_declaration"],
    class_kinds: &[
        "type_declaration",
        "type_spec",
        "struct_type",
        "interface_type",
    ],
    import_kinds: &["import_declaration", "import_spec"],
    block_scope_kinds: &["block"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    switch_kinds: &[
        "expression_switch_statement",
        "type_switch_statement",
        "select_statement",
    ],
    case_kinds: &[
        "expression_case",
        "type_case",
        "communication_case",
        "default_case",
    ],
    member_access_kinds: &["selector_expression", "index_expression"],
    binary_expression_kinds: &["binary_expression"],
    identifier_kinds: &[
        "identifier",
        "field_identifier",
        "type_identifier",
        "package_identifier",
    ],
    unsafe_block_kinds: &[], // Go unsafe is a package, not syntax
    defer_kinds: &["defer_statement"],
    spawn_kinds: &["go_statement"],

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
    object_field: "operand",
    property_field: "field",
    function_field: "function",
    parameters_field: "parameters",
    return_type_field: "result",
    type_field: "type",
    handler_field: "",   // N/A for Go
    finalizer_field: "", // N/A for Go
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_function_kinds() {
        assert!(GO_SEMANTICS.is_function_def("function_declaration"));
        assert!(GO_SEMANTICS.is_function_def("method_declaration"));
        assert!(GO_SEMANTICS.is_function_def("func_literal"));
    }

    #[test]
    fn test_go_loop_kinds() {
        // Go only has "for" loops
        assert!(GO_SEMANTICS.is_loop("for_statement"));
    }

    #[test]
    fn test_go_defer() {
        assert!(GO_SEMANTICS.is_defer("defer_statement"));
    }

    #[test]
    fn test_go_goroutine() {
        assert!(GO_SEMANTICS.is_spawn("go_statement"));
    }

    #[test]
    fn test_go_nil() {
        assert!(GO_SEMANTICS.is_null_literal("nil"));
    }

    #[test]
    fn test_go_switch() {
        assert!(GO_SEMANTICS.is_switch("expression_switch_statement"));
        assert!(GO_SEMANTICS.is_switch("type_switch_statement"));
        assert!(GO_SEMANTICS.is_switch("select_statement"));
    }
}
