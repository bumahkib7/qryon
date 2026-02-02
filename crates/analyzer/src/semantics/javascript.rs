//! JavaScript/TypeScript semantic mappings
//!
//! Maps tree-sitter-javascript and tree-sitter-typescript node kinds
//! to generic semantic concepts.

use super::LanguageSemantics;

/// JavaScript and TypeScript semantic mappings
///
/// Note: TypeScript uses the same base grammar with additional nodes,
/// so this mapping works for both languages.
pub static JAVASCRIPT_SEMANTICS: LanguageSemantics = LanguageSemantics {
    language: "javascript",

    // Node kinds
    function_def_kinds: &[
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    ],
    if_kinds: &["if_statement"],
    loop_kinds: &[
        "for_statement",
        "for_in_statement",
        "for_of_statement",
        "while_statement",
        "do_statement",
    ],
    variable_declaration_kinds: &[
        "variable_declaration",
        "lexical_declaration",
        "variable_declarator",
    ],
    assignment_kinds: &["assignment_expression"],
    augmented_assignment_kinds: &["augmented_assignment_expression"],
    return_kinds: &["return_statement"],
    call_kinds: &["call_expression", "new_expression"],
    try_catch_kinds: &["try_statement"],
    throw_kinds: &["throw_statement"],
    string_literal_kinds: &["string", "template_string", "template_literal"],
    numeric_literal_kinds: &["number"],
    boolean_literal_kinds: &["true", "false"],
    null_literal_kinds: &["null", "undefined"],
    parameter_kinds: &[
        "formal_parameters",
        "required_parameter",
        "optional_parameter",
        "rest_parameter",
    ],
    class_kinds: &["class_declaration", "class_expression", "class"],
    import_kinds: &[
        "import_statement",
        "import_declaration",
        "export_statement",
        "export_declaration",
    ],
    block_scope_kinds: &["statement_block", "block"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    switch_kinds: &["switch_statement"],
    case_kinds: &["switch_case", "switch_default"],
    member_access_kinds: &["member_expression", "subscript_expression"],
    binary_expression_kinds: &["binary_expression"],
    identifier_kinds: &[
        "identifier",
        "property_identifier",
        "shorthand_property_identifier",
    ],
    unsafe_block_kinds: &[], // JavaScript has no unsafe blocks
    defer_kinds: &[],        // JavaScript has no defer
    spawn_kinds: &[],        // async functions handled differently

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
    object_field: "object",
    property_field: "property",
    function_field: "function",
    parameters_field: "parameters",
    return_type_field: "return_type",
    type_field: "type",
    handler_field: "handler",
    finalizer_field: "finalizer",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_javascript_function_kinds() {
        assert!(JAVASCRIPT_SEMANTICS.is_function_def("function_declaration"));
        assert!(JAVASCRIPT_SEMANTICS.is_function_def("arrow_function"));
        assert!(JAVASCRIPT_SEMANTICS.is_function_def("method_definition"));
    }

    #[test]
    fn test_javascript_loop_kinds() {
        assert!(JAVASCRIPT_SEMANTICS.is_loop("for_statement"));
        assert!(JAVASCRIPT_SEMANTICS.is_loop("while_statement"));
        assert!(JAVASCRIPT_SEMANTICS.is_loop("for_of_statement"));
    }

    #[test]
    fn test_javascript_literals() {
        assert!(JAVASCRIPT_SEMANTICS.is_string_literal("string"));
        assert!(JAVASCRIPT_SEMANTICS.is_string_literal("template_string"));
        assert!(JAVASCRIPT_SEMANTICS.is_numeric_literal("number"));
        assert!(JAVASCRIPT_SEMANTICS.is_boolean_literal("true"));
        assert!(JAVASCRIPT_SEMANTICS.is_null_literal("null"));
        assert!(JAVASCRIPT_SEMANTICS.is_null_literal("undefined"));
    }
}
