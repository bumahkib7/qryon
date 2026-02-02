//! Python semantic mappings
//!
//! Maps tree-sitter-python node kinds to generic semantic concepts.

use super::LanguageSemantics;

/// Python semantic mappings
///
/// Python uses indentation-based blocks rather than explicit block markers,
/// and has no separate variable declaration syntax - variables are created
/// by assignment. Python 3.10+ adds structural pattern matching (match statement).
pub static PYTHON_SEMANTICS: LanguageSemantics = LanguageSemantics {
    language: "python",

    // Node kinds
    function_def_kinds: &["function_definition", "lambda"],
    if_kinds: &["if_statement"],
    loop_kinds: &["for_statement", "while_statement"],
    // Python has no separate declaration - variables created via assignment
    variable_declaration_kinds: &["assignment", "augmented_assignment"],
    assignment_kinds: &["assignment", "augmented_assignment"],
    augmented_assignment_kinds: &["augmented_assignment"],
    return_kinds: &["return_statement"],
    call_kinds: &["call"],
    try_catch_kinds: &["try_statement"],
    throw_kinds: &["raise_statement"],
    string_literal_kinds: &["string", "concatenated_string"],
    numeric_literal_kinds: &["integer", "float"],
    boolean_literal_kinds: &["true", "false"],
    null_literal_kinds: &["none"],
    parameter_kinds: &[
        "parameters",
        "default_parameter",
        "typed_parameter",
        "typed_default_parameter",
        "list_splat_pattern",       // *args
        "dictionary_splat_pattern", // **kwargs
    ],
    class_kinds: &["class_definition"],
    import_kinds: &["import_statement", "import_from_statement"],
    block_scope_kinds: &["block"],
    break_kinds: &["break_statement"],
    continue_kinds: &["continue_statement"],
    switch_kinds: &["match_statement"], // Python 3.10+ structural pattern matching
    case_kinds: &["case_clause"],
    member_access_kinds: &["attribute"],
    binary_expression_kinds: &["binary_operator", "boolean_operator", "comparison_operator"],
    identifier_kinds: &["identifier"],
    unsafe_block_kinds: &[], // Python has no unsafe blocks
    defer_kinds: &[],        // Python uses context managers (with statement), not defer
    spawn_kinds: &[],        // Python async is handled differently

    // Field names (tree-sitter-python grammar)
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
    property_field: "attribute",
    function_field: "function",
    parameters_field: "parameters",
    return_type_field: "return_type",
    type_field: "type",
    handler_field: "handler",    // except clause handler
    finalizer_field: "finalize", // finally clause
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_function_kinds() {
        assert!(PYTHON_SEMANTICS.is_function_def("function_definition"));
        assert!(PYTHON_SEMANTICS.is_function_def("lambda"));
    }

    #[test]
    fn test_python_loop_kinds() {
        assert!(PYTHON_SEMANTICS.is_loop("for_statement"));
        assert!(PYTHON_SEMANTICS.is_loop("while_statement"));
        // Python has no do-while loop
    }

    #[test]
    fn test_python_none() {
        assert!(PYTHON_SEMANTICS.is_null_literal("none"));
    }

    #[test]
    fn test_python_try_except() {
        assert!(PYTHON_SEMANTICS.is_try_catch("try_statement"));
        assert!(PYTHON_SEMANTICS.is_throw("raise_statement"));
    }

    #[test]
    fn test_python_match() {
        // Python 3.10+ pattern matching
        assert!(PYTHON_SEMANTICS.is_switch("match_statement"));
        assert!(PYTHON_SEMANTICS.is_case("case_clause"));
    }

    #[test]
    fn test_python_assignment_is_declaration() {
        // Python creates variables through assignment
        assert!(PYTHON_SEMANTICS.is_variable_declaration("assignment"));
        assert!(PYTHON_SEMANTICS.is_assignment("assignment"));
    }

    #[test]
    fn test_python_augmented_assignment() {
        assert!(PYTHON_SEMANTICS.is_augmented_assignment("augmented_assignment"));
        // Augmented assignment also counts as assignment in Python
        assert!(PYTHON_SEMANTICS.is_assignment("augmented_assignment"));
    }

    #[test]
    fn test_python_binary_operators() {
        assert!(PYTHON_SEMANTICS.is_binary_expression("binary_operator"));
        assert!(PYTHON_SEMANTICS.is_binary_expression("boolean_operator"));
        assert!(PYTHON_SEMANTICS.is_binary_expression("comparison_operator"));
    }

    #[test]
    fn test_python_no_unsafe() {
        // Python has no unsafe blocks
        assert!(PYTHON_SEMANTICS.unsafe_block_kinds.is_empty());
    }

    #[test]
    fn test_python_member_access() {
        assert!(PYTHON_SEMANTICS.is_member_access("attribute"));
    }
}
