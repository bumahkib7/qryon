//! Java semantic mappings
//!
//! Maps tree-sitter-java node kinds to generic semantic concepts.
//!
//! This module provides complete tree-sitter node kind mappings for Java,
//! covering modern Java features including records (Java 14+), switch expressions
//! (Java 12+), text blocks (Java 15+), and sealed classes (Java 17+).

use super::LanguageSemantics;

/// Java semantic mappings for tree-sitter-java grammar
///
/// Reference: https://github.com/tree-sitter/tree-sitter-java/blob/master/src/node-types.json
pub static JAVA_SEMANTICS: LanguageSemantics = LanguageSemantics {
    language: "java",

    // =========================================================================
    // Node kinds - Complete mappings from tree-sitter-java grammar
    // =========================================================================

    // Function/method definitions
    // - method_declaration: Regular methods
    // - constructor_declaration: Class constructors
    // - lambda_expression: Lambda expressions (Java 8+)
    // - compact_constructor_declaration: Record compact constructors (Java 14+)
    function_def_kinds: &[
        "method_declaration",
        "constructor_declaration",
        "lambda_expression",
        "compact_constructor_declaration",
    ],

    // Conditional branches
    if_kinds: &["if_statement"],

    // Loop constructs
    // - for_statement: Traditional for(init; cond; update)
    // - enhanced_for_statement: for-each loops (for T item : collection)
    // - while_statement: while(cond) loops
    // - do_statement: do-while loops
    loop_kinds: &[
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
    ],

    // Variable declarations
    // - local_variable_declaration: Variables in method bodies
    // - field_declaration: Class/instance fields
    // - constant_declaration: Interface constants
    variable_declaration_kinds: &[
        "local_variable_declaration",
        "field_declaration",
        "constant_declaration",
    ],

    // Assignment expressions
    // Note: Java treats += -= etc. as assignment_expression with different operators
    assignment_kinds: &["assignment_expression"],

    // Augmented assignment (compound assignment)
    // In Java these are part of assignment_expression but can be distinguished
    // by the operator (+= -= *= /= %= &= |= ^= <<= >>= >>>=)
    augmented_assignment_kinds: &["assignment_expression"],

    // Return statements
    return_kinds: &["return_statement"],

    // Call expressions
    // - method_invocation: obj.method() or method()
    // - object_creation_expression: new ClassName()
    // - explicit_constructor_invocation: this() or super() calls
    call_kinds: &[
        "method_invocation",
        "object_creation_expression",
        "explicit_constructor_invocation",
    ],

    // Exception handling
    // - try_statement: try-catch-finally
    // - try_with_resources_statement: try(resource) (Java 7+)
    try_catch_kinds: &["try_statement", "try_with_resources_statement"],

    // Throw statements
    throw_kinds: &["throw_statement"],

    // String literals
    // - string_literal: Regular "string"
    // - text_block: Multi-line """text block""" (Java 15+)
    // - character_literal: 'c'
    string_literal_kinds: &["string_literal", "text_block", "character_literal"],

    // Numeric literals - comprehensive coverage
    // - decimal_integer_literal: 123
    // - hex_integer_literal: 0xFF
    // - octal_integer_literal: 0777
    // - binary_integer_literal: 0b1010 (Java 7+)
    // - decimal_floating_point_literal: 3.14, 1e10
    // - hex_floating_point_literal: 0x1.0p0 (rare)
    numeric_literal_kinds: &[
        "decimal_integer_literal",
        "hex_integer_literal",
        "octal_integer_literal",
        "binary_integer_literal",
        "decimal_floating_point_literal",
        "hex_floating_point_literal",
    ],

    // Boolean literals
    boolean_literal_kinds: &["true", "false"],

    // Null literal
    null_literal_kinds: &["null_literal"],

    // Parameter kinds
    // - formal_parameter: Regular parameters
    // - spread_parameter: Varargs (Type... args)
    // - receiver_parameter: Explicit this parameter for type annotations
    parameter_kinds: &["formal_parameter", "spread_parameter", "receiver_parameter"],

    // Class/type definitions
    // - class_declaration: Regular classes
    // - interface_declaration: Interfaces
    // - enum_declaration: Enums
    // - record_declaration: Records (Java 14+)
    // - annotation_type_declaration: @interface annotations
    class_kinds: &[
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "annotation_type_declaration",
    ],

    // Import declarations
    import_kinds: &["import_declaration"],

    // Block scopes
    // - block: { } statement blocks
    // - static_initializer: static { } blocks
    // - instance_initializer: { } instance init blocks
    block_scope_kinds: &["block", "static_initializer", "instance_initializer"],

    // Break statements
    break_kinds: &["break_statement"],

    // Continue statements
    continue_kinds: &["continue_statement"],

    // Switch constructs
    // - switch_expression: Expression form (Java 12+) returns value
    // - switch_statement: Statement form (traditional)
    switch_kinds: &["switch_expression", "switch_statement"],

    // Case clauses in switch
    // - switch_block_statement_group: Traditional case: ... break;
    // - switch_rule: Arrow syntax case X -> ... (Java 12+)
    case_kinds: &["switch_block_statement_group", "switch_rule"],

    // Member/property access
    // - field_access: obj.field
    // - array_access: array[index]
    // - method_reference: Class::method (Java 8+)
    member_access_kinds: &["field_access", "array_access", "method_reference"],

    // Binary expressions
    binary_expression_kinds: &["binary_expression"],

    // Identifiers
    // - identifier: Variable/method names
    // - type_identifier: Type names (classes, interfaces)
    identifier_kinds: &["identifier", "type_identifier"],

    // Unsafe blocks - Java has no unsafe keyword
    // Note: JNI (native methods) are separate declarations, not blocks
    unsafe_block_kinds: &[],

    // Defer-like constructs - Java uses try-with-resources instead
    defer_kinds: &[],

    // Spawn/async - Java threads are library calls, not syntax
    // Note: Virtual threads (Java 21+) also use library APIs
    spawn_kinds: &[],

    // =========================================================================
    // Field names for accessing child nodes in tree-sitter
    // =========================================================================

    // Condition field for if/while/for/ternary
    condition_field: "condition",

    // Consequence/then branch
    consequence_field: "consequence",

    // Alternative/else branch
    alternative_field: "alternative",

    // Body field for methods, loops, classes
    body_field: "body",

    // Initializer/value for variable declarations
    initializer_field: "value",

    // Left operand in binary expressions
    left_field: "left",

    // Right operand in binary expressions
    right_field: "right",

    // Name field for declarations
    name_field: "name",

    // Arguments in method calls
    arguments_field: "arguments",

    // Value in assignments, returns
    value_field: "value",

    // Operator in expressions
    operator_field: "operator",

    // Object/receiver in member access
    object_field: "object",

    // Property/field being accessed
    property_field: "field",

    // Function being called (less common in Java, methods use "name")
    function_field: "name",

    // Parameters in method declarations
    parameters_field: "parameters",

    // Return type in method declarations
    return_type_field: "type",

    // Type annotations
    type_field: "type",

    // Exception handler in try-catch (catch_clause)
    handler_field: "handler",

    // Finally block in try-catch-finally
    finalizer_field: "finalizer",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_java_function_kinds() {
        assert!(JAVA_SEMANTICS.is_function_def("method_declaration"));
        assert!(JAVA_SEMANTICS.is_function_def("constructor_declaration"));
        assert!(JAVA_SEMANTICS.is_function_def("lambda_expression"));
        assert!(JAVA_SEMANTICS.is_function_def("compact_constructor_declaration"));
        assert!(!JAVA_SEMANTICS.is_function_def("method_invocation"));
    }

    #[test]
    fn test_java_loop_kinds() {
        assert!(JAVA_SEMANTICS.is_loop("for_statement"));
        assert!(JAVA_SEMANTICS.is_loop("enhanced_for_statement"));
        assert!(JAVA_SEMANTICS.is_loop("while_statement"));
        assert!(JAVA_SEMANTICS.is_loop("do_statement"));
        assert!(!JAVA_SEMANTICS.is_loop("if_statement"));
    }

    #[test]
    fn test_java_null() {
        assert!(JAVA_SEMANTICS.is_null_literal("null_literal"));
        assert!(!JAVA_SEMANTICS.is_null_literal("nil"));
    }

    #[test]
    fn test_java_try_catch() {
        assert!(JAVA_SEMANTICS.is_try_catch("try_statement"));
        assert!(JAVA_SEMANTICS.is_try_catch("try_with_resources_statement"));
        assert!(JAVA_SEMANTICS.is_throw("throw_statement"));
    }

    #[test]
    fn test_java_class_kinds() {
        assert!(JAVA_SEMANTICS.is_class("class_declaration"));
        assert!(JAVA_SEMANTICS.is_class("interface_declaration"));
        assert!(JAVA_SEMANTICS.is_class("enum_declaration"));
        assert!(JAVA_SEMANTICS.is_class("record_declaration"));
        assert!(JAVA_SEMANTICS.is_class("annotation_type_declaration"));
    }

    #[test]
    fn test_java_switch_kinds() {
        assert!(JAVA_SEMANTICS.is_switch("switch_expression"));
        assert!(JAVA_SEMANTICS.is_switch("switch_statement"));
        assert!(JAVA_SEMANTICS.is_case("switch_block_statement_group"));
        assert!(JAVA_SEMANTICS.is_case("switch_rule"));
    }

    #[test]
    fn test_java_literal_kinds() {
        // String literals
        assert!(JAVA_SEMANTICS.is_string_literal("string_literal"));
        assert!(JAVA_SEMANTICS.is_string_literal("text_block"));
        assert!(JAVA_SEMANTICS.is_string_literal("character_literal"));

        // Numeric literals
        assert!(JAVA_SEMANTICS.is_numeric_literal("decimal_integer_literal"));
        assert!(JAVA_SEMANTICS.is_numeric_literal("hex_integer_literal"));
        assert!(JAVA_SEMANTICS.is_numeric_literal("binary_integer_literal"));
        assert!(JAVA_SEMANTICS.is_numeric_literal("decimal_floating_point_literal"));

        // Boolean literals
        assert!(JAVA_SEMANTICS.is_boolean_literal("true"));
        assert!(JAVA_SEMANTICS.is_boolean_literal("false"));

        // Combined literal check
        assert!(JAVA_SEMANTICS.is_literal("string_literal"));
        assert!(JAVA_SEMANTICS.is_literal("decimal_integer_literal"));
        assert!(JAVA_SEMANTICS.is_literal("true"));
        assert!(JAVA_SEMANTICS.is_literal("null_literal"));
    }

    #[test]
    fn test_java_member_access() {
        assert!(JAVA_SEMANTICS.is_member_access("field_access"));
        assert!(JAVA_SEMANTICS.is_member_access("array_access"));
        assert!(JAVA_SEMANTICS.is_member_access("method_reference"));
    }

    #[test]
    fn test_java_call_kinds() {
        assert!(JAVA_SEMANTICS.is_call("method_invocation"));
        assert!(JAVA_SEMANTICS.is_call("object_creation_expression"));
        assert!(JAVA_SEMANTICS.is_call("explicit_constructor_invocation"));
    }

    #[test]
    fn test_java_control_flow() {
        assert!(JAVA_SEMANTICS.is_control_flow("if_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("for_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("while_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("switch_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("try_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("return_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("break_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("continue_statement"));
        assert!(JAVA_SEMANTICS.is_control_flow("throw_statement"));
    }

    #[test]
    fn test_java_no_unsafe_defer_spawn() {
        // Java doesn't have these constructs at the syntax level
        assert!(!JAVA_SEMANTICS.is_unsafe_block("unsafe_block"));
        assert!(!JAVA_SEMANTICS.is_defer("defer_statement"));
        assert!(!JAVA_SEMANTICS.is_spawn("go_statement"));
    }

    #[test]
    fn test_java_identifiers() {
        assert!(JAVA_SEMANTICS.is_identifier("identifier"));
        assert!(JAVA_SEMANTICS.is_identifier("type_identifier"));
    }

    #[test]
    fn test_java_block_scopes() {
        assert!(JAVA_SEMANTICS.is_block_scope("block"));
        assert!(JAVA_SEMANTICS.is_block_scope("static_initializer"));
        assert!(JAVA_SEMANTICS.is_block_scope("instance_initializer"));
    }
}
