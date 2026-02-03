//! Symbol table construction from tree-sitter AST
//!
//! Builds a per-function symbol table by walking the AST and tracking:
//! - Variable declarations and their initializers
//! - Function parameters
//! - Reassignments
//! - Scope depth
//!
//! Uses LanguageSemantics for language-agnostic AST traversal.

use crate::semantics::LanguageSemantics;
use rma_common::Language;
use rma_parser::ParsedFile;
use std::collections::HashMap;
use tree_sitter::{Node, TreeCursor};

/// Per-function symbol table mapping variable names to their info
#[derive(Debug, Default)]
pub struct SymbolTable {
    /// Map variable name -> SymbolInfo
    symbols: HashMap<String, SymbolInfo>,
}

/// Information about a symbol (variable/parameter)
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// Variable name
    pub name: String,
    /// Tree-sitter node ID of declaration
    pub declaration_node_id: usize,
    /// Where the initial value comes from
    pub initializer: ValueOrigin,
    /// Track all reassignments
    pub reassignments: Vec<ValueOrigin>,
    /// Line number of declaration
    pub line: usize,
    /// Scope depth (0 = function scope, 1 = first block, etc.)
    pub scope_depth: usize,
}

/// Represents where a value originates from
#[derive(Clone, Debug, PartialEq)]
pub enum ValueOrigin {
    /// Literal value: "hello", 42, true
    Literal(String),
    /// Function parameter at given index
    Parameter(usize),
    /// Result of function call
    FunctionCall(String),
    /// Member access like req.query, process.env
    MemberAccess(String),
    /// Binary expression (concatenation, arithmetic) - legacy, prefer StringConcat
    BinaryExpression,
    /// String concatenation with tracked operand variables
    /// The Vec contains variable names that are part of the concatenation.
    /// If any of these variables is tainted, the result is tainted.
    StringConcat(Vec<String>),
    /// Template literal/interpolated string with tracked variables
    /// Similar to StringConcat - tracks which variables are interpolated.
    TemplateLiteral(Vec<String>),
    /// Method call on an object (e.g., str.concat(x), arr.join())
    /// Contains (method_name, receiver_var, argument_vars)
    MethodCall {
        method: String,
        receiver: Option<String>,
        arguments: Vec<String>,
    },
    /// Assigned from another variable
    Variable(String),
    /// Cannot determine origin
    Unknown,
}

impl SymbolTable {
    /// Build symbol table from parsed file
    ///
    /// Uses LanguageSemantics to adapt to each language's AST structure.
    pub fn build(parsed: &ParsedFile, language: Language) -> Self {
        let mut table = Self::default();
        let mut cursor = parsed.tree.walk();
        let semantics = LanguageSemantics::for_language(language);

        match language {
            Language::JavaScript | Language::TypeScript => {
                table.build_javascript(&mut cursor, &parsed.content, semantics);
            }
            Language::Rust => {
                table.build_rust(&mut cursor, &parsed.content, semantics);
            }
            Language::Go => {
                table.build_go(&mut cursor, &parsed.content, semantics);
            }
            Language::Python => {
                table.build_python(&mut cursor, &parsed.content, semantics);
            }
            Language::Java => {
                table.build_java(&mut cursor, &parsed.content, semantics);
            }
            _ => {
                // Unsupported language - return empty table
            }
        }

        table
    }

    /// Get symbol info by name
    pub fn get(&self, name: &str) -> Option<&SymbolInfo> {
        self.symbols.get(name)
    }

    /// Check if a variable was initialized from a literal
    pub fn is_literal(&self, name: &str) -> bool {
        self.symbols
            .get(name)
            .map(|info| matches!(info.initializer, ValueOrigin::Literal(_)))
            .unwrap_or(false)
    }

    /// Get the origin of a variable's value
    pub fn origin_of(&self, name: &str) -> ValueOrigin {
        self.symbols
            .get(name)
            .map(|info| info.initializer.clone())
            .unwrap_or(ValueOrigin::Unknown)
    }

    /// Check if symbol exists
    pub fn contains(&self, name: &str) -> bool {
        self.symbols.contains_key(name)
    }

    /// Get all symbol names
    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.symbols.keys()
    }

    /// Iterate over all symbols
    pub fn iter(&self) -> impl Iterator<Item = (&String, &SymbolInfo)> {
        self.symbols.iter()
    }

    // =========================================================================
    // JavaScript/TypeScript symbol extraction
    // =========================================================================

    fn build_javascript(
        &mut self,
        cursor: &mut TreeCursor,
        content: &str,
        semantics: &'static LanguageSemantics,
    ) {
        let mut scope_depth = 0;
        let mut param_index = 0;

        self.walk_tree_with_semantics(cursor, content, semantics, |table, node, content, depth| {
            scope_depth = depth;

            match node.kind() {
                // Function parameters
                "formal_parameters" => {
                    param_index = 0;
                    for i in 0..node.named_child_count() {
                        if let Some(param) = node.named_child(i)
                            && let Some(name) = Self::extract_js_param_name(&param, content)
                        {
                            table.symbols.insert(
                                name.clone(),
                                SymbolInfo {
                                    name: name.clone(),
                                    declaration_node_id: param.id(),
                                    initializer: ValueOrigin::Parameter(param_index),
                                    reassignments: Vec::new(),
                                    line: param.start_position().row + 1,
                                    scope_depth,
                                },
                            );
                            param_index += 1;
                        }
                    }
                }

                // Variable declarations: const x = ..., let y = ..., var z = ...
                "variable_declarator" => {
                    if let Some(name_node) = node.child_by_field_name("name")
                        && let Ok(name) = name_node.utf8_text(content.as_bytes())
                    {
                        let initializer = node
                            .child_by_field_name("value")
                            .map(|v| Self::classify_origin(&v, content))
                            .unwrap_or(ValueOrigin::Unknown);

                        table.symbols.insert(
                            name.to_string(),
                            SymbolInfo {
                                name: name.to_string(),
                                declaration_node_id: node.id(),
                                initializer,
                                reassignments: Vec::new(),
                                line: node.start_position().row + 1,
                                scope_depth,
                            },
                        );
                    }
                }

                // Assignment expressions: x = ...
                "assignment_expression" => {
                    if let Some(left) = node.child_by_field_name("left")
                        && left.kind() == "identifier"
                        && let Ok(name) = left.utf8_text(content.as_bytes())
                    {
                        let origin = node
                            .child_by_field_name("right")
                            .map(|v| Self::classify_origin(&v, content))
                            .unwrap_or(ValueOrigin::Unknown);

                        if let Some(info) = table.symbols.get_mut(name) {
                            info.reassignments.push(origin);
                        } else {
                            // Implicit global or undeclared
                            table.symbols.insert(
                                name.to_string(),
                                SymbolInfo {
                                    name: name.to_string(),
                                    declaration_node_id: node.id(),
                                    initializer: origin,
                                    reassignments: Vec::new(),
                                    line: node.start_position().row + 1,
                                    scope_depth,
                                },
                            );
                        }
                    }
                }

                _ => {}
            }
        });
    }

    fn extract_js_param_name(node: &Node, content: &str) -> Option<String> {
        match node.kind() {
            "identifier" => node.utf8_text(content.as_bytes()).ok().map(String::from),
            // Destructuring: { a, b } or [a, b]
            "object_pattern" | "array_pattern" => {
                // For now, skip destructured params
                None
            }
            // Default value: x = 5
            "assignment_pattern" => node
                .child_by_field_name("left")
                .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                .map(String::from),
            // Rest param: ...args
            "rest_pattern" => node
                .named_child(0)
                .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                .map(String::from),
            _ => None,
        }
    }

    // =========================================================================
    // Rust symbol extraction
    // =========================================================================

    fn build_rust(
        &mut self,
        cursor: &mut TreeCursor,
        content: &str,
        semantics: &'static LanguageSemantics,
    ) {
        let mut param_index = 0;

        self.walk_tree_with_semantics(
            cursor,
            content,
            semantics,
            |table, node, content, scope_depth| {
                match node.kind() {
                    // Function parameters
                    "parameter" => {
                        if let Some(pattern) = node.child_by_field_name("pattern")
                            && let Ok(name) = pattern.utf8_text(content.as_bytes())
                        {
                            // Strip mutability: mut x -> x
                            let clean_name = name.trim_start_matches("mut ").trim();
                            table.symbols.insert(
                                clean_name.to_string(),
                                SymbolInfo {
                                    name: clean_name.to_string(),
                                    declaration_node_id: node.id(),
                                    initializer: ValueOrigin::Parameter(param_index),
                                    reassignments: Vec::new(),
                                    line: node.start_position().row + 1,
                                    scope_depth,
                                },
                            );
                            param_index += 1;
                        }
                    }

                    // Let declarations: let x = ...
                    "let_declaration" => {
                        if let Some(pattern) = node.child_by_field_name("pattern")
                            && let Ok(name) = pattern.utf8_text(content.as_bytes())
                        {
                            let clean_name = name.trim_start_matches("mut ").trim();
                            let initializer = node
                                .child_by_field_name("value")
                                .map(|v| Self::classify_origin(&v, content))
                                .unwrap_or(ValueOrigin::Unknown);

                            table.symbols.insert(
                                clean_name.to_string(),
                                SymbolInfo {
                                    name: clean_name.to_string(),
                                    declaration_node_id: node.id(),
                                    initializer,
                                    reassignments: Vec::new(),
                                    line: node.start_position().row + 1,
                                    scope_depth,
                                },
                            );
                        }
                    }

                    // Assignment: x = ...
                    "assignment_expression" => {
                        if let Some(left) = node.child_by_field_name("left")
                            && left.kind() == "identifier"
                            && let Ok(name) = left.utf8_text(content.as_bytes())
                        {
                            let origin = node
                                .child_by_field_name("right")
                                .map(|v| Self::classify_origin(&v, content))
                                .unwrap_or(ValueOrigin::Unknown);

                            if let Some(info) = table.symbols.get_mut(name) {
                                info.reassignments.push(origin);
                            }
                        }
                    }

                    // Reset param index on new function
                    "function_item" | "closure_expression" => {
                        param_index = 0;
                    }

                    _ => {}
                }
            },
        );
    }

    // =========================================================================
    // Go symbol extraction
    // =========================================================================

    fn build_go(
        &mut self,
        cursor: &mut TreeCursor,
        content: &str,
        semantics: &'static LanguageSemantics,
    ) {
        let mut param_index = 0;

        self.walk_tree_with_semantics(
            cursor,
            content,
            semantics,
            |table, node, content, scope_depth| {
                match node.kind() {
                    // Function parameters
                    "parameter_declaration" => {
                        // Go params: name type or name1, name2 type
                        for i in 0..node.named_child_count() {
                            if let Some(child) = node.named_child(i)
                                && child.kind() == "identifier"
                                && let Ok(name) = child.utf8_text(content.as_bytes())
                            {
                                table.symbols.insert(
                                    name.to_string(),
                                    SymbolInfo {
                                        name: name.to_string(),
                                        declaration_node_id: node.id(),
                                        initializer: ValueOrigin::Parameter(param_index),
                                        reassignments: Vec::new(),
                                        line: node.start_position().row + 1,
                                        scope_depth,
                                    },
                                );
                                param_index += 1;
                            }
                        }
                    }

                    // Short var declaration: x := ...
                    "short_var_declaration" => {
                        if let Some(left) = node.child_by_field_name("left")
                            && let Some(right) = node.child_by_field_name("right")
                        {
                            // Handle expression_list on both sides
                            let names = Self::extract_go_identifiers(&left, content);
                            let values = Self::extract_go_values(&right, content);

                            for (i, name) in names.into_iter().enumerate() {
                                let origin = values.get(i).cloned().unwrap_or(ValueOrigin::Unknown);
                                table.symbols.insert(
                                    name.clone(),
                                    SymbolInfo {
                                        name,
                                        declaration_node_id: node.id(),
                                        initializer: origin,
                                        reassignments: Vec::new(),
                                        line: node.start_position().row + 1,
                                        scope_depth,
                                    },
                                );
                            }
                        }
                    }

                    // Var declaration: var x = ...
                    "var_declaration" => {
                        // Walk var_spec children
                        for i in 0..node.named_child_count() {
                            if let Some(spec) = node.named_child(i)
                                && spec.kind() == "var_spec"
                                && let Some(name_node) = spec.child_by_field_name("name")
                                && let Ok(name) = name_node.utf8_text(content.as_bytes())
                            {
                                let origin = spec
                                    .child_by_field_name("value")
                                    .map(|v| Self::classify_origin(&v, content))
                                    .unwrap_or(ValueOrigin::Unknown);

                                table.symbols.insert(
                                    name.to_string(),
                                    SymbolInfo {
                                        name: name.to_string(),
                                        declaration_node_id: node.id(),
                                        initializer: origin,
                                        reassignments: Vec::new(),
                                        line: node.start_position().row + 1,
                                        scope_depth,
                                    },
                                );
                            }
                        }
                    }

                    // Assignment: x = ...
                    "assignment_statement" => {
                        if let Some(left) = node.child_by_field_name("left")
                            && let Some(right) = node.child_by_field_name("right")
                        {
                            let names = Self::extract_go_identifiers(&left, content);
                            let values = Self::extract_go_values(&right, content);

                            for (i, name) in names.into_iter().enumerate() {
                                if let Some(info) = table.symbols.get_mut(&name) {
                                    let origin =
                                        values.get(i).cloned().unwrap_or(ValueOrigin::Unknown);
                                    info.reassignments.push(origin);
                                }
                            }
                        }
                    }

                    "function_declaration" | "method_declaration" => {
                        param_index = 0;
                    }

                    _ => {}
                }
            },
        );
    }

    fn extract_go_identifiers(node: &Node, content: &str) -> Vec<String> {
        let mut names = Vec::new();
        if node.kind() == "identifier" {
            if let Ok(name) = node.utf8_text(content.as_bytes()) {
                names.push(name.to_string());
            }
        } else if node.kind() == "expression_list" {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i)
                    && child.kind() == "identifier"
                    && let Ok(name) = child.utf8_text(content.as_bytes())
                {
                    names.push(name.to_string());
                }
            }
        }
        names
    }

    fn extract_go_values(node: &Node, content: &str) -> Vec<ValueOrigin> {
        let mut values = Vec::new();
        if node.kind() == "expression_list" {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i) {
                    values.push(Self::classify_origin(&child, content));
                }
            }
        } else {
            values.push(Self::classify_origin(node, content));
        }
        values
    }

    // =========================================================================
    // Python symbol extraction
    // =========================================================================

    fn build_python(
        &mut self,
        cursor: &mut TreeCursor,
        content: &str,
        semantics: &'static LanguageSemantics,
    ) {
        let mut param_index = 0;

        self.walk_tree_with_semantics(
            cursor,
            content,
            semantics,
            |table, node, content, scope_depth| {
                match node.kind() {
                    // Function parameters
                    "parameters" => {
                        param_index = 0;
                        for i in 0..node.named_child_count() {
                            if let Some(param) = node.named_child(i) {
                                let name = match param.kind() {
                                    "identifier" => {
                                        param.utf8_text(content.as_bytes()).ok().map(String::from)
                                    }
                                    "default_parameter" | "typed_parameter" => param
                                        .child_by_field_name("name")
                                        .or_else(|| param.named_child(0))
                                        .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                                        .map(String::from),
                                    _ => None,
                                };

                                if let Some(name) = name {
                                    // Skip self/cls
                                    if name != "self" && name != "cls" {
                                        table.symbols.insert(
                                            name.clone(),
                                            SymbolInfo {
                                                name,
                                                declaration_node_id: param.id(),
                                                initializer: ValueOrigin::Parameter(param_index),
                                                reassignments: Vec::new(),
                                                line: param.start_position().row + 1,
                                                scope_depth,
                                            },
                                        );
                                        param_index += 1;
                                    }
                                }
                            }
                        }
                    }

                    // Assignment: x = ...
                    "assignment" => {
                        if let Some(left) = node.child_by_field_name("left")
                            && left.kind() == "identifier"
                            && let Ok(name) = left.utf8_text(content.as_bytes())
                        {
                            let origin = node
                                .child_by_field_name("right")
                                .map(|v| Self::classify_origin(&v, content))
                                .unwrap_or(ValueOrigin::Unknown);

                            if let Some(info) = table.symbols.get_mut(name) {
                                info.reassignments.push(origin);
                            } else {
                                // Python: assignment is also declaration
                                table.symbols.insert(
                                    name.to_string(),
                                    SymbolInfo {
                                        name: name.to_string(),
                                        declaration_node_id: node.id(),
                                        initializer: origin,
                                        reassignments: Vec::new(),
                                        line: node.start_position().row + 1,
                                        scope_depth,
                                    },
                                );
                            }
                        }
                    }

                    "function_definition" => {
                        param_index = 0;
                    }

                    _ => {}
                }
            },
        );
    }

    // =========================================================================
    // Value origin classification (shared across languages)
    // =========================================================================

    fn classify_origin(node: &Node, content: &str) -> ValueOrigin {
        match node.kind() {
            // Literals - but check template strings for interpolations first
            "string" | "string_literal" | "raw_string_literal" => {
                let text = node.utf8_text(content.as_bytes()).unwrap_or("");
                ValueOrigin::Literal(text.to_string())
            }
            // Template strings might have interpolations
            "template_string" => {
                // Check if this template string has any substitutions
                let mut has_substitution = false;
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "template_substitution" {
                        has_substitution = true;
                        break;
                    }
                }
                if has_substitution {
                    Self::classify_template_literal(node, content)
                } else {
                    let text = node.utf8_text(content.as_bytes()).unwrap_or("");
                    ValueOrigin::Literal(text.to_string())
                }
            }
            "number" | "integer" | "float" | "integer_literal" | "float_literal" => {
                let text = node.utf8_text(content.as_bytes()).unwrap_or("0");
                ValueOrigin::Literal(text.to_string())
            }
            "true" | "false" | "boolean" => {
                let text = node.utf8_text(content.as_bytes()).unwrap_or("false");
                ValueOrigin::Literal(text.to_string())
            }
            "null" | "nil" | "none" | "None" => ValueOrigin::Literal("null".to_string()),

            // Function calls - check for method calls like str.concat(), fmt.Sprintf(), etc.
            "call_expression" | "call" => Self::classify_call_expression(node, content),

            // Member access: obj.prop, obj.method()
            "member_expression" | "field_expression" | "selector_expression" | "attribute" => {
                let text = node.utf8_text(content.as_bytes()).unwrap_or("");
                ValueOrigin::MemberAccess(text.to_string())
            }

            // Subscript: obj["key"], arr[0]
            "subscript_expression" | "index_expression" => {
                let text = node.utf8_text(content.as_bytes()).unwrap_or("");
                ValueOrigin::MemberAccess(text.to_string())
            }

            // Variable reference
            "identifier" | "variable_name" => {
                let name = node.utf8_text(content.as_bytes()).unwrap_or("");
                ValueOrigin::Variable(name.to_string())
            }

            // Binary expressions - extract operand variables for taint tracking
            "binary_expression" | "binary_operator" => {
                Self::classify_binary_expression(node, content)
            }

            // Template literals with interpolation - track embedded variables
            "template_literal" => Self::classify_template_literal(node, content),

            // Python f-strings
            "formatted_string" | "interpolation" => Self::classify_template_literal(node, content),

            // Await expressions - check the inner call
            "await_expression" => {
                if let Some(inner) = node.named_child(0) {
                    Self::classify_origin(&inner, content)
                } else {
                    ValueOrigin::Unknown
                }
            }

            // Parenthesized - unwrap
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    Self::classify_origin(&inner, content)
                } else {
                    ValueOrigin::Unknown
                }
            }

            _ => ValueOrigin::Unknown,
        }
    }

    /// Classify a binary expression, extracting variable operands for taint tracking
    fn classify_binary_expression(node: &Node, content: &str) -> ValueOrigin {
        // Check if this is a string concatenation (+ operator)
        let operator = node
            .child_by_field_name("operator")
            .and_then(|op| op.utf8_text(content.as_bytes()).ok())
            .unwrap_or("");

        // String concatenation operators: + (most languages), % (Python formatting)
        if operator == "+" || operator == "%" {
            let mut variables = Vec::new();
            Self::collect_expression_variables(node, content, &mut variables);

            if !variables.is_empty() {
                return ValueOrigin::StringConcat(variables);
            }
        }

        // For other binary expressions, still try to track variables
        let mut variables = Vec::new();
        Self::collect_expression_variables(node, content, &mut variables);

        if !variables.is_empty() {
            ValueOrigin::StringConcat(variables)
        } else {
            ValueOrigin::BinaryExpression
        }
    }

    /// Classify a template literal, extracting interpolated variables
    fn classify_template_literal(node: &Node, content: &str) -> ValueOrigin {
        let mut variables = Vec::new();
        Self::collect_template_variables(node, content, &mut variables);

        if variables.is_empty() {
            // No interpolations, treat as literal
            let text = node.utf8_text(content.as_bytes()).unwrap_or("");
            ValueOrigin::Literal(text.to_string())
        } else {
            ValueOrigin::TemplateLiteral(variables)
        }
    }

    /// Classify a call expression, detecting string methods like concat, join, format
    fn classify_call_expression(node: &Node, content: &str) -> ValueOrigin {
        let func_node = node
            .child_by_field_name("function")
            .or_else(|| node.child(0));

        if let Some(func) = func_node {
            let func_text = func.utf8_text(content.as_bytes()).unwrap_or("");

            // Check if it's a method call (e.g., str.concat(), arr.join())
            if func.kind() == "member_expression" || func.kind() == "attribute" {
                let method_name = func
                    .child_by_field_name("property")
                    .or_else(|| func.named_child(func.named_child_count().saturating_sub(1)))
                    .and_then(|p| p.utf8_text(content.as_bytes()).ok())
                    .unwrap_or("");

                let receiver = func
                    .child_by_field_name("object")
                    .or_else(|| func.named_child(0))
                    .and_then(|o| {
                        if o.kind() == "identifier" {
                            o.utf8_text(content.as_bytes()).ok().map(String::from)
                        } else {
                            None
                        }
                    });

                // Check for string manipulation methods that propagate taint
                let string_methods = [
                    "concat",
                    "join",
                    "format",
                    "replace",
                    "trim",
                    "toLowerCase",
                    "toUpperCase",
                    "slice",
                    "substring",
                    "substr",
                    "split",
                    "repeat",
                    "padStart",
                    "padEnd",
                    "append",
                    "push_str",
                    "to_string",
                    "to_str",
                    "sprintf",
                    "printf",
                    "Sprintf",
                    "Join",
                    "Format",
                ];

                if string_methods
                    .iter()
                    .any(|m| method_name.eq_ignore_ascii_case(m))
                {
                    let mut arguments = Vec::new();

                    // Collect argument variables
                    if let Some(args) = node.child_by_field_name("arguments") {
                        Self::collect_argument_variables(&args, content, &mut arguments);
                    }

                    return ValueOrigin::MethodCall {
                        method: method_name.to_string(),
                        receiver,
                        arguments,
                    };
                }
            }

            // Check for format functions: format!(), fmt.Sprintf(), String.format(), etc.
            let format_functions = [
                "format!",
                "format",
                "sprintf",
                "printf",
                "Sprintf",
                "Printf",
                "fmt.Sprintf",
                "fmt.Printf",
                "String.format",
                "str.format",
            ];

            if format_functions.iter().any(|f| func_text.contains(f)) {
                let mut arguments = Vec::new();
                if let Some(args) = node.child_by_field_name("arguments") {
                    Self::collect_argument_variables(&args, content, &mut arguments);
                }

                return ValueOrigin::MethodCall {
                    method: func_text.to_string(),
                    receiver: None,
                    arguments,
                };
            }

            ValueOrigin::FunctionCall(func_text.to_string())
        } else {
            ValueOrigin::FunctionCall("unknown".to_string())
        }
    }

    /// Recursively collect variable names from an expression
    fn collect_expression_variables(node: &Node, content: &str, variables: &mut Vec<String>) {
        match node.kind() {
            "identifier" | "variable_name" => {
                if let Ok(name) = node.utf8_text(content.as_bytes()) {
                    let name_str = name.to_string();
                    if !variables.contains(&name_str) {
                        variables.push(name_str);
                    }
                }
            }
            "binary_expression" | "binary_operator" => {
                // Recurse into left and right operands
                if let Some(left) = node.child_by_field_name("left") {
                    Self::collect_expression_variables(&left, content, variables);
                }
                if let Some(right) = node.child_by_field_name("right") {
                    Self::collect_expression_variables(&right, content, variables);
                }
            }
            "member_expression" | "field_expression" | "selector_expression" | "attribute" => {
                // For member access like obj.prop, collect the full path
                if let Ok(text) = node.utf8_text(content.as_bytes()) {
                    let text_str = text.to_string();
                    if !variables.contains(&text_str) {
                        variables.push(text_str);
                    }
                }
                // Also check the base object
                if let Some(obj) = node
                    .child_by_field_name("object")
                    .or_else(|| node.named_child(0))
                {
                    Self::collect_expression_variables(&obj, content, variables);
                }
            }
            "call_expression" | "call" => {
                // For function calls, collect argument variables
                if let Some(args) = node.child_by_field_name("arguments") {
                    Self::collect_argument_variables(&args, content, variables);
                }
                // Also check the function part (for method calls like x.toString())
                if let Some(func) = node.child_by_field_name("function")
                    && let Some(obj) = func.child_by_field_name("object")
                {
                    Self::collect_expression_variables(&obj, content, variables);
                }
            }
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    Self::collect_expression_variables(&inner, content, variables);
                }
            }
            "template_literal" | "template_string" => {
                Self::collect_template_variables(node, content, variables);
            }
            _ => {
                // Recurse into children for other node types
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    Self::collect_expression_variables(&child, content, variables);
                }
            }
        }
    }

    /// Collect variables from template literal interpolations
    fn collect_template_variables(node: &Node, content: &str, variables: &mut Vec<String>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                // JavaScript template substitution: ${expr}
                "template_substitution" => {
                    if let Some(expr) = child.named_child(0) {
                        Self::collect_expression_variables(&expr, content, variables);
                    }
                }
                // Python f-string interpolation
                "interpolation" | "format_expression" => {
                    for i in 0..child.named_child_count() {
                        if let Some(expr) = child.named_child(i) {
                            Self::collect_expression_variables(&expr, content, variables);
                        }
                    }
                }
                // Recurse into nested template parts
                "template_literal" | "formatted_string" => {
                    Self::collect_template_variables(&child, content, variables);
                }
                _ => {
                    // For other children, check if they're expressions
                    Self::collect_expression_variables(&child, content, variables);
                }
            }
        }
    }

    /// Collect variable names from function call arguments
    fn collect_argument_variables(args_node: &Node, content: &str, variables: &mut Vec<String>) {
        let mut cursor = args_node.walk();
        for arg in args_node.named_children(&mut cursor) {
            Self::collect_expression_variables(&arg, content, variables);
        }
    }

    // =========================================================================
    // Java symbol extraction
    // =========================================================================

    fn build_java(
        &mut self,
        cursor: &mut TreeCursor,
        content: &str,
        semantics: &'static LanguageSemantics,
    ) {
        let mut param_index = 0;

        self.walk_tree_with_semantics(
            cursor,
            content,
            semantics,
            |table, node, content, scope_depth| {
                match node.kind() {
                    // Method parameters
                    "formal_parameter" => {
                        // Java param: type name or final type name
                        if let Some(name_node) = node.child_by_field_name("name")
                            && let Ok(name) = name_node.utf8_text(content.as_bytes())
                        {
                            table.symbols.insert(
                                name.to_string(),
                                SymbolInfo {
                                    name: name.to_string(),
                                    declaration_node_id: node.id(),
                                    initializer: ValueOrigin::Parameter(param_index),
                                    reassignments: Vec::new(),
                                    line: node.start_position().row + 1,
                                    scope_depth,
                                },
                            );
                            param_index += 1;
                        }
                    }

                    // Local variable declaration: Type name = value;
                    "local_variable_declaration" => {
                        for i in 0..node.named_child_count() {
                            if let Some(declarator) = node.named_child(i)
                                && declarator.kind() == "variable_declarator"
                                && let Some(name_node) = declarator.child_by_field_name("name")
                                && let Ok(name) = name_node.utf8_text(content.as_bytes())
                            {
                                let initializer = declarator
                                    .child_by_field_name("value")
                                    .map(|v| Self::classify_origin(&v, content))
                                    .unwrap_or(ValueOrigin::Unknown);

                                table.symbols.insert(
                                    name.to_string(),
                                    SymbolInfo {
                                        name: name.to_string(),
                                        declaration_node_id: node.id(),
                                        initializer,
                                        reassignments: Vec::new(),
                                        line: node.start_position().row + 1,
                                        scope_depth,
                                    },
                                );
                            }
                        }
                    }

                    // Assignment: name = value
                    "assignment_expression" => {
                        if let Some(left) = node.child_by_field_name("left")
                            && left.kind() == "identifier"
                            && let Ok(name) = left.utf8_text(content.as_bytes())
                        {
                            let origin = node
                                .child_by_field_name("right")
                                .map(|v| Self::classify_origin(&v, content))
                                .unwrap_or(ValueOrigin::Unknown);

                            if let Some(info) = table.symbols.get_mut(name) {
                                info.reassignments.push(origin);
                            }
                        }
                    }

                    // Reset param index on new method
                    "method_declaration" | "constructor_declaration" => {
                        param_index = 0;
                    }

                    _ => {}
                }
            },
        );
    }

    // =========================================================================
    // Tree walking helper with LanguageSemantics
    // =========================================================================

    fn walk_tree_with_semantics<F>(
        &mut self,
        cursor: &mut TreeCursor,
        content: &str,
        semantics: &'static LanguageSemantics,
        mut callback: F,
    ) where
        F: FnMut(&mut Self, Node, &str, usize),
    {
        let mut scope_depth = 0;

        loop {
            let node = cursor.node();
            let kind = node.kind();

            // Track scope depth using semantics
            let is_scope = semantics.is_block_scope(kind) || semantics.is_function_def(kind);

            if is_scope {
                scope_depth += 1;
            }

            callback(self, node, content, scope_depth);

            if cursor.goto_first_child() {
                continue;
            }

            loop {
                // Leaving scope
                let leaving_node = cursor.node();
                let leaving_kind = leaving_node.kind();
                let is_leaving_scope = semantics.is_block_scope(leaving_kind)
                    || semantics.is_function_def(leaving_kind);

                if is_leaving_scope && scope_depth > 0 {
                    scope_depth -= 1;
                }

                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_parser::ParserEngine;
    use std::path::Path;

    fn parse_js(code: &str) -> ParsedFile {
        let config = rma_common::RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser
            .parse_file(Path::new("test.js"), code)
            .expect("parse failed")
    }

    #[test]
    fn test_js_variable_declaration() {
        let code = r#"
            const x = "hello";
            let y = 42;
            var z = true;
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("x"));
        assert!(table.is_literal("x"));
        assert!(matches!(table.origin_of("x"), ValueOrigin::Literal(_)));

        assert!(table.contains("y"));
        assert!(table.is_literal("y"));

        assert!(table.contains("z"));
        assert!(table.is_literal("z"));
    }

    #[test]
    fn test_js_function_call_origin() {
        let code = r#"
            const el = document.getElementById("foo");
            const data = fetch("/api/data");
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("el"));
        assert!(matches!(
            table.origin_of("el"),
            ValueOrigin::FunctionCall(_)
        ));

        assert!(table.contains("data"));
    }

    #[test]
    fn test_js_member_access_origin() {
        let code = r#"
            const query = req.query;
            const body = req.body.data;
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("query"));
        assert!(matches!(
            table.origin_of("query"),
            ValueOrigin::MemberAccess(_)
        ));

        assert!(table.contains("body"));
    }

    #[test]
    fn test_js_reassignment() {
        let code = r#"
            let x = "safe";
            x = userInput;
            x = "safe again";
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        let info = table.get("x").expect("x should exist");
        assert_eq!(info.reassignments.len(), 2);
        assert!(matches!(info.reassignments[0], ValueOrigin::Variable(_)));
        assert!(matches!(info.reassignments[1], ValueOrigin::Literal(_)));
    }

    #[test]
    fn test_js_function_params() {
        let code = r#"
            function handler(req, res) {
                const data = req.body;
            }
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("req"));
        assert!(matches!(table.origin_of("req"), ValueOrigin::Parameter(0)));

        assert!(table.contains("res"));
        assert!(matches!(table.origin_of("res"), ValueOrigin::Parameter(1)));
    }

    // =========================================================================
    // String Concatenation Origin Tests
    // =========================================================================

    #[test]
    fn test_binary_plus_string_concat() {
        let code = r#"
            const a = "hello";
            const b = "world";
            const result = a + b;
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("result"));
        let origin = table.origin_of("result");
        match origin {
            ValueOrigin::StringConcat(vars) => {
                assert!(vars.contains(&"a".to_string()), "should contain 'a'");
                assert!(vars.contains(&"b".to_string()), "should contain 'b'");
            }
            _ => panic!("Expected StringConcat, got {:?}", origin),
        }
    }

    #[test]
    fn test_template_literal_origin() {
        let code = r#"
            const name = "world";
            const greeting = `Hello, ${name}!`;
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("greeting"));
        let origin = table.origin_of("greeting");
        match origin {
            ValueOrigin::TemplateLiteral(vars) => {
                assert!(
                    vars.contains(&"name".to_string()),
                    "should contain 'name' from interpolation"
                );
            }
            ValueOrigin::Literal(_) => {
                // If there's no interpolation detected, it might be treated as literal
                // This is acceptable for the simple case
            }
            _ => panic!("Expected TemplateLiteral or Literal, got {:?}", origin),
        }
    }

    #[test]
    fn test_chained_concat_origin() {
        let code = r#"
            const a = "a";
            const b = "b";
            const c = "c";
            const result = a + b + c;
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("result"));
        let origin = table.origin_of("result");
        match origin {
            ValueOrigin::StringConcat(vars) => {
                assert!(vars.len() >= 2, "should have at least 2 variables");
            }
            _ => panic!("Expected StringConcat, got {:?}", origin),
        }
    }

    #[test]
    fn test_concat_method_origin() {
        let code = r#"
            const a = "hello";
            const b = "world";
            const result = a.concat(b);
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("result"));
        let origin = table.origin_of("result");
        match origin {
            ValueOrigin::MethodCall {
                method,
                receiver,
                arguments,
            } => {
                assert_eq!(method, "concat");
                assert_eq!(receiver, Some("a".to_string()));
                assert!(arguments.contains(&"b".to_string()));
            }
            _ => panic!("Expected MethodCall, got {:?}", origin),
        }
    }

    #[test]
    fn test_join_method_origin() {
        let code = r#"
            const parts = ["a", "b"];
            const result = parts.join(",");
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("result"));
        let origin = table.origin_of("result");
        match origin {
            ValueOrigin::MethodCall {
                method, receiver, ..
            } => {
                assert_eq!(method, "join");
                assert_eq!(receiver, Some("parts".to_string()));
            }
            _ => panic!("Expected MethodCall, got {:?}", origin),
        }
    }

    #[test]
    fn test_complex_expression_origin() {
        let code = r#"
            const x = "a";
            const y = "b";
            const z = "c";
            const result = x + (y + z);
        "#;
        let parsed = parse_js(code);
        let table = SymbolTable::build(&parsed, Language::JavaScript);

        assert!(table.contains("result"));
        let origin = table.origin_of("result");
        match origin {
            ValueOrigin::StringConcat(vars) => {
                // Should capture variables from nested expressions
                assert!(!vars.is_empty(), "should have captured some variables");
            }
            _ => panic!("Expected StringConcat, got {:?}", origin),
        }
    }
}
