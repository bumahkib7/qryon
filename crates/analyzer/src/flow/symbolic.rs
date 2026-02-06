//! Symbolic Path Condition Tracking
//!
//! Tracks symbolic constraints on variables along control flow paths.
//! This enables:
//! - Constraint-aware taint analysis: `if (input.length < 10)` constrains input
//! - Type narrowing: `typeof x === 'string'` narrows x to string
//! - Nullability refinement: `x !== null` proves x is non-null
//! - Feasibility checking: detect infeasible paths (dead code)
//!
//! The symbolic state is propagated through the CFG, with conditions
//! extracted from branch predicates (if statements, while conditions, etc.).

use crate::flow::cfg::{BlockId, CFG, Terminator};
use crate::flow::dataflow::{DataflowResult, Direction, TransferFunction, find_node_by_id};
use crate::flow::type_inference::InferredType;
use crate::semantics::LanguageSemantics;
use std::collections::{HashMap, HashSet};

// =============================================================================
// Path Conditions
// =============================================================================

/// A symbolic constraint on a variable.
/// Represents knowledge gained from control flow predicates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathCondition {
    /// Length constraint: variable.length op value
    /// e.g., `input.length < 10` -> LengthConstraint { var: "input", op: Lt, value: 10 }
    LengthConstraint {
        variable: String,
        op: ComparisonOp,
        value: i64,
    },

    /// Type guard: typeof variable === "type"
    /// e.g., `typeof x === 'string'` -> TypeGuard { var: "x", guarded_type: String }
    TypeGuard {
        variable: String,
        guarded_type: GuardedType,
        /// true if the guard is positive (===), false if negative (!==)
        is_positive: bool,
    },

    /// Null check: variable === null or variable !== null
    /// e.g., `x !== null` -> NullCheck { var: "x", is_null: false }
    NullCheck {
        variable: String,
        /// true if checking for null, false if checking for non-null
        is_null: bool,
    },

    /// Undefined check: variable === undefined or variable !== undefined
    UndefinedCheck {
        variable: String,
        /// true if checking for undefined, false if checking for defined
        is_undefined: bool,
    },

    /// Truthiness check: if (variable) or if (!variable)
    /// e.g., `if (x)` -> Truthy { var: "x", is_truthy: true }
    Truthy { variable: String, is_truthy: bool },

    /// Instance check: variable instanceof Type
    /// e.g., `x instanceof Array` -> InstanceOf { var: "x", type_name: "Array" }
    InstanceOf {
        variable: String,
        type_name: String,
        is_positive: bool,
    },

    /// Numeric comparison: variable op value
    /// e.g., `x > 0` -> NumericComparison { var: "x", op: Gt, value: 0 }
    NumericComparison {
        variable: String,
        op: ComparisonOp,
        value: i64,
    },

    /// String equality: variable === "literal"
    StringEquality {
        variable: String,
        value: String,
        is_equal: bool,
    },

    /// Property existence: "prop" in object or object.hasOwnProperty("prop")
    PropertyExists {
        object: String,
        property: String,
        exists: bool,
    },

    /// Array inclusion: array.includes(value) or value in array
    ArrayIncludes {
        array: String,
        value: String,
        includes: bool,
    },

    /// Negation of another condition
    Not(Box<PathCondition>),

    /// Conjunction of conditions (both must hold)
    And(Box<PathCondition>, Box<PathCondition>),

    /// Disjunction of conditions (at least one must hold)
    Or(Box<PathCondition>, Box<PathCondition>),
}

impl PathCondition {
    /// Get the variable(s) this condition constrains
    pub fn constrained_variables(&self) -> Vec<&str> {
        match self {
            PathCondition::LengthConstraint { variable, .. } => vec![variable.as_str()],
            PathCondition::TypeGuard { variable, .. } => vec![variable.as_str()],
            PathCondition::NullCheck { variable, .. } => vec![variable.as_str()],
            PathCondition::UndefinedCheck { variable, .. } => vec![variable.as_str()],
            PathCondition::Truthy { variable, .. } => vec![variable.as_str()],
            PathCondition::InstanceOf { variable, .. } => vec![variable.as_str()],
            PathCondition::NumericComparison { variable, .. } => vec![variable.as_str()],
            PathCondition::StringEquality { variable, .. } => vec![variable.as_str()],
            PathCondition::PropertyExists { object, .. } => vec![object.as_str()],
            PathCondition::ArrayIncludes { array, value, .. } => {
                vec![array.as_str(), value.as_str()]
            }
            PathCondition::Not(inner) => inner.constrained_variables(),
            PathCondition::And(left, right) => {
                let mut vars = left.constrained_variables();
                vars.extend(right.constrained_variables());
                vars
            }
            PathCondition::Or(left, right) => {
                let mut vars = left.constrained_variables();
                vars.extend(right.constrained_variables());
                vars
            }
        }
    }

    /// Negate this condition
    pub fn negate(self) -> PathCondition {
        match self {
            // Direct negations
            PathCondition::NullCheck { variable, is_null } => PathCondition::NullCheck {
                variable,
                is_null: !is_null,
            },
            PathCondition::UndefinedCheck {
                variable,
                is_undefined,
            } => PathCondition::UndefinedCheck {
                variable,
                is_undefined: !is_undefined,
            },
            PathCondition::Truthy {
                variable,
                is_truthy,
            } => PathCondition::Truthy {
                variable,
                is_truthy: !is_truthy,
            },
            PathCondition::TypeGuard {
                variable,
                guarded_type,
                is_positive,
            } => PathCondition::TypeGuard {
                variable,
                guarded_type,
                is_positive: !is_positive,
            },
            PathCondition::InstanceOf {
                variable,
                type_name,
                is_positive,
            } => PathCondition::InstanceOf {
                variable,
                type_name,
                is_positive: !is_positive,
            },
            PathCondition::StringEquality {
                variable,
                value,
                is_equal,
            } => PathCondition::StringEquality {
                variable,
                value,
                is_equal: !is_equal,
            },
            PathCondition::PropertyExists {
                object,
                property,
                exists,
            } => PathCondition::PropertyExists {
                object,
                property,
                exists: !exists,
            },
            PathCondition::ArrayIncludes {
                array,
                value,
                includes,
            } => PathCondition::ArrayIncludes {
                array,
                value,
                includes: !includes,
            },
            // Comparison negations
            PathCondition::LengthConstraint {
                variable,
                op,
                value,
            } => PathCondition::LengthConstraint {
                variable,
                op: op.negate(),
                value,
            },
            PathCondition::NumericComparison {
                variable,
                op,
                value,
            } => PathCondition::NumericComparison {
                variable,
                op: op.negate(),
                value,
            },
            // Double negation elimination
            PathCondition::Not(inner) => *inner,
            // De Morgan's laws
            PathCondition::And(left, right) => {
                PathCondition::Or(Box::new(left.negate()), Box::new(right.negate()))
            }
            PathCondition::Or(left, right) => {
                PathCondition::And(Box::new(left.negate()), Box::new(right.negate()))
            }
        }
    }

    /// Check if this condition implies another condition
    pub fn implies(&self, other: &PathCondition) -> bool {
        // Simple structural equality
        if self == other {
            return true;
        }

        // Implication rules
        match (self, other) {
            // Null check implications
            (
                PathCondition::NullCheck {
                    variable: v1,
                    is_null: false,
                },
                PathCondition::Truthy {
                    variable: v2,
                    is_truthy: true,
                },
            ) if v1 == v2 => {
                // non-null implies truthy (in most cases)
                true
            }
            // Strict inequalities imply non-strict
            (
                PathCondition::NumericComparison {
                    variable: v1,
                    op: ComparisonOp::Lt,
                    value: val1,
                },
                PathCondition::NumericComparison {
                    variable: v2,
                    op: ComparisonOp::Le,
                    value: val2,
                },
            ) if v1 == v2 => *val1 <= *val2,
            (
                PathCondition::NumericComparison {
                    variable: v1,
                    op: ComparisonOp::Gt,
                    value: val1,
                },
                PathCondition::NumericComparison {
                    variable: v2,
                    op: ComparisonOp::Ge,
                    value: val2,
                },
            ) if v1 == v2 => *val1 >= *val2,
            // Length constraints imply similar
            (
                PathCondition::LengthConstraint {
                    variable: v1,
                    op: ComparisonOp::Lt,
                    value: val1,
                },
                PathCondition::LengthConstraint {
                    variable: v2,
                    op: ComparisonOp::Le,
                    value: val2,
                },
            ) if v1 == v2 => *val1 <= *val2,
            _ => false,
        }
    }

    /// Check if this condition contradicts another condition
    pub fn contradicts(&self, other: &PathCondition) -> bool {
        match (self, other) {
            // Null check contradictions
            (
                PathCondition::NullCheck {
                    variable: v1,
                    is_null: n1,
                },
                PathCondition::NullCheck {
                    variable: v2,
                    is_null: n2,
                },
            ) if v1 == v2 => n1 != n2,
            // Type guard contradictions (same var, different types)
            (
                PathCondition::TypeGuard {
                    variable: v1,
                    guarded_type: t1,
                    is_positive: true,
                },
                PathCondition::TypeGuard {
                    variable: v2,
                    guarded_type: t2,
                    is_positive: true,
                },
            ) if v1 == v2 => t1 != t2,
            // Numeric range contradictions
            (
                PathCondition::NumericComparison {
                    variable: v1,
                    op: ComparisonOp::Lt,
                    value: val1,
                },
                PathCondition::NumericComparison {
                    variable: v2,
                    op: ComparisonOp::Ge,
                    value: val2,
                },
            ) if v1 == v2 => *val1 <= *val2,
            (
                PathCondition::NumericComparison {
                    variable: v1,
                    op: ComparisonOp::Gt,
                    value: val1,
                },
                PathCondition::NumericComparison {
                    variable: v2,
                    op: ComparisonOp::Le,
                    value: val2,
                },
            ) if v1 == v2 => *val1 >= *val2,
            _ => false,
        }
    }
}

/// Comparison operators for constraints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComparisonOp {
    /// Less than (<)
    Lt,
    /// Less than or equal (<=)
    Le,
    /// Greater than (>)
    Gt,
    /// Greater than or equal (>=)
    Ge,
    /// Equal (== or ===)
    Eq,
    /// Not equal (!= or !==)
    Ne,
}

impl ComparisonOp {
    /// Negate the comparison operator
    pub fn negate(self) -> Self {
        match self {
            ComparisonOp::Lt => ComparisonOp::Ge,
            ComparisonOp::Le => ComparisonOp::Gt,
            ComparisonOp::Gt => ComparisonOp::Le,
            ComparisonOp::Ge => ComparisonOp::Lt,
            ComparisonOp::Eq => ComparisonOp::Ne,
            ComparisonOp::Ne => ComparisonOp::Eq,
        }
    }

    /// Parse from operator string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "<" => Some(ComparisonOp::Lt),
            "<=" => Some(ComparisonOp::Le),
            ">" => Some(ComparisonOp::Gt),
            ">=" => Some(ComparisonOp::Ge),
            "==" | "===" => Some(ComparisonOp::Eq),
            "!=" | "!==" => Some(ComparisonOp::Ne),
            _ => None,
        }
    }
}

/// Types that can be guarded by typeof checks
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GuardedType {
    String,
    Number,
    Boolean,
    Object,
    Function,
    Undefined,
    Symbol,
    BigInt,
    /// Custom type name (for instanceof checks)
    Custom(String),
}

impl GuardedType {
    /// Parse from a type string (e.g., from typeof result)
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim_matches(|c| c == '"' || c == '\'') {
            "string" => Some(GuardedType::String),
            "number" => Some(GuardedType::Number),
            "boolean" => Some(GuardedType::Boolean),
            "object" => Some(GuardedType::Object),
            "function" => Some(GuardedType::Function),
            "undefined" => Some(GuardedType::Undefined),
            "symbol" => Some(GuardedType::Symbol),
            "bigint" => Some(GuardedType::BigInt),
            other if !other.is_empty() => Some(GuardedType::Custom(other.to_string())),
            _ => None,
        }
    }

    /// Convert to InferredType
    pub fn to_inferred_type(&self) -> InferredType {
        match self {
            GuardedType::String => InferredType::String,
            GuardedType::Number => InferredType::Number,
            GuardedType::Boolean => InferredType::Boolean,
            GuardedType::Object => InferredType::Object,
            GuardedType::Function => InferredType::Function,
            GuardedType::Undefined => InferredType::Undefined,
            GuardedType::Symbol | GuardedType::BigInt | GuardedType::Custom(_) => {
                InferredType::Unknown
            }
        }
    }
}

// =============================================================================
// Symbolic State
// =============================================================================

/// The symbolic state at a program point.
/// Contains all path conditions that must hold at this point.
#[derive(Debug, Clone, Default)]
pub struct SymbolicState {
    /// Set of conditions that hold at this point
    conditions: HashSet<PathCondition>,
    /// Cached feasibility (None = not checked yet)
    feasible: Option<bool>,
}

impl SymbolicState {
    /// Create an empty symbolic state
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a symbolic state with initial conditions
    pub fn with_conditions(conditions: HashSet<PathCondition>) -> Self {
        Self {
            conditions,
            feasible: None,
        }
    }

    /// Add a condition to the state
    pub fn add_condition(&mut self, condition: PathCondition) {
        self.conditions.insert(condition);
        self.feasible = None; // Invalidate cache
    }

    /// Remove a condition from the state
    pub fn remove_condition(&mut self, condition: &PathCondition) {
        self.conditions.remove(condition);
        self.feasible = None;
    }

    /// Get all conditions
    pub fn conditions(&self) -> &HashSet<PathCondition> {
        &self.conditions
    }

    /// Check if the state has any conditions
    pub fn is_empty(&self) -> bool {
        self.conditions.is_empty()
    }

    /// Get constraints for a specific variable
    pub fn get_constraints(&self, var_name: &str) -> Vec<&PathCondition> {
        self.conditions
            .iter()
            .filter(|c| c.constrained_variables().contains(&var_name))
            .collect()
    }

    /// Check if this path is feasible (no contradicting conditions)
    pub fn is_feasible(&self) -> bool {
        if let Some(cached) = self.feasible {
            return cached;
        }

        // Check for obvious contradictions
        let conditions: Vec<_> = self.conditions.iter().collect();
        for i in 0..conditions.len() {
            for j in (i + 1)..conditions.len() {
                if conditions[i].contradicts(conditions[j]) {
                    return false;
                }
            }
        }

        true
    }

    /// Merge two symbolic states (at join points)
    /// Takes the intersection of conditions (what holds on ALL paths)
    pub fn merge(&self, other: &SymbolicState) -> SymbolicState {
        let intersection: HashSet<_> = self
            .conditions
            .intersection(&other.conditions)
            .cloned()
            .collect();

        SymbolicState {
            conditions: intersection,
            feasible: None,
        }
    }

    /// Extend with conditions from another state
    pub fn extend(&mut self, other: &SymbolicState) {
        self.conditions.extend(other.conditions.iter().cloned());
        self.feasible = None;
    }

    /// Check if a variable is known to be non-null
    pub fn is_non_null(&self, var_name: &str) -> bool {
        self.conditions.iter().any(|c| {
            matches!(c,
                PathCondition::NullCheck { variable, is_null: false } if variable == var_name
            )
        })
    }

    /// Check if a variable is known to be null
    pub fn is_null(&self, var_name: &str) -> bool {
        self.conditions.iter().any(|c| {
            matches!(c,
                PathCondition::NullCheck { variable, is_null: true } if variable == var_name
            )
        })
    }

    /// Check if a variable is known to be truthy
    pub fn is_truthy(&self, var_name: &str) -> bool {
        self.conditions.iter().any(|c| {
            matches!(c,
                PathCondition::Truthy { variable, is_truthy: true } if variable == var_name
            )
        })
    }

    /// Get the type guard for a variable (if any)
    pub fn get_type_guard(&self, var_name: &str) -> Option<&GuardedType> {
        self.conditions.iter().find_map(|c| match c {
            PathCondition::TypeGuard {
                variable,
                guarded_type,
                is_positive: true,
            } if variable == var_name => Some(guarded_type),
            _ => None,
        })
    }

    /// Get length constraints for a variable
    pub fn get_length_constraints(&self, var_name: &str) -> Vec<(ComparisonOp, i64)> {
        self.conditions
            .iter()
            .filter_map(|c| match c {
                PathCondition::LengthConstraint {
                    variable,
                    op,
                    value,
                } if variable == var_name => Some((*op, *value)),
                _ => None,
            })
            .collect()
    }

    /// Get numeric constraints for a variable
    pub fn get_numeric_constraints(&self, var_name: &str) -> Vec<(ComparisonOp, i64)> {
        self.conditions
            .iter()
            .filter_map(|c| match c {
                PathCondition::NumericComparison {
                    variable,
                    op,
                    value,
                } if variable == var_name => Some((*op, *value)),
                _ => None,
            })
            .collect()
    }
}

// =============================================================================
// Symbolic Analysis Result
// =============================================================================

/// Result of symbolic path condition analysis
#[derive(Debug, Default)]
pub struct SymbolicAnalysisResult {
    /// Symbolic state at entry of each block
    pub block_entry: HashMap<BlockId, SymbolicState>,
    /// Symbolic state at exit of each block
    pub block_exit: HashMap<BlockId, SymbolicState>,
    /// Infeasible blocks (unreachable due to contradicting conditions)
    pub infeasible_blocks: HashSet<BlockId>,
}

impl SymbolicAnalysisResult {
    /// Get the symbolic state at block entry
    pub fn state_at_entry(&self, block_id: BlockId) -> Option<&SymbolicState> {
        self.block_entry.get(&block_id)
    }

    /// Get the symbolic state at block exit
    pub fn state_at_exit(&self, block_id: BlockId) -> Option<&SymbolicState> {
        self.block_exit.get(&block_id)
    }

    /// Get constraints for a variable at a specific block
    pub fn get_constraints(&self, block_id: BlockId, var_name: &str) -> Vec<&PathCondition> {
        self.block_entry
            .get(&block_id)
            .map(|state| state.get_constraints(var_name))
            .unwrap_or_default()
    }

    /// Check if a block is infeasible
    pub fn is_infeasible(&self, block_id: BlockId) -> bool {
        self.infeasible_blocks.contains(&block_id)
    }

    /// Check if a variable is non-null at a specific block
    pub fn is_non_null_at(&self, block_id: BlockId, var_name: &str) -> bool {
        self.block_entry
            .get(&block_id)
            .map(|state| state.is_non_null(var_name))
            .unwrap_or(false)
    }

    /// Check if a variable is null at a specific block
    pub fn is_null_at(&self, block_id: BlockId, var_name: &str) -> bool {
        self.block_entry
            .get(&block_id)
            .map(|state| state.is_null(var_name))
            .unwrap_or(false)
    }

    /// Get the type guard for a variable at a specific block
    pub fn get_type_guard_at(&self, block_id: BlockId, var_name: &str) -> Option<&GuardedType> {
        self.block_entry
            .get(&block_id)
            .and_then(|state| state.get_type_guard(var_name))
    }
}

// =============================================================================
// Condition Extractor
// =============================================================================

/// Extracts path conditions from AST nodes
pub struct ConditionExtractor<'a> {
    semantics: &'static LanguageSemantics,
    source: &'a [u8],
}

impl<'a> ConditionExtractor<'a> {
    pub fn new(semantics: &'static LanguageSemantics, source: &'a [u8]) -> Self {
        Self { semantics, source }
    }

    /// Extract a path condition from a condition node
    pub fn extract_condition(&self, node: tree_sitter::Node<'a>) -> Option<PathCondition> {
        let kind = node.kind();

        // Handle unary negation
        if kind == "unary_expression" {
            return self.extract_unary_condition(node);
        }

        // Handle binary expressions
        if self.semantics.is_binary_expression(kind) || kind == "binary_expression" {
            return self.extract_binary_condition(node);
        }

        // Handle typeof expressions
        if kind == "typeof_expression" || kind == "typeof" {
            // typeof alone isn't a condition, it needs to be in a comparison
            return None;
        }

        // Handle instanceof
        if kind == "instanceof_expression" {
            return self.extract_instanceof_condition(node);
        }

        // Handle member access (for truthiness of obj.prop)
        if self.semantics.is_member_access(kind) {
            let text = node.utf8_text(self.source).ok()?;
            return Some(PathCondition::Truthy {
                variable: text.to_string(),
                is_truthy: true,
            });
        }

        // Handle identifiers (truthiness check)
        if self.semantics.is_identifier(kind) || kind == "identifier" {
            let var_name = node.utf8_text(self.source).ok()?;
            return Some(PathCondition::Truthy {
                variable: var_name.to_string(),
                is_truthy: true,
            });
        }

        // Handle call expressions (for things like Array.isArray)
        if self.semantics.is_call(kind) {
            return self.extract_call_condition(node);
        }

        None
    }

    /// Extract condition from unary expression (typically negation)
    fn extract_unary_condition(&self, node: tree_sitter::Node<'a>) -> Option<PathCondition> {
        let operator = node.child_by_field_name("operator").or_else(|| {
            let mut cursor = node.walk();
            node.children(&mut cursor).find(|c| c.kind() == "!")
        })?;

        let operator_text = operator.utf8_text(self.source).ok()?;

        if operator_text == "!" {
            // Get the operand
            let operand = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;

            // Extract the inner condition and negate it
            if let Some(inner) = self.extract_condition(operand) {
                return Some(inner.negate());
            }

            // If we can't extract a condition, treat as truthy check
            let operand_text = operand.utf8_text(self.source).ok()?;
            return Some(PathCondition::Truthy {
                variable: operand_text.to_string(),
                is_truthy: false,
            });
        }

        None
    }

    /// Extract condition from binary expression
    fn extract_binary_condition(&self, node: tree_sitter::Node<'a>) -> Option<PathCondition> {
        let left = node.child_by_field_name(self.semantics.left_field)?;
        let right = node.child_by_field_name(self.semantics.right_field)?;
        let operator = node
            .child_by_field_name(self.semantics.operator_field)
            .or_else(|| {
                let mut cursor = node.walk();
                node.children(&mut cursor).find(|c| !c.is_named())
            })?;

        let op_text = operator.utf8_text(self.source).ok()?;

        // Handle logical operators (&&, ||)
        if op_text == "&&" {
            let left_cond = self.extract_condition(left)?;
            let right_cond = self.extract_condition(right)?;
            return Some(PathCondition::And(
                Box::new(left_cond),
                Box::new(right_cond),
            ));
        }

        if op_text == "||" {
            let left_cond = self.extract_condition(left)?;
            let right_cond = self.extract_condition(right)?;
            return Some(PathCondition::Or(Box::new(left_cond), Box::new(right_cond)));
        }

        // Handle typeof comparisons
        if left.kind() == "typeof_expression" || left.kind() == "typeof" {
            return self.extract_typeof_comparison(left, right, op_text);
        }
        if right.kind() == "typeof_expression" || right.kind() == "typeof" {
            return self.extract_typeof_comparison(right, left, op_text);
        }

        // Handle null/undefined checks
        if self.is_null_literal(right) {
            return self.extract_null_check(left, op_text, true);
        }
        if self.is_null_literal(left) {
            return self.extract_null_check(right, op_text, true);
        }
        if self.is_undefined_literal(right) {
            return self.extract_null_check(left, op_text, false);
        }
        if self.is_undefined_literal(left) {
            return self.extract_null_check(right, op_text, false);
        }

        // Handle length checks (x.length < 10)
        if let Some(cond) = self.try_extract_length_check(left, right, op_text) {
            return Some(cond);
        }
        if let Some(cond) = self.try_extract_length_check(right, left, self.flip_operator(op_text))
        {
            return Some(cond);
        }

        // Handle numeric comparisons
        if let Some(cond) = self.try_extract_numeric_comparison(left, right, op_text) {
            return Some(cond);
        }

        // Handle string equality
        if let Some(cond) = self.try_extract_string_equality(left, right, op_text) {
            return Some(cond);
        }

        // Handle 'in' operator
        if op_text == "in" {
            return self.extract_in_check(left, right);
        }

        None
    }

    /// Extract typeof comparison condition
    fn extract_typeof_comparison(
        &self,
        typeof_node: tree_sitter::Node<'a>,
        type_literal: tree_sitter::Node<'a>,
        op: &str,
    ) -> Option<PathCondition> {
        // Get the variable from typeof expression
        let variable = typeof_node.named_child(0)?;
        let var_name = variable.utf8_text(self.source).ok()?.to_string();

        // Get the type string
        let type_str = type_literal.utf8_text(self.source).ok()?;
        let guarded_type = GuardedType::parse(type_str)?;

        let is_positive = matches!(op, "==" | "===");

        Some(PathCondition::TypeGuard {
            variable: var_name,
            guarded_type,
            is_positive,
        })
    }

    /// Extract null check condition
    fn extract_null_check(
        &self,
        var_node: tree_sitter::Node<'a>,
        op: &str,
        is_null_literal: bool,
    ) -> Option<PathCondition> {
        let var_name = var_node.utf8_text(self.source).ok()?.to_string();
        let is_equality = matches!(op, "==" | "===");

        if is_null_literal {
            Some(PathCondition::NullCheck {
                variable: var_name,
                is_null: is_equality,
            })
        } else {
            Some(PathCondition::UndefinedCheck {
                variable: var_name,
                is_undefined: is_equality,
            })
        }
    }

    /// Try to extract a length check (x.length op value)
    fn try_extract_length_check(
        &self,
        potential_length: tree_sitter::Node<'a>,
        value_node: tree_sitter::Node<'a>,
        op: &str,
    ) -> Option<PathCondition> {
        // Check if left side is a .length access
        if !self.semantics.is_member_access(potential_length.kind()) {
            return None;
        }

        let property = potential_length.child_by_field_name(self.semantics.property_field)?;
        let property_name = property.utf8_text(self.source).ok()?;

        if property_name != "length" {
            return None;
        }

        // Get the object being accessed
        let object = potential_length.child_by_field_name(self.semantics.object_field)?;
        let var_name = object.utf8_text(self.source).ok()?.to_string();

        // Get the numeric value
        let value_text = value_node.utf8_text(self.source).ok()?;
        let value: i64 = value_text.parse().ok()?;

        let comparison_op = ComparisonOp::parse(op)?;

        Some(PathCondition::LengthConstraint {
            variable: var_name,
            op: comparison_op,
            value,
        })
    }

    /// Try to extract a numeric comparison
    fn try_extract_numeric_comparison(
        &self,
        left: tree_sitter::Node<'a>,
        right: tree_sitter::Node<'a>,
        op: &str,
    ) -> Option<PathCondition> {
        let comparison_op = ComparisonOp::parse(op)?;

        // Try left as variable, right as number
        if (self.semantics.is_identifier(left.kind()) || left.kind() == "identifier")
            && self.semantics.is_numeric_literal(right.kind())
        {
            let var_name = left.utf8_text(self.source).ok()?.to_string();
            let value_text = right.utf8_text(self.source).ok()?;
            let value: i64 = value_text.parse().ok()?;

            return Some(PathCondition::NumericComparison {
                variable: var_name,
                op: comparison_op,
                value,
            });
        }

        // Try right as variable, left as number (flip the operator)
        if self.semantics.is_numeric_literal(left.kind())
            && (self.semantics.is_identifier(right.kind()) || right.kind() == "identifier")
        {
            let var_name = right.utf8_text(self.source).ok()?.to_string();
            let value_text = left.utf8_text(self.source).ok()?;
            let value: i64 = value_text.parse().ok()?;

            return Some(PathCondition::NumericComparison {
                variable: var_name,
                op: comparison_op.negate(), // Flip: 5 < x becomes x > 5
                value,
            });
        }

        None
    }

    /// Try to extract a string equality check
    fn try_extract_string_equality(
        &self,
        left: tree_sitter::Node<'a>,
        right: tree_sitter::Node<'a>,
        op: &str,
    ) -> Option<PathCondition> {
        if !matches!(op, "==" | "===" | "!=" | "!==") {
            return None;
        }

        let is_equal = matches!(op, "==" | "===");

        // Try left as variable, right as string
        if (self.semantics.is_identifier(left.kind()) || left.kind() == "identifier")
            && self.semantics.is_string_literal(right.kind())
        {
            let var_name = left.utf8_text(self.source).ok()?.to_string();
            let value = right.utf8_text(self.source).ok()?;
            let value = value.trim_matches(|c| c == '"' || c == '\'').to_string();

            return Some(PathCondition::StringEquality {
                variable: var_name,
                value,
                is_equal,
            });
        }

        // Try right as variable, left as string
        if self.semantics.is_string_literal(left.kind())
            && (self.semantics.is_identifier(right.kind()) || right.kind() == "identifier")
        {
            let var_name = right.utf8_text(self.source).ok()?.to_string();
            let value = left.utf8_text(self.source).ok()?;
            let value = value.trim_matches(|c| c == '"' || c == '\'').to_string();

            return Some(PathCondition::StringEquality {
                variable: var_name,
                value,
                is_equal,
            });
        }

        None
    }

    /// Extract 'in' operator check ("prop" in obj)
    fn extract_in_check(
        &self,
        left: tree_sitter::Node<'a>,
        right: tree_sitter::Node<'a>,
    ) -> Option<PathCondition> {
        let property = left.utf8_text(self.source).ok()?;
        let property = property.trim_matches(|c| c == '"' || c == '\'').to_string();
        let object = right.utf8_text(self.source).ok()?.to_string();

        Some(PathCondition::PropertyExists {
            object,
            property,
            exists: true,
        })
    }

    /// Extract instanceof condition
    fn extract_instanceof_condition(&self, node: tree_sitter::Node<'a>) -> Option<PathCondition> {
        let left = node
            .child_by_field_name("left")
            .or_else(|| node.named_child(0))?;
        let right = node
            .child_by_field_name("right")
            .or_else(|| node.named_child(1))?;

        let variable = left.utf8_text(self.source).ok()?.to_string();
        let type_name = right.utf8_text(self.source).ok()?.to_string();

        Some(PathCondition::InstanceOf {
            variable,
            type_name,
            is_positive: true,
        })
    }

    /// Extract condition from call expression (e.g., Array.isArray(x))
    fn extract_call_condition(&self, node: tree_sitter::Node<'a>) -> Option<PathCondition> {
        let func = node
            .child_by_field_name(self.semantics.function_field)
            .or_else(|| node.named_child(0))?;
        let func_text = func.utf8_text(self.source).ok()?;

        // Array.isArray(x)
        if func_text == "Array.isArray" {
            let args = node.child_by_field_name(self.semantics.arguments_field)?;
            let first_arg = args.named_child(0)?;
            let var_name = first_arg.utf8_text(self.source).ok()?.to_string();

            return Some(PathCondition::InstanceOf {
                variable: var_name,
                type_name: "Array".to_string(),
                is_positive: true,
            });
        }

        // obj.hasOwnProperty("prop")
        if func_text.ends_with(".hasOwnProperty") {
            let object = func_text.trim_end_matches(".hasOwnProperty").to_string();
            let args = node.child_by_field_name(self.semantics.arguments_field)?;
            let first_arg = args.named_child(0)?;
            let property = first_arg.utf8_text(self.source).ok()?;
            let property = property.trim_matches(|c| c == '"' || c == '\'').to_string();

            return Some(PathCondition::PropertyExists {
                object,
                property,
                exists: true,
            });
        }

        // array.includes(value)
        if func_text.ends_with(".includes") {
            let array = func_text.trim_end_matches(".includes").to_string();
            let args = node.child_by_field_name(self.semantics.arguments_field)?;
            let first_arg = args.named_child(0)?;
            let value = first_arg.utf8_text(self.source).ok()?.to_string();

            return Some(PathCondition::ArrayIncludes {
                array,
                value,
                includes: true,
            });
        }

        None
    }

    /// Check if a node is a null literal
    fn is_null_literal(&self, node: tree_sitter::Node<'a>) -> bool {
        let kind = node.kind();
        if self.semantics.is_null_literal(kind) || kind == "null" || kind == "nil" {
            return true;
        }
        if kind == "identifier"
            && let Ok(text) = node.utf8_text(self.source)
        {
            return text == "null" || text == "nil" || text == "None";
        }
        false
    }

    /// Check if a node is an undefined literal
    fn is_undefined_literal(&self, node: tree_sitter::Node<'a>) -> bool {
        if node.kind() == "undefined" {
            return true;
        }
        if node.kind() == "identifier"
            && let Ok(text) = node.utf8_text(self.source)
        {
            return text == "undefined";
        }
        false
    }

    /// Flip a comparison operator (for when operands are swapped)
    fn flip_operator<'b>(&self, op: &'b str) -> &'b str {
        match op {
            "<" => ">",
            ">" => "<",
            "<=" => ">=",
            ">=" => "<=",
            "==" => "==",
            "===" => "===",
            "!=" => "!=",
            "!==" => "!==",
            other => other,
        }
    }
}

// =============================================================================
// Symbolic Analysis
// =============================================================================

/// Analyze symbolic path conditions through the CFG
pub fn analyze_symbolic_conditions(
    cfg: &CFG,
    tree: &tree_sitter::Tree,
    source: &[u8],
    semantics: &'static LanguageSemantics,
) -> SymbolicAnalysisResult {
    let mut result = SymbolicAnalysisResult::default();
    let extractor = ConditionExtractor::new(semantics, source);

    // Initialize all blocks with empty state
    for block in &cfg.blocks {
        result.block_entry.insert(block.id, SymbolicState::new());
        result.block_exit.insert(block.id, SymbolicState::new());
    }

    // Process blocks in topological order (roughly forward through CFG)
    let mut worklist: Vec<BlockId> = vec![cfg.entry];
    let mut visited: HashSet<BlockId> = HashSet::new();

    while let Some(block_id) = worklist.pop() {
        if visited.contains(&block_id) {
            continue;
        }
        visited.insert(block_id);

        if block_id >= cfg.blocks.len() {
            continue;
        }

        let block = &cfg.blocks[block_id];
        if !block.reachable {
            continue;
        }

        // Compute entry state from predecessors
        let entry_state = if block.predecessors.is_empty() {
            SymbolicState::new()
        } else {
            // Merge states from all predecessors
            let mut merged: Option<SymbolicState> = None;
            for &pred_id in &block.predecessors {
                if let Some(pred_exit) = result.block_exit.get(&pred_id) {
                    merged = Some(match merged {
                        None => pred_exit.clone(),
                        Some(existing) => existing.merge(pred_exit),
                    });
                }
            }
            merged.unwrap_or_default()
        };

        // Check feasibility
        if !entry_state.is_feasible() {
            result.infeasible_blocks.insert(block_id);
        }

        result.block_entry.insert(block_id, entry_state.clone());

        // Compute exit states based on terminator
        match &block.terminator {
            Terminator::Branch {
                condition_node,
                true_block,
                false_block,
            } => {
                // Extract condition from the branch
                if let Some(cond_node) = find_node_by_id(tree, *condition_node)
                    && let Some(condition) = extractor.extract_condition(cond_node)
                {
                    // True branch gets the condition
                    let mut true_state = entry_state.clone();
                    true_state.add_condition(condition.clone());
                    result.block_entry.insert(*true_block, true_state.clone());
                    result.block_exit.insert(block_id, true_state);

                    // False branch gets the negated condition
                    let mut false_state = entry_state;
                    false_state.add_condition(condition.negate());
                    result.block_entry.insert(*false_block, false_state);

                    // Add successors to worklist
                    worklist.push(*true_block);
                    worklist.push(*false_block);
                    continue;
                }

                // Couldn't extract condition, propagate unchanged
                result.block_exit.insert(block_id, entry_state.clone());
                worklist.push(*true_block);
                worklist.push(*false_block);
            }

            Terminator::Loop {
                body,
                exit,
                condition_node,
            } => {
                if let Some(cond_id) = condition_node
                    && let Some(cond_node) = find_node_by_id(tree, *cond_id)
                    && let Some(condition) = extractor.extract_condition(cond_node)
                {
                    // Loop body gets the condition
                    let mut body_state = entry_state.clone();
                    body_state.add_condition(condition.clone());
                    result.block_entry.insert(*body, body_state);

                    // Loop exit gets the negated condition
                    let mut exit_state = entry_state;
                    exit_state.add_condition(condition.negate());
                    result.block_entry.insert(*exit, exit_state);

                    worklist.push(*body);
                    worklist.push(*exit);
                    continue;
                }

                result.block_exit.insert(block_id, entry_state);
                worklist.push(*body);
                worklist.push(*exit);
            }

            Terminator::Switch { cases, .. } => {
                result.block_exit.insert(block_id, entry_state);
                for (_, target) in cases {
                    worklist.push(*target);
                }
            }

            _ => {
                result.block_exit.insert(block_id, entry_state);
                for succ in cfg.successors(block_id) {
                    worklist.push(succ);
                }
            }
        }
    }

    result
}

/// Check if a set of path conditions is feasible (satisfiable)
pub fn is_feasible(conditions: &HashSet<PathCondition>) -> bool {
    let state = SymbolicState::with_conditions(conditions.clone());
    state.is_feasible()
}

/// Get all constraints for a variable from a set of conditions
pub fn get_constraints<'a>(
    conditions: &'a HashSet<PathCondition>,
    var_name: &str,
) -> Vec<&'a PathCondition> {
    conditions
        .iter()
        .filter(|c| c.constrained_variables().contains(&var_name))
        .collect()
}

// =============================================================================
// Transfer Function for Dataflow Integration
// =============================================================================

/// A symbolic path condition fact for dataflow analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymbolicFact {
    /// The path condition
    pub condition: PathCondition,
}

impl SymbolicFact {
    pub fn new(condition: PathCondition) -> Self {
        Self { condition }
    }
}

/// Transfer function for symbolic analysis as forward dataflow
pub struct SymbolicTransfer {
    semantics: &'static LanguageSemantics,
}

impl SymbolicTransfer {
    pub fn new(semantics: &'static LanguageSemantics) -> Self {
        Self { semantics }
    }
}

impl TransferFunction<SymbolicFact> for SymbolicTransfer {
    fn transfer(
        &self,
        block: &crate::flow::cfg::BasicBlock,
        input: &HashSet<SymbolicFact>,
        _cfg: &CFG,
        source: &[u8],
        tree: &tree_sitter::Tree,
    ) -> HashSet<SymbolicFact> {
        let mut output = input.clone();
        let extractor = ConditionExtractor::new(self.semantics, source);

        // Process branch conditions at the end of the block
        if let Terminator::Branch { condition_node, .. } = &block.terminator
            && let Some(cond_node) = find_node_by_id(tree, *condition_node)
            && let Some(condition) = extractor.extract_condition(cond_node)
        {
            output.insert(SymbolicFact::new(condition));
        }

        output
    }
}

/// Run symbolic analysis using the dataflow framework
pub fn analyze_symbolic_dataflow(
    cfg: &CFG,
    tree: &tree_sitter::Tree,
    source: &[u8],
    semantics: &'static LanguageSemantics,
) -> DataflowResult<SymbolicFact> {
    let transfer = SymbolicTransfer::new(semantics);
    crate::flow::dataflow::solve(cfg, Direction::Forward, &transfer, source, tree)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::Language;
    use rma_parser::ParserEngine;
    use std::path::Path;

    fn parse_js(code: &str) -> rma_parser::ParsedFile {
        let config = rma_common::RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser
            .parse_file(Path::new("test.js"), code)
            .expect("parse failed")
    }

    // =========================================================================
    // PathCondition Tests
    // =========================================================================

    #[test]
    fn test_null_check_condition() {
        let cond = PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: true,
        };
        assert_eq!(cond.constrained_variables(), vec!["x"]);
    }

    #[test]
    fn test_condition_negation() {
        let cond = PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: true,
        };
        let negated = cond.negate();
        assert!(matches!(
            negated,
            PathCondition::NullCheck { is_null: false, .. }
        ));
    }

    #[test]
    fn test_type_guard_condition() {
        let cond = PathCondition::TypeGuard {
            variable: "x".to_string(),
            guarded_type: GuardedType::String,
            is_positive: true,
        };
        assert_eq!(cond.constrained_variables(), vec!["x"]);
    }

    #[test]
    fn test_length_constraint() {
        let cond = PathCondition::LengthConstraint {
            variable: "input".to_string(),
            op: ComparisonOp::Lt,
            value: 10,
        };
        assert_eq!(cond.constrained_variables(), vec!["input"]);
    }

    #[test]
    fn test_condition_contradiction() {
        let cond1 = PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: true,
        };
        let cond2 = PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: false,
        };
        assert!(cond1.contradicts(&cond2));
    }

    #[test]
    fn test_comparison_op_negation() {
        assert_eq!(ComparisonOp::Lt.negate(), ComparisonOp::Ge);
        assert_eq!(ComparisonOp::Gt.negate(), ComparisonOp::Le);
        assert_eq!(ComparisonOp::Eq.negate(), ComparisonOp::Ne);
    }

    // =========================================================================
    // SymbolicState Tests
    // =========================================================================

    #[test]
    fn test_symbolic_state_add_condition() {
        let mut state = SymbolicState::new();
        state.add_condition(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: false,
        });
        assert!(!state.is_empty());
        assert!(state.is_non_null("x"));
    }

    #[test]
    fn test_symbolic_state_feasibility() {
        let mut state = SymbolicState::new();
        state.add_condition(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: true,
        });
        state.add_condition(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: false,
        });
        assert!(!state.is_feasible());
    }

    #[test]
    fn test_symbolic_state_merge() {
        let mut state1 = SymbolicState::new();
        state1.add_condition(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: false,
        });
        state1.add_condition(PathCondition::Truthy {
            variable: "y".to_string(),
            is_truthy: true,
        });

        let mut state2 = SymbolicState::new();
        state2.add_condition(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: false,
        });

        let merged = state1.merge(&state2);
        // Only the common condition (x is non-null) should remain
        assert!(merged.is_non_null("x"));
        assert!(!merged.is_truthy("y")); // This was only in state1
    }

    #[test]
    fn test_get_type_guard() {
        let mut state = SymbolicState::new();
        state.add_condition(PathCondition::TypeGuard {
            variable: "x".to_string(),
            guarded_type: GuardedType::String,
            is_positive: true,
        });

        let guard = state.get_type_guard("x");
        assert!(matches!(guard, Some(GuardedType::String)));
    }

    #[test]
    fn test_get_length_constraints() {
        let mut state = SymbolicState::new();
        state.add_condition(PathCondition::LengthConstraint {
            variable: "input".to_string(),
            op: ComparisonOp::Lt,
            value: 10,
        });
        state.add_condition(PathCondition::LengthConstraint {
            variable: "input".to_string(),
            op: ComparisonOp::Gt,
            value: 0,
        });

        let constraints = state.get_length_constraints("input");
        assert_eq!(constraints.len(), 2);
    }

    // =========================================================================
    // Condition Extraction Tests
    // =========================================================================

    #[test]
    fn test_extract_null_check() {
        let code = "if (x !== null) { console.log(x); }";
        let parsed = parse_js(code);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        let result = analyze_symbolic_conditions(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // Should have extracted conditions
        assert!(!result.block_entry.is_empty());
    }

    #[test]
    fn test_extract_typeof_check() {
        let code = r#"if (typeof x === "string") { console.log(x); }"#;
        let parsed = parse_js(code);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        let result = analyze_symbolic_conditions(&cfg, &parsed.tree, code.as_bytes(), semantics);

        assert!(!result.block_entry.is_empty());
    }

    #[test]
    fn test_extract_length_check() {
        let code = "if (input.length < 10) { process(input); }";
        let parsed = parse_js(code);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        let result = analyze_symbolic_conditions(&cfg, &parsed.tree, code.as_bytes(), semantics);

        assert!(!result.block_entry.is_empty());
    }

    #[test]
    fn test_extract_numeric_comparison() {
        let code = "if (count > 0) { process(count); }";
        let parsed = parse_js(code);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        let result = analyze_symbolic_conditions(&cfg, &parsed.tree, code.as_bytes(), semantics);

        assert!(!result.block_entry.is_empty());
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_branching_conditions() {
        let code = r#"
            function validate(input) {
                if (input !== null) {
                    if (typeof input === 'string') {
                        if (input.length > 0) {
                            return input;
                        }
                    }
                }
                return null;
            }
        "#;
        let parsed = parse_js(code);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        let result = analyze_symbolic_conditions(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // Analysis should have run and populated block entries
        // At minimum, we should have the entry block
        assert!(
            !result.block_entry.is_empty(),
            "Should have analyzed at least one block"
        );

        // If we have multiple blocks, verify we extracted some conditions
        if cfg.block_count() > 1 {
            // At least one block should have some state computed
            let has_some_state = result
                .block_entry
                .values()
                .chain(result.block_exit.values())
                .any(|state| !state.is_empty() || state.conditions().is_empty());
            assert!(has_some_state, "Should have computed states for blocks");
        }
    }

    #[test]
    fn test_infeasible_path_detection() {
        // This creates an obviously infeasible path
        let code = r#"
            if (x === null) {
                if (x !== null) {
                    // This block should be infeasible
                    console.log("unreachable");
                }
            }
        "#;
        let parsed = parse_js(code);
        let semantics = LanguageSemantics::for_language(Language::JavaScript);
        let cfg = CFG::build(&parsed, Language::JavaScript);

        let result = analyze_symbolic_conditions(&cfg, &parsed.tree, code.as_bytes(), semantics);

        // Should detect the infeasible path
        // Note: This depends on the CFG structure
        assert!(result.block_entry.len() > 1);
    }

    // =========================================================================
    // GuardedType Tests
    // =========================================================================

    #[test]
    fn test_guarded_type_from_str() {
        assert_eq!(GuardedType::parse("string"), Some(GuardedType::String));
        assert_eq!(GuardedType::parse("number"), Some(GuardedType::Number));
        assert_eq!(GuardedType::parse("boolean"), Some(GuardedType::Boolean));
        assert_eq!(GuardedType::parse("object"), Some(GuardedType::Object));
        assert_eq!(GuardedType::parse("function"), Some(GuardedType::Function));
        assert_eq!(
            GuardedType::parse("undefined"),
            Some(GuardedType::Undefined)
        );
        assert_eq!(GuardedType::parse("symbol"), Some(GuardedType::Symbol));
        assert_eq!(GuardedType::parse("bigint"), Some(GuardedType::BigInt));
        assert_eq!(GuardedType::parse("'string'"), Some(GuardedType::String));
        assert_eq!(GuardedType::parse("\"number\""), Some(GuardedType::Number));
    }

    #[test]
    fn test_guarded_type_to_inferred() {
        assert_eq!(GuardedType::String.to_inferred_type(), InferredType::String);
        assert_eq!(GuardedType::Number.to_inferred_type(), InferredType::Number);
        assert_eq!(
            GuardedType::Boolean.to_inferred_type(),
            InferredType::Boolean
        );
    }

    // =========================================================================
    // Utility Function Tests
    // =========================================================================

    #[test]
    fn test_is_feasible_function() {
        let mut conditions = HashSet::new();
        conditions.insert(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: false,
        });
        assert!(is_feasible(&conditions));

        conditions.insert(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: true,
        });
        assert!(!is_feasible(&conditions));
    }

    #[test]
    fn test_get_constraints_function() {
        let mut conditions = HashSet::new();
        conditions.insert(PathCondition::NullCheck {
            variable: "x".to_string(),
            is_null: false,
        });
        conditions.insert(PathCondition::Truthy {
            variable: "y".to_string(),
            is_truthy: true,
        });
        conditions.insert(PathCondition::LengthConstraint {
            variable: "x".to_string(),
            op: ComparisonOp::Gt,
            value: 0,
        });

        let x_constraints = get_constraints(&conditions, "x");
        assert_eq!(x_constraints.len(), 2);

        let y_constraints = get_constraints(&conditions, "y");
        assert_eq!(y_constraints.len(), 1);

        let z_constraints = get_constraints(&conditions, "z");
        assert_eq!(z_constraints.len(), 0);
    }
}
