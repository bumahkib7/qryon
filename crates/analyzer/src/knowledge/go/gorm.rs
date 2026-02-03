//! GORM and database/sql profile
//!
//! Security knowledge for Go database access - GORM ORM and the standard
//! database/sql package. Focuses on SQL injection prevention and
//! connection management.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// GORM and database/sql profile
pub static GORM_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "gorm",
    description: "GORM ORM and database/sql - Go database access with SQL injection prevention",
    detect_imports: &[
        "gorm.io/gorm",
        "gorm.io/driver",
        "database/sql",
        "github.com/jinzhu/gorm", // Legacy GORM v1
        "github.com/jmoiron/sqlx",
        "github.com/Masterminds/squirrel",
    ],

    sources: &[
        // Database results can be sources if they contain user-generated content
        SourceDef {
            name: "db_find_result",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gorm.DB",
                method: "Find",
            },
            taint_label: "db_content",
            description: "Database query result - may contain user-generated content",
        },
        SourceDef {
            name: "db_first_result",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gorm.DB",
                method: "First",
            },
            taint_label: "db_content",
            description: "Database query result - may contain user-generated content",
        },
        SourceDef {
            name: "db_take_result",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gorm.DB",
                method: "Take",
            },
            taint_label: "db_content",
            description: "Database query result - may contain user-generated content",
        },
        SourceDef {
            name: "sql_query_row",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*sql.DB",
                method: "QueryRow",
            },
            taint_label: "db_content",
            description: "SQL query result - may contain user-generated content",
        },
        SourceDef {
            name: "sql_query",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*sql.DB",
                method: "Query",
            },
            taint_label: "db_content",
            description: "SQL query result - may contain user-generated content",
        },
    ],

    sinks: &[
        // GORM raw SQL methods - HIGH RISK
        SinkDef {
            name: "gorm_raw",
            pattern: SinkKind::MethodCall("Raw"),
            rule_id: "go/gorm-sql-injection-raw",
            severity: Severity::Critical,
            description: "GORM Raw() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "gorm_exec",
            pattern: SinkKind::MethodCall("Exec"),
            rule_id: "go/gorm-sql-injection-exec",
            severity: Severity::Critical,
            description: "GORM Exec() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        // database/sql direct queries - use MethodCall since classifier extracts method names
        SinkDef {
            name: "sql_query",
            pattern: SinkKind::MethodCall("Query"),
            rule_id: "go/sql-injection-query",
            severity: Severity::Critical,
            description: "sql.DB.Query() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "sql_query_context",
            pattern: SinkKind::MethodCall("QueryContext"),
            rule_id: "go/sql-injection-query-context",
            severity: Severity::Critical,
            description: "sql.DB.QueryContext() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "sql_query_row",
            pattern: SinkKind::MethodCall("QueryRow"),
            rule_id: "go/sql-injection-queryrow",
            severity: Severity::Critical,
            description: "sql.DB.QueryRow() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "sql_query_row_context",
            pattern: SinkKind::MethodCall("QueryRowContext"),
            rule_id: "go/sql-injection-queryrow-context",
            severity: Severity::Critical,
            description: "sql.DB.QueryRowContext() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "sql_exec",
            pattern: SinkKind::MethodCall("Exec"),
            rule_id: "go/sql-injection-exec",
            severity: Severity::Critical,
            description: "sql.DB.Exec() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "sql_exec_context",
            pattern: SinkKind::MethodCall("ExecContext"),
            rule_id: "go/sql-injection-exec-context",
            severity: Severity::Critical,
            description: "sql.DB.ExecContext() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "sql_prepare",
            pattern: SinkKind::MethodCall("Prepare"),
            rule_id: "go/sql-injection-prepare",
            severity: Severity::Critical,
            description: "sql.DB.Prepare() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "sql_prepare_context",
            pattern: SinkKind::MethodCall("PrepareContext"),
            rule_id: "go/sql-injection-prepare-context",
            severity: Severity::Critical,
            description: "sql.DB.PrepareContext() with string concatenation causes SQL injection",
            cwe: Some("CWE-89"),
        },
        // fmt.Sprintf building SQL - ALWAYS DANGEROUS
        // Note: classifier extracts "Sprintf" from "fmt.Sprintf" calls
        SinkDef {
            name: "sprintf_sql",
            pattern: SinkKind::FunctionCall("Sprintf"),
            rule_id: "go/sql-injection-sprintf",
            severity: Severity::Critical,
            description: "Building SQL with fmt.Sprintf causes SQL injection",
            cwe: Some("CWE-89"),
        },
        // String concatenation for SQL
        SinkDef {
            name: "string_concat_sql",
            pattern: SinkKind::TemplateInsertion,
            rule_id: "go/sql-injection-concat",
            severity: Severity::Critical,
            description: "String concatenation in SQL query causes SQL injection",
            cwe: Some("CWE-89"),
        },
        // GORM Where with string concat
        SinkDef {
            name: "gorm_where_string",
            pattern: SinkKind::MethodCall("Where"),
            rule_id: "go/gorm-sql-injection-where",
            severity: Severity::Warning,
            description: "GORM Where() with string concatenation - use ? placeholders",
            cwe: Some("CWE-89"),
        },
        // GORM Order with user input
        SinkDef {
            name: "gorm_order",
            pattern: SinkKind::MethodCall("Order"),
            rule_id: "go/gorm-order-injection",
            severity: Severity::Warning,
            description: "GORM Order() with user input - validate column names",
            cwe: Some("CWE-89"),
        },
        // GORM Select with user input
        SinkDef {
            name: "gorm_select",
            pattern: SinkKind::MethodCall("Select"),
            rule_id: "go/gorm-select-injection",
            severity: Severity::Warning,
            description: "GORM Select() with user input - validate column names",
            cwe: Some("CWE-89"),
        },
        // GORM Group with user input
        SinkDef {
            name: "gorm_group",
            pattern: SinkKind::MethodCall("Group"),
            rule_id: "go/gorm-group-injection",
            severity: Severity::Warning,
            description: "GORM Group() with user input - validate column names",
            cwe: Some("CWE-89"),
        },
        // GORM Table with user input
        SinkDef {
            name: "gorm_table",
            pattern: SinkKind::MethodCall("Table"),
            rule_id: "go/gorm-table-injection",
            severity: Severity::Critical,
            description: "GORM Table() with user input - validate table names",
            cwe: Some("CWE-89"),
        },
    ],

    sanitizers: &[
        // Parameterized queries are the sanitizer
        SanitizerDef {
            name: "parameterized_query",
            pattern: SanitizerKind::Function("?"),
            sanitizes: "sql",
            description: "Parameterized queries with ? placeholders prevent SQL injection",
        },
        // GORM chain methods with struct binding
        SanitizerDef {
            name: "gorm_struct_binding",
            pattern: SanitizerKind::MethodCall("Create"),
            sanitizes: "sql",
            description: "GORM struct binding automatically escapes values",
        },
        SanitizerDef {
            name: "gorm_updates_map",
            pattern: SanitizerKind::MethodCall("Updates"),
            sanitizes: "sql",
            description: "GORM Updates with map automatically escapes values",
        },
        // Squirrel query builder
        SanitizerDef {
            name: "squirrel_builder",
            pattern: SanitizerKind::Function("squirrel."),
            sanitizes: "sql",
            description: "Squirrel query builder generates parameterized queries",
        },
        SanitizerDef {
            name: "squirrel_placeholder",
            pattern: SanitizerKind::Function("sq.Placeholder"),
            sanitizes: "sql",
            description: "Squirrel placeholder format for parameterized queries",
        },
        // Column name validation
        SanitizerDef {
            name: "column_whitelist",
            pattern: SanitizerKind::Function("allowedColumns"),
            sanitizes: "column_name",
            description: "Whitelist validation of column names",
        },
    ],

    safe_patterns: &[
        // GORM with ? placeholders
        SafePattern {
            name: "gorm_where_placeholder",
            pattern: "Where(\"column = ?\", value)",
            reason: "Parameterized query with ? placeholder is safe",
        },
        SafePattern {
            name: "gorm_where_map",
            pattern: "Where(map[string]interface{}",
            reason: "GORM map conditions are parameterized",
        },
        SafePattern {
            name: "gorm_where_struct",
            pattern: "Where(&Model{",
            reason: "GORM struct conditions are parameterized",
        },
        // GORM chain methods
        SafePattern {
            name: "gorm_find",
            pattern: "db.Find(&result)",
            reason: "GORM Find without raw SQL is safe",
        },
        SafePattern {
            name: "gorm_first",
            pattern: "db.First(&result)",
            reason: "GORM First without raw SQL is safe",
        },
        SafePattern {
            name: "gorm_create_struct",
            pattern: "db.Create(&model)",
            reason: "GORM Create with struct is parameterized",
        },
        SafePattern {
            name: "gorm_updates_struct",
            pattern: "db.Updates(&model)",
            reason: "GORM Updates with struct is parameterized",
        },
        // Prepared statements
        SafePattern {
            name: "sql_prepare",
            pattern: "db.Prepare(",
            reason: "Prepared statements with ? placeholders are safe",
        },
        // Squirrel
        SafePattern {
            name: "squirrel_select",
            pattern: "sq.Select(",
            reason: "Squirrel query builder generates safe queries",
        },
        SafePattern {
            name: "squirrel_insert",
            pattern: "sq.Insert(",
            reason: "Squirrel query builder generates safe queries",
        },
        SafePattern {
            name: "squirrel_update",
            pattern: "sq.Update(",
            reason: "Squirrel query builder generates safe queries",
        },
    ],

    dangerous_patterns: &[
        // String concatenation in SQL
        DangerousPattern {
            name: "sql_string_concat",
            pattern: PatternKind::Regex(
                r#"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\+\s*[a-zA-Z]"#,
            ),
            rule_id: "go/sql-string-concat",
            severity: Severity::Critical,
            description: "SQL query built with string concatenation - use parameterized queries",
            cwe: Some("CWE-89"),
        },
        // fmt.Sprintf for SQL
        DangerousPattern {
            name: "sprintf_sql_pattern",
            pattern: PatternKind::Regex(
                r#"fmt\.Sprintf\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)"#,
            ),
            rule_id: "go/sprintf-sql",
            severity: Severity::Critical,
            description: "fmt.Sprintf to build SQL - use parameterized queries",
            cwe: Some("CWE-89"),
        },
        // GORM Raw without placeholders
        DangerousPattern {
            name: "gorm_raw_no_placeholder",
            pattern: PatternKind::Regex(
                r#"\.Raw\s*\(\s*["'][^?]*["']\s*\+|\.Raw\s*\(\s*fmt\.Sprintf"#,
            ),
            rule_id: "go/gorm-raw-unsafe",
            severity: Severity::Critical,
            description: "GORM Raw() without ? placeholders - SQL injection risk",
            cwe: Some("CWE-89"),
        },
        // Exec without placeholders
        DangerousPattern {
            name: "exec_no_placeholder",
            pattern: PatternKind::Regex(
                r#"\.Exec\s*\(\s*["'][^?]*["']\s*\+|\.Exec\s*\(\s*fmt\.Sprintf"#,
            ),
            rule_id: "go/exec-unsafe",
            severity: Severity::Critical,
            description: "Exec() without ? placeholders - SQL injection risk",
            cwe: Some("CWE-89"),
        },
        // Error not checked after database operation
        DangerousPattern {
            name: "db_error_ignored",
            pattern: PatternKind::Regex(r#"db\.\w+\([^)]*\)\s*$"#),
            rule_id: "go/db-error-ignored",
            severity: Severity::Warning,
            description: "Database operation without error check",
            cwe: Some("CWE-252"),
        },
        // Rows not closed
        DangerousPattern {
            name: "rows_not_closed",
            pattern: PatternKind::Missing("defer rows.Close()"),
            rule_id: "go/rows-not-closed",
            severity: Severity::Warning,
            description: "sql.Rows should be closed with defer rows.Close()",
            cwe: Some("CWE-404"),
        },
        // Connection not checked
        DangerousPattern {
            name: "db_ping_missing",
            pattern: PatternKind::Missing("db.Ping"),
            rule_id: "go/db-ping-missing",
            severity: Severity::Info,
            description: "Consider calling db.Ping() to verify database connection",
            cwe: None,
        },
        // Hardcoded credentials in DSN
        DangerousPattern {
            name: "hardcoded_dsn_password",
            pattern: PatternKind::Regex(r#":\w+@.*\("(mysql|postgres|sqlite)"#),
            rule_id: "go/hardcoded-db-password",
            severity: Severity::Critical,
            description: "Hardcoded database password in connection string",
            cwe: Some("CWE-798"),
        },
    ],

    resource_types: &[
        ResourceType {
            name: "*sql.DB",
            acquire_pattern: "sql.Open|gorm.Open",
            release_pattern: "Close()",
            leak_consequence: "Database connection pool leak",
        },
        ResourceType {
            name: "*sql.Rows",
            acquire_pattern: "Query|QueryContext",
            release_pattern: "Close()",
            leak_consequence: "Database connection leak - exhausts connection pool",
        },
        ResourceType {
            name: "*sql.Stmt",
            acquire_pattern: "Prepare|PrepareContext",
            release_pattern: "Close()",
            leak_consequence: "Prepared statement leak",
        },
        ResourceType {
            name: "*sql.Tx",
            acquire_pattern: "Begin|BeginTx",
            release_pattern: "Commit()|Rollback()",
            leak_consequence: "Transaction leak - database locks",
        },
        ResourceType {
            name: "*gorm.DB (transaction)",
            acquire_pattern: "Begin()",
            release_pattern: "Commit()|Rollback()",
            leak_consequence: "GORM transaction leak - database locks",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gorm_detection() {
        let content = r#"
            package main
            import "gorm.io/gorm"
        "#;
        assert!(GORM_PROFILE.is_active(content));
    }

    #[test]
    fn test_sql_detection() {
        let content = r#"
            package main
            import "database/sql"
        "#;
        assert!(GORM_PROFILE.is_active(content));
    }

    #[test]
    fn test_sqlx_detection() {
        let content = r#"
            package main
            import "github.com/jmoiron/sqlx"
        "#;
        assert!(GORM_PROFILE.is_active(content));
    }

    #[test]
    fn test_squirrel_detection() {
        let content = r#"
            package main
            import sq "github.com/Masterminds/squirrel"
        "#;
        assert!(GORM_PROFILE.is_active(content));
    }

    #[test]
    fn test_has_sql_injection_sinks() {
        assert!(GORM_PROFILE.sinks.iter().any(|s| s.name == "gorm_raw"));
        assert!(GORM_PROFILE.sinks.iter().any(|s| s.name == "sql_query"));
        assert!(GORM_PROFILE.sinks.iter().any(|s| s.name == "sprintf_sql"));
    }

    #[test]
    fn test_has_safe_patterns() {
        assert!(
            GORM_PROFILE
                .safe_patterns
                .iter()
                .any(|s| s.name == "gorm_where_placeholder")
        );
        assert!(
            GORM_PROFILE
                .safe_patterns
                .iter()
                .any(|s| s.name == "squirrel_select")
        );
    }

    #[test]
    fn test_has_resource_types() {
        assert!(
            GORM_PROFILE
                .resource_types
                .iter()
                .any(|r| r.name == "*sql.Rows")
        );
        assert!(
            GORM_PROFILE
                .resource_types
                .iter()
                .any(|r| r.name == "*sql.Tx")
        );
    }
}
