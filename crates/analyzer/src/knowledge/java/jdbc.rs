//! JDBC (Java Database Connectivity) framework profile
//!
//! JDBC is the standard Java API for database access. This profile covers:
//! - SQL injection sinks via Statement and Connection
//! - Safe patterns using PreparedStatement with parameters
//! - Resource management for Connection, Statement, ResultSet
//!
//! # Key Security Concerns
//!
//! - **SQL Injection**: String concatenation in queries
//! - **Resource Leaks**: Unclosed connections, statements, result sets
//! - **Connection Pool Exhaustion**: Not returning connections properly

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SinkDef, SinkKind,
    SourceDef, SourceKind,
};
use rma_common::Severity;

/// JDBC framework profile for database security analysis
pub static JDBC_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "jdbc",
    description: "Java Database Connectivity - standard database access API",

    detect_imports: &[
        "java.sql",
        "javax.sql",
        "import java.sql.",
        "import javax.sql.",
    ],

    // =========================================================================
    // Sources - Data from database queries (potentially containing user input)
    // =========================================================================
    sources: &[
        SourceDef {
            name: "ResultSet.getString",
            pattern: SourceKind::MethodOnType {
                type_pattern: "ResultSet",
                method: "getString",
            },
            taint_label: "db_data",
            description: "Data retrieved from database may contain user input (stored XSS)",
        },
        SourceDef {
            name: "ResultSet.getObject",
            pattern: SourceKind::MethodOnType {
                type_pattern: "ResultSet",
                method: "getObject",
            },
            taint_label: "db_data",
            description: "Data retrieved from database may contain user input",
        },
    ],

    // =========================================================================
    // Sinks - SQL injection vectors
    // =========================================================================
    sinks: &[
        // Statement.execute with string concatenation
        SinkDef {
            name: "Statement.execute",
            pattern: SinkKind::MethodCall("execute"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Critical,
            description: "Statement.execute() with concatenated SQL allows injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "Statement.executeQuery",
            pattern: SinkKind::MethodCall("executeQuery"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Critical,
            description: "Statement.executeQuery() with concatenated SQL allows injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "Statement.executeUpdate",
            pattern: SinkKind::MethodCall("executeUpdate"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Critical,
            description: "Statement.executeUpdate() with concatenated SQL allows injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "Statement.executeBatch",
            pattern: SinkKind::MethodCall("executeBatch"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Critical,
            description: "Statement.executeBatch() with concatenated SQL allows injection",
            cwe: Some("CWE-89"),
        },
        // Connection.prepareStatement with string concat (still dangerous!)
        SinkDef {
            name: "Connection.prepareStatement-concat",
            pattern: SinkKind::MethodCall("prepareStatement"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Critical,
            description: "Connection.prepareStatement() with string concatenation defeats parameterization",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "Connection.prepareCall-concat",
            pattern: SinkKind::MethodCall("prepareCall"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Critical,
            description: "Connection.prepareCall() with string concatenation defeats parameterization",
            cwe: Some("CWE-89"),
        },
        // Statement.addBatch for batch operations
        SinkDef {
            name: "Statement.addBatch",
            pattern: SinkKind::MethodCall("addBatch"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Critical,
            description: "Statement.addBatch() with concatenated SQL allows injection",
            cwe: Some("CWE-89"),
        },
        // Native SQL execution
        SinkDef {
            name: "Connection.nativeSQL",
            pattern: SinkKind::MethodCall("nativeSQL"),
            rule_id: "java/jdbc-sql-injection",
            severity: Severity::Error,
            description: "Connection.nativeSQL() bypasses JDBC escaping",
            cwe: Some("CWE-89"),
        },
    ],

    // =========================================================================
    // Sanitizers - N/A for JDBC, use PreparedStatement instead
    // =========================================================================
    sanitizers: &[
        // Note: There's no reliable way to sanitize SQL in Java
        // The only safe approach is parameterized queries
    ],

    // =========================================================================
    // Safe Patterns - Parameterized queries prevent SQL injection
    // =========================================================================
    safe_patterns: &[
        SafePattern {
            name: "PreparedStatement with ?",
            pattern: "PreparedStatement.*\\?",
            reason: "Parameterized queries with ? placeholders prevent SQL injection",
        },
        SafePattern {
            name: "PreparedStatement setString",
            pattern: "setString\\(",
            reason: "Setting parameters via setString safely escapes values",
        },
        SafePattern {
            name: "PreparedStatement setInt",
            pattern: "setInt\\(",
            reason: "Setting parameters via setInt safely handles values",
        },
        SafePattern {
            name: "PreparedStatement setLong",
            pattern: "setLong\\(",
            reason: "Setting parameters via setLong safely handles values",
        },
        SafePattern {
            name: "PreparedStatement setObject",
            pattern: "setObject\\(",
            reason: "Setting parameters via setObject safely handles values",
        },
        SafePattern {
            name: "CallableStatement with ?",
            pattern: "CallableStatement.*\\?",
            reason: "Parameterized stored procedure calls prevent injection",
        },
        SafePattern {
            name: "Named parameters",
            pattern: ":\\w+",
            reason: "Named parameters (used by some frameworks) prevent injection",
        },
    ],

    // =========================================================================
    // Dangerous Patterns - JDBC-specific anti-patterns
    // =========================================================================
    dangerous_patterns: &[
        // SQL string concatenation
        DangerousPattern {
            name: "SQL string concatenation",
            pattern: PatternKind::Regex(
                r#"(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR)\s*"\s*\+\s*"#,
            ),
            rule_id: "java/jdbc-string-concat",
            severity: Severity::Critical,
            description: "SQL query built with string concatenation - use PreparedStatement",
            cwe: Some("CWE-89"),
        },
        // Statement used instead of PreparedStatement
        DangerousPattern {
            name: "Statement instead of PreparedStatement",
            pattern: PatternKind::Construct("createStatement()"),
            rule_id: "java/jdbc-use-prepared-statement",
            severity: Severity::Warning,
            description: "Use PreparedStatement instead of Statement for parameterized queries",
            cwe: Some("CWE-89"),
        },
        // Unclosed ResultSet
        DangerousPattern {
            name: "ResultSet without close",
            pattern: PatternKind::Missing("ResultSet.*close"),
            rule_id: "java/jdbc-unclosed-resultset",
            severity: Severity::Warning,
            description: "ResultSet should be closed to prevent resource leaks",
            cwe: Some("CWE-404"),
        },
        // Unclosed Statement
        DangerousPattern {
            name: "Statement without close",
            pattern: PatternKind::Missing("Statement.*close"),
            rule_id: "java/jdbc-unclosed-statement",
            severity: Severity::Warning,
            description: "Statement should be closed to prevent resource leaks",
            cwe: Some("CWE-404"),
        },
        // Unclosed Connection
        DangerousPattern {
            name: "Connection without close",
            pattern: PatternKind::Missing("Connection.*close"),
            rule_id: "java/jdbc-unclosed-connection",
            severity: Severity::Error,
            description: "Connection should be closed to prevent pool exhaustion",
            cwe: Some("CWE-404"),
        },
        // SQL in log statements (information disclosure)
        DangerousPattern {
            name: "SQL in logs",
            pattern: PatternKind::Regex(r#"(log|LOG|Log)\.\w+\(.*sql"#),
            rule_id: "java/jdbc-sql-logging",
            severity: Severity::Warning,
            description: "Logging SQL queries may expose sensitive data",
            cwe: Some("CWE-532"),
        },
        // Hardcoded credentials in connection string
        DangerousPattern {
            name: "Hardcoded DB password",
            pattern: PatternKind::Regex(r#"getConnection\([^)]*password\s*="#),
            rule_id: "java/jdbc-hardcoded-credentials",
            severity: Severity::Critical,
            description: "Database credentials should not be hardcoded",
            cwe: Some("CWE-798"),
        },
    ],

    // =========================================================================
    // Resource Types - JDBC resources require careful lifecycle management
    // =========================================================================
    resource_types: &[
        ResourceType {
            name: "Connection",
            acquire_pattern: "getConnection() | DriverManager.getConnection()",
            release_pattern: "close()",
            leak_consequence: "Connection pool exhaustion, database connection limit reached, memory leak",
        },
        ResourceType {
            name: "Statement",
            acquire_pattern: "createStatement() | prepareStatement() | prepareCall()",
            release_pattern: "close()",
            leak_consequence: "Database cursor leak, memory leak, connection cannot be reused",
        },
        ResourceType {
            name: "PreparedStatement",
            acquire_pattern: "prepareStatement()",
            release_pattern: "close()",
            leak_consequence: "Database cursor leak, memory leak",
        },
        ResourceType {
            name: "CallableStatement",
            acquire_pattern: "prepareCall()",
            release_pattern: "close()",
            leak_consequence: "Database cursor leak, memory leak",
        },
        ResourceType {
            name: "ResultSet",
            acquire_pattern: "executeQuery() | getResultSet() | getGeneratedKeys()",
            release_pattern: "close()",
            leak_consequence: "Database cursor leak, may block other queries",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jdbc_detection() {
        assert!(JDBC_PROFILE.is_active("import java.sql.Connection;"));
        assert!(JDBC_PROFILE.is_active("import java.sql.*;"));
        assert!(JDBC_PROFILE.is_active("import javax.sql.DataSource;"));
        assert!(!JDBC_PROFILE.is_active("import org.springframework.jdbc;"));
    }

    #[test]
    fn test_jdbc_has_sql_injection_sinks() {
        assert!(!JDBC_PROFILE.sinks.is_empty());
        assert!(
            JDBC_PROFILE
                .sinks
                .iter()
                .any(|s| s.name.contains("execute"))
        );
    }

    #[test]
    fn test_jdbc_has_safe_patterns() {
        assert!(!JDBC_PROFILE.safe_patterns.is_empty());
        assert!(
            JDBC_PROFILE
                .safe_patterns
                .iter()
                .any(|p| p.name.contains("PreparedStatement"))
        );
    }

    #[test]
    fn test_jdbc_resource_types() {
        assert!(!JDBC_PROFILE.resource_types.is_empty());

        let resource_names: Vec<&str> =
            JDBC_PROFILE.resource_types.iter().map(|r| r.name).collect();
        assert!(resource_names.contains(&"Connection"));
        assert!(resource_names.contains(&"Statement"));
        assert!(resource_names.contains(&"PreparedStatement"));
        assert!(resource_names.contains(&"ResultSet"));
    }

    #[test]
    fn test_jdbc_dangerous_patterns() {
        assert!(!JDBC_PROFILE.dangerous_patterns.is_empty());
        assert!(
            JDBC_PROFILE
                .dangerous_patterns
                .iter()
                .any(|p| p.name.contains("concatenation"))
        );
    }
}
