//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYSQL_GEN_SOURCES: &[SourceDef] = &[];

static MYSQL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "mysql.connector.abstracts.MySQLCursorAbstract.execute",
        pattern: SinkKind::FunctionCall("mysql.connector.abstracts.MySQLCursorAbstract.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.abstracts.MySQLCursorAbstract.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.abstracts.MySQLCursorAbstract.executemany",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.abstracts.MySQLCursorAbstract.executemany",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.abstracts.MySQLCursorAbstract.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.abstracts.MySQLConnectionAbstract.cmd_query",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.abstracts.MySQLConnectionAbstract.cmd_query",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.abstracts.MySQLConnectionAbstract.cmd_query (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.abstracts.MySQLConnectionAbstract.cmd_query_iter",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.abstracts.MySQLConnectionAbstract.cmd_query_iter",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.abstracts.MySQLConnectionAbstract.cmd_query_iter (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.abstracts.MySQLConnectionAbstract.info_query",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.abstracts.MySQLConnectionAbstract.info_query",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.abstracts.MySQLConnectionAbstract.info_query (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.abstracts.MySQLConnectionAbstract.cmd_stmt_prepare",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.abstracts.MySQLConnectionAbstract.cmd_stmt_prepare",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.abstracts.MySQLConnectionAbstract.cmd_stmt_prepare (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.connection.MySQLConnection.cmd_query",
        pattern: SinkKind::FunctionCall("mysql.connector.connection.MySQLConnection.cmd_query"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.connection.MySQLConnection.cmd_query (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.connection.MySQLConnection.cmd_query_iter",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.connection.MySQLConnection.cmd_query_iter",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.connection.MySQLConnection.cmd_query_iter (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.connection.MySQLConnection.info_query",
        pattern: SinkKind::FunctionCall("mysql.connector.connection.MySQLConnection.info_query"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.connection.MySQLConnection.info_query (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.connection.MySQLConnection.cmd_stmt_prepare",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.connection.MySQLConnection.cmd_stmt_prepare",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.connection.MySQLConnection.cmd_stmt_prepare (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.connection_cext.CMySQLConnection.cmd_query",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.connection_cext.CMySQLConnection.cmd_query",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.connection_cext.CMySQLConnection.cmd_query (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mysql.connector.connection_cext.CMySQLConnection.info_query",
        pattern: SinkKind::FunctionCall(
            "mysql.connector.connection_cext.CMySQLConnection.info_query",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mysql.connector.connection_cext.CMySQLConnection.info_query (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static MYSQL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYSQL_GEN_IMPORTS: &[&str] = &["mysql"];

pub static MYSQL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mysql_generated",
    description: "Generated profile for mysql from CodeQL/Pysa",
    detect_imports: MYSQL_GEN_IMPORTS,
    sources: MYSQL_GEN_SOURCES,
    sinks: MYSQL_GEN_SINKS,
    sanitizers: MYSQL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
