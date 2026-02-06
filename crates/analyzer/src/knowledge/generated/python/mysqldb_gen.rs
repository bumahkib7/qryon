//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYSQLDB_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "MySQLdb.cursors.BaseCursor.execute",
        pattern: SourceKind::MemberAccess("MySQLdb.cursors.BaseCursor.execute"),
        taint_label: "user_input",
        description: "Pysa source: MySQLdb.cursors.BaseCursor.execute (kind: SQLControlled)",
    },
    SourceDef {
        name: "MySQLdb.cursors.BaseCursor.executemany",
        pattern: SourceKind::MemberAccess("MySQLdb.cursors.BaseCursor.executemany"),
        taint_label: "user_input",
        description: "Pysa source: MySQLdb.cursors.BaseCursor.executemany (kind: SQLControlled)",
    },
];

static MYSQLDB_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "MySQLdb.cursors.BaseCursor.execute",
        pattern: SinkKind::FunctionCall("MySQLdb.cursors.BaseCursor.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: MySQLdb.cursors.BaseCursor.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "MySQLdb.cursors.BaseCursor.executemany",
        pattern: SinkKind::FunctionCall("MySQLdb.cursors.BaseCursor.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: MySQLdb.cursors.BaseCursor.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "MySQLdb.cursors.BaseCursor.callproc",
        pattern: SinkKind::FunctionCall("MySQLdb.cursors.BaseCursor.callproc"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: MySQLdb.cursors.BaseCursor.callproc (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static MYSQLDB_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYSQLDB_GEN_IMPORTS: &[&str] = &["MySQLdb"];

pub static MYSQLDB_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mysqldb_generated",
    description: "Generated profile for MySQLdb from CodeQL/Pysa",
    detect_imports: MYSQLDB_GEN_IMPORTS,
    sources: MYSQLDB_GEN_SOURCES,
    sinks: MYSQLDB_GEN_SINKS,
    sanitizers: MYSQLDB_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
