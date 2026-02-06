//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PYMYSQL_GEN_SOURCES: &[SourceDef] = &[];

static PYMYSQL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "pymysql.cursors.Cursor.execute",
        pattern: SinkKind::FunctionCall("pymysql.cursors.Cursor.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: pymysql.cursors.Cursor.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "pymysql.cursors.Cursor.executemany",
        pattern: SinkKind::FunctionCall("pymysql.cursors.Cursor.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: pymysql.cursors.Cursor.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static PYMYSQL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PYMYSQL_GEN_IMPORTS: &[&str] = &["pymysql"];

pub static PYMYSQL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pymysql_generated",
    description: "Generated profile for pymysql from CodeQL/Pysa",
    detect_imports: PYMYSQL_GEN_IMPORTS,
    sources: PYMYSQL_GEN_SOURCES,
    sinks: PYMYSQL_GEN_SINKS,
    sanitizers: PYMYSQL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
