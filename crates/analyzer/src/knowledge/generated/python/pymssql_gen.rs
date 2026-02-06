//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PYMSSQL_GEN_SOURCES: &[SourceDef] = &[];

static PYMSSQL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "pymssql.Cursor.execute",
        pattern: SinkKind::FunctionCall("pymssql.Cursor.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: pymssql.Cursor.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "pymssql.Cursor.executemany",
        pattern: SinkKind::FunctionCall("pymssql.Cursor.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: pymssql.Cursor.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static PYMSSQL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PYMSSQL_GEN_IMPORTS: &[&str] = &["pymssql"];

pub static PYMSSQL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pymssql_generated",
    description: "Generated profile for pymssql from CodeQL/Pysa",
    detect_imports: PYMSSQL_GEN_IMPORTS,
    sources: PYMSSQL_GEN_SOURCES,
    sinks: PYMSSQL_GEN_SINKS,
    sanitizers: PYMSSQL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
