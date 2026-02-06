//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SQLITE3_GEN_SOURCES: &[SourceDef] = &[];

static SQLITE3_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "sqlite3.Cursor.execute",
        pattern: SinkKind::FunctionCall("sqlite3.Cursor.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlite3.Cursor.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlite3.Cursor.executemany",
        pattern: SinkKind::FunctionCall("sqlite3.Cursor.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlite3.Cursor.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlite3.Cursor.executescript",
        pattern: SinkKind::FunctionCall("sqlite3.Cursor.executescript"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlite3.Cursor.executescript (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlite3.Connection.execute",
        pattern: SinkKind::FunctionCall("sqlite3.Connection.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlite3.Connection.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlite3.Connection.executemany",
        pattern: SinkKind::FunctionCall("sqlite3.Connection.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlite3.Connection.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlite3.Connection.executescript",
        pattern: SinkKind::FunctionCall("sqlite3.Connection.executescript"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlite3.Connection.executescript (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static SQLITE3_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SQLITE3_GEN_IMPORTS: &[&str] = &["sqlite3"];

pub static SQLITE3_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "sqlite3_generated",
    description: "Generated profile for sqlite3 from CodeQL/Pysa",
    detect_imports: SQLITE3_GEN_IMPORTS,
    sources: SQLITE3_GEN_SOURCES,
    sinks: SQLITE3_GEN_SINKS,
    sanitizers: SQLITE3_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
