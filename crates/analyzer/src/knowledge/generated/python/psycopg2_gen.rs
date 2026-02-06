//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PSYCOPG2_GEN_SOURCES: &[SourceDef] = &[];

static PSYCOPG2_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "psycopg2._psycopg.cursor.execute",
        pattern: SinkKind::FunctionCall("psycopg2._psycopg.cursor.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: psycopg2._psycopg.cursor.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "psycopg2._psycopg.cursor.executemany",
        pattern: SinkKind::FunctionCall("psycopg2._psycopg.cursor.executemany"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: psycopg2._psycopg.cursor.executemany (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static PSYCOPG2_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PSYCOPG2_GEN_IMPORTS: &[&str] = &["psycopg2"];

pub static PSYCOPG2_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "psycopg2_generated",
    description: "Generated profile for psycopg2 from CodeQL/Pysa",
    detect_imports: PSYCOPG2_GEN_IMPORTS,
    sources: PSYCOPG2_GEN_SOURCES,
    sinks: PSYCOPG2_GEN_SINKS,
    sanitizers: PSYCOPG2_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
