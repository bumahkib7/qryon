//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SQLALCHEMY_GEN_SOURCES: &[SourceDef] = &[];

static SQLALCHEMY_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "sqlalchemy.engine.base.Engine.execute",
        pattern: SinkKind::FunctionCall("sqlalchemy.engine.base.Engine.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlalchemy.engine.base.Engine.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlalchemy.engine.base.Engine.scalar",
        pattern: SinkKind::FunctionCall("sqlalchemy.engine.base.Engine.scalar"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlalchemy.engine.base.Engine.scalar (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlalchemy.engine.base.Connection.execute",
        pattern: SinkKind::FunctionCall("sqlalchemy.engine.base.Connection.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlalchemy.engine.base.Connection.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlalchemy.engine.base.Connection.scalar",
        pattern: SinkKind::FunctionCall("sqlalchemy.engine.base.Connection.scalar"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlalchemy.engine.base.Connection.scalar (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlalchemy.engine.interfaces.Connectable.execute",
        pattern: SinkKind::FunctionCall("sqlalchemy.engine.interfaces.Connectable.execute"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlalchemy.engine.interfaces.Connectable.execute (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "sqlalchemy.engine.interfaces.Connectable.scalar",
        pattern: SinkKind::FunctionCall("sqlalchemy.engine.interfaces.Connectable.scalar"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: sqlalchemy.engine.interfaces.Connectable.scalar (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static SQLALCHEMY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SQLALCHEMY_GEN_IMPORTS: &[&str] = &["sqlalchemy"];

pub static SQLALCHEMY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "sqlalchemy_generated",
    description: "Generated profile for sqlalchemy from CodeQL/Pysa",
    detect_imports: SQLALCHEMY_GEN_IMPORTS,
    sources: SQLALCHEMY_GEN_SOURCES,
    sinks: SQLALCHEMY_GEN_SINKS,
    sanitizers: SQLALCHEMY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
