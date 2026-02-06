//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LIQUIBASE_GEN_SOURCES: &[SourceDef] = &[];

static LIQUIBASE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "liquibase.statement.core.RawSqlStatement.RawSqlStatement",
        pattern: SinkKind::FunctionCall("liquibase.statement.core.RawSqlStatement.RawSqlStatement"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: liquibase.statement.core.RawSqlStatement.RawSqlStatement (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "liquibase.database.jvm.JdbcConnection.prepareStatement",
        pattern: SinkKind::FunctionCall("liquibase.database.jvm.JdbcConnection.prepareStatement"),
        rule_id: "java/gen-ai-manual",
        severity: Severity::Error,
        description: "CodeQL sink: liquibase.database.jvm.JdbcConnection.prepareStatement (kind: ai-manual)",
        cwe: Some("CWE-74"),
    },
];

static LIQUIBASE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LIQUIBASE_GEN_IMPORTS: &[&str] = &["liquibase.statement.core", "liquibase.database.jvm"];

pub static LIQUIBASE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "liquibase_generated",
    description: "Generated profile for liquibase.statement.core from CodeQL/Pysa",
    detect_imports: LIQUIBASE_GEN_IMPORTS,
    sources: LIQUIBASE_GEN_SOURCES,
    sinks: LIQUIBASE_GEN_SINKS,
    sanitizers: LIQUIBASE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
