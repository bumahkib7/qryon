//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static NHIBERNATE_GEN_SOURCES: &[SourceDef] = &[];

static NHIBERNATE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "NHibernate.ISession.CreateSQLQuery",
        pattern: SinkKind::FunctionCall("NHibernate.ISession.CreateSQLQuery"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: NHibernate.ISession.CreateSQLQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "NHibernate.IStatelessSession.CreateSQLQuery",
        pattern: SinkKind::FunctionCall("NHibernate.IStatelessSession.CreateSQLQuery"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: NHibernate.IStatelessSession.CreateSQLQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "NHibernate.Impl.AbstractSessionImpl.CreateSQLQuery",
        pattern: SinkKind::FunctionCall("NHibernate.Impl.AbstractSessionImpl.CreateSQLQuery"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: NHibernate.Impl.AbstractSessionImpl.CreateSQLQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static NHIBERNATE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static NHIBERNATE_GEN_IMPORTS: &[&str] = &["NHibernate", "NHibernate.Impl"];

pub static NHIBERNATE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "nhibernate_generated",
    description: "Generated profile for NHibernate from CodeQL/Pysa",
    detect_imports: NHIBERNATE_GEN_IMPORTS,
    sources: NHIBERNATE_GEN_SOURCES,
    sinks: NHIBERNATE_GEN_SINKS,
    sanitizers: NHIBERNATE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
