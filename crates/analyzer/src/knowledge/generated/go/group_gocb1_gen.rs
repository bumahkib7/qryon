//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_GOCB1_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "group:gocb1.Cluster.ExecuteAnalyticsQuery",
        pattern: SourceKind::MemberAccess("group:gocb1.Cluster.ExecuteAnalyticsQuery"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb1.Cluster.ExecuteAnalyticsQuery (kind: manual)",
    },
    SourceDef {
        name: "group:gocb1.Cluster.ExecuteN1qlQuery",
        pattern: SourceKind::MemberAccess("group:gocb1.Cluster.ExecuteN1qlQuery"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb1.Cluster.ExecuteN1qlQuery (kind: manual)",
    },
    SourceDef {
        name: "group:gocb1.Cluster.ExecuteSearchQuery",
        pattern: SourceKind::MemberAccess("group:gocb1.Cluster.ExecuteSearchQuery"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb1.Cluster.ExecuteSearchQuery (kind: manual)",
    },
];

static GROUP_GOCB1_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:gocb1.Bucket.ExecuteN1qlQuery",
        pattern: SinkKind::FunctionCall("group:gocb1.Bucket.ExecuteN1qlQuery"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb1.Bucket.ExecuteN1qlQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gocb1.Bucket.ExecuteAnalyticsQuery",
        pattern: SinkKind::FunctionCall("group:gocb1.Bucket.ExecuteAnalyticsQuery"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb1.Bucket.ExecuteAnalyticsQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gocb1.Cluster.ExecuteN1qlQuery",
        pattern: SinkKind::FunctionCall("group:gocb1.Cluster.ExecuteN1qlQuery"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb1.Cluster.ExecuteN1qlQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gocb1.Cluster.ExecuteAnalyticsQuery",
        pattern: SinkKind::FunctionCall("group:gocb1.Cluster.ExecuteAnalyticsQuery"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb1.Cluster.ExecuteAnalyticsQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_GOCB1_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_GOCB1_GEN_IMPORTS: &[&str] = &["group:gocb1"];

pub static GROUP_GOCB1_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:gocb1_generated",
    description: "Generated profile for group:gocb1 from CodeQL/Pysa",
    detect_imports: GROUP_GOCB1_GEN_IMPORTS,
    sources: GROUP_GOCB1_GEN_SOURCES,
    sinks: GROUP_GOCB1_GEN_SINKS,
    sanitizers: GROUP_GOCB1_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
