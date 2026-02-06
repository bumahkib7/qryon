//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_GOCB2_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "group:gocb2.Cluster.AnalyticsQuery",
        pattern: SourceKind::MemberAccess("group:gocb2.Cluster.AnalyticsQuery"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Cluster.AnalyticsQuery (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Cluster.Query",
        pattern: SourceKind::MemberAccess("group:gocb2.Cluster.Query"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Cluster.Query (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.Get",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.Get"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.Get (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.GetAndLock",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.GetAndLock"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.GetAndLock (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.GetAndTouch",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.GetAndTouch"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.GetAndTouch (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.GetAnyReplica",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.GetAnyReplica"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.GetAnyReplica (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.LookupIn",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.LookupIn"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.LookupIn (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.LookupInAllReplicas",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.LookupInAllReplicas"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.LookupInAllReplicas (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.LookupInAnyReplica",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.LookupInAnyReplica"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.LookupInAnyReplica (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Collection.Scan",
        pattern: SourceKind::MemberAccess("group:gocb2.Collection.Scan"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Collection.Scan (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Scope.AnalyticsQuery",
        pattern: SourceKind::MemberAccess("group:gocb2.Scope.AnalyticsQuery"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Scope.AnalyticsQuery (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.Scope.Query",
        pattern: SourceKind::MemberAccess("group:gocb2.Scope.Query"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.Scope.Query (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.TransactionAttemptContext.Get",
        pattern: SourceKind::MemberAccess("group:gocb2.TransactionAttemptContext.Get"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.TransactionAttemptContext.Get (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.TransactionAttemptContext.GetReplicaFromPreferredServerGroup",
        pattern: SourceKind::MemberAccess(
            "group:gocb2.TransactionAttemptContext.GetReplicaFromPreferredServerGroup",
        ),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.TransactionAttemptContext.GetReplicaFromPreferredServerGroup (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.TransactionAttemptContext.Insert",
        pattern: SourceKind::MemberAccess("group:gocb2.TransactionAttemptContext.Insert"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.TransactionAttemptContext.Insert (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.TransactionAttemptContext.Query",
        pattern: SourceKind::MemberAccess("group:gocb2.TransactionAttemptContext.Query"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.TransactionAttemptContext.Query (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.TransactionAttemptContext.Replace",
        pattern: SourceKind::MemberAccess("group:gocb2.TransactionAttemptContext.Replace"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.TransactionAttemptContext.Replace (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.ViewIndexManager.GetAllDesignDocuments",
        pattern: SourceKind::MemberAccess("group:gocb2.ViewIndexManager.GetAllDesignDocuments"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.ViewIndexManager.GetAllDesignDocuments (kind: manual)",
    },
    SourceDef {
        name: "group:gocb2.ViewIndexManager.GetDesignDocument",
        pattern: SourceKind::MemberAccess("group:gocb2.ViewIndexManager.GetDesignDocument"),
        taint_label: "user_input",
        description: "CodeQL source: group:gocb2.ViewIndexManager.GetDesignDocument (kind: manual)",
    },
];

static GROUP_GOCB2_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:gocb2.Cluster.AnalyticsQuery",
        pattern: SinkKind::FunctionCall("group:gocb2.Cluster.AnalyticsQuery"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb2.Cluster.AnalyticsQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gocb2.Cluster.Query",
        pattern: SinkKind::FunctionCall("group:gocb2.Cluster.Query"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb2.Cluster.Query (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gocb2.Scope.AnalyticsQuery",
        pattern: SinkKind::FunctionCall("group:gocb2.Scope.AnalyticsQuery"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb2.Scope.AnalyticsQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gocb2.Scope.Query",
        pattern: SinkKind::FunctionCall("group:gocb2.Scope.Query"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gocb2.Scope.Query (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_GOCB2_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_GOCB2_GEN_IMPORTS: &[&str] = &["group:gocb2"];

pub static GROUP_GOCB2_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:gocb2_generated",
    description: "Generated profile for group:gocb2 from CodeQL/Pysa",
    detect_imports: GROUP_GOCB2_GEN_IMPORTS,
    sources: GROUP_GOCB2_GEN_SOURCES,
    sinks: GROUP_GOCB2_GEN_SINKS,
    sanitizers: GROUP_GOCB2_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
