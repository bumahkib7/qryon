//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_GORM_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "group:gorm.Association.Find",
        pattern: SourceKind::MemberAccess("group:gorm.Association.Find"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.Association.Find (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.ConnPool.QueryContext",
        pattern: SourceKind::MemberAccess("group:gorm.ConnPool.QueryContext"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.ConnPool.QueryContext (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.ConnPool.QueryRowContext",
        pattern: SourceKind::MemberAccess("group:gorm.ConnPool.QueryRowContext"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.ConnPool.QueryRowContext (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Find",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Find"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Find (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.FindInBatches",
        pattern: SourceKind::MemberAccess("group:gorm.DB.FindInBatches"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.FindInBatches (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.First",
        pattern: SourceKind::MemberAccess("group:gorm.DB.First"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.First (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.FirstOrCreate",
        pattern: SourceKind::MemberAccess("group:gorm.DB.FirstOrCreate"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.FirstOrCreate (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.FirstOrInit",
        pattern: SourceKind::MemberAccess("group:gorm.DB.FirstOrInit"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.FirstOrInit (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Last",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Last"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Last (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Model",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Model"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Model (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Pluck",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Pluck"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Pluck (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Row",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Row"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Row (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Rows",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Rows"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Rows (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Scan",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Scan"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Scan (kind: manual)",
    },
    SourceDef {
        name: "group:gorm.DB.Take",
        pattern: SourceKind::MemberAccess("group:gorm.DB.Take"),
        taint_label: "user_input",
        description: "CodeQL source: group:gorm.DB.Take (kind: manual)",
    },
];

static GROUP_GORM_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:gorm.DB.Where",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Where"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Where (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Raw",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Raw"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Raw (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Order",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Order"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Order (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Not",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Not"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Not (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Or",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Or"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Or (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Select",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Select"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Select (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Table",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Table"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Table (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Group",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Group"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Group (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Having",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Having"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Having (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Joins",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Joins"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Joins (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Exec",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Exec"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Exec (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Distinct",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Distinct"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Distinct (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gorm.DB.Pluck",
        pattern: SinkKind::FunctionCall("group:gorm.DB.Pluck"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gorm.DB.Pluck (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_GORM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_GORM_GEN_IMPORTS: &[&str] = &["group:gorm"];

pub static GROUP_GORM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:gorm_generated",
    description: "Generated profile for group:gorm from CodeQL/Pysa",
    detect_imports: GROUP_GORM_GEN_IMPORTS,
    sources: GROUP_GORM_GEN_SOURCES,
    sinks: GROUP_GORM_GEN_SINKS,
    sanitizers: GROUP_GORM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
