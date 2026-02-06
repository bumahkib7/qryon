//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_BEEGO_LOGS_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_BEEGO_LOGS_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:beego-logs.Alert",
        pattern: SinkKind::FunctionCall("group:beego-logs.Alert"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Alert (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Critical",
        pattern: SinkKind::FunctionCall("group:beego-logs.Critical"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Critical (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Debug",
        pattern: SinkKind::FunctionCall("group:beego-logs.Debug"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Debug (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Emergency",
        pattern: SinkKind::FunctionCall("group:beego-logs.Emergency"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Emergency (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Error",
        pattern: SinkKind::FunctionCall("group:beego-logs.Error"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Error (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Info",
        pattern: SinkKind::FunctionCall("group:beego-logs.Info"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Info (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Informational",
        pattern: SinkKind::FunctionCall("group:beego-logs.Informational"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Informational (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Notice",
        pattern: SinkKind::FunctionCall("group:beego-logs.Notice"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Notice (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Trace",
        pattern: SinkKind::FunctionCall("group:beego-logs.Trace"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Trace (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Warn",
        pattern: SinkKind::FunctionCall("group:beego-logs.Warn"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Warn (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.Warning",
        pattern: SinkKind::FunctionCall("group:beego-logs.Warning"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs..Warning (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Alert",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Alert"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Alert (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Critical",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Critical"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Critical (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Debug",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Debug"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Debug (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Emergency",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Emergency"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Emergency (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Error",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Error"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Error (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Info",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Info"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Info (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Informational",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Informational"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Informational (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Notice",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Notice"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Notice (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Trace",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Trace"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Trace (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Warn",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Warn"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Warn (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-logs.BeeLogger.Warning",
        pattern: SinkKind::FunctionCall("group:beego-logs.BeeLogger.Warning"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-logs.BeeLogger.Warning (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_BEEGO_LOGS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_BEEGO_LOGS_GEN_IMPORTS: &[&str] = &["group:beego-logs"];

pub static GROUP_BEEGO_LOGS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:beego_logs_generated",
    description: "Generated profile for group:beego-logs from CodeQL/Pysa",
    detect_imports: GROUP_BEEGO_LOGS_GEN_IMPORTS,
    sources: GROUP_BEEGO_LOGS_GEN_SOURCES,
    sinks: GROUP_BEEGO_LOGS_GEN_SINKS,
    sanitizers: GROUP_BEEGO_LOGS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
