//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_BEEGO_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "group:beego.Controller.ParseForm",
        pattern: SourceKind::MemberAccess("group:beego.Controller.ParseForm"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego.Controller.ParseForm (kind: manual)",
    },
    SourceDef {
        name: "group:beego.Controller.GetFile",
        pattern: SourceKind::MemberAccess("group:beego.Controller.GetFile"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego.Controller.GetFile (kind: manual)",
    },
    SourceDef {
        name: "group:beego.Controller.GetFiles",
        pattern: SourceKind::MemberAccess("group:beego.Controller.GetFiles"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego.Controller.GetFiles (kind: manual)",
    },
    SourceDef {
        name: "group:beego.Controller.GetString",
        pattern: SourceKind::MemberAccess("group:beego.Controller.GetString"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego.Controller.GetString (kind: manual)",
    },
    SourceDef {
        name: "group:beego.Controller.GetStrings",
        pattern: SourceKind::MemberAccess("group:beego.Controller.GetStrings"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego.Controller.GetStrings (kind: manual)",
    },
    SourceDef {
        name: "group:beego.Controller.Input",
        pattern: SourceKind::MemberAccess("group:beego.Controller.Input"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego.Controller.Input (kind: manual)",
    },
];

static GROUP_BEEGO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:beego.Alert",
        pattern: SinkKind::FunctionCall("group:beego.Alert"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Alert (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Critical",
        pattern: SinkKind::FunctionCall("group:beego.Critical"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Critical (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Debug",
        pattern: SinkKind::FunctionCall("group:beego.Debug"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Debug (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Emergency",
        pattern: SinkKind::FunctionCall("group:beego.Emergency"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Emergency (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Error",
        pattern: SinkKind::FunctionCall("group:beego.Error"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Error (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Info",
        pattern: SinkKind::FunctionCall("group:beego.Info"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Info (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Informational",
        pattern: SinkKind::FunctionCall("group:beego.Informational"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Informational (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Notice",
        pattern: SinkKind::FunctionCall("group:beego.Notice"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Notice (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Trace",
        pattern: SinkKind::FunctionCall("group:beego.Trace"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Trace (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Warn",
        pattern: SinkKind::FunctionCall("group:beego.Warn"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Warn (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Warning",
        pattern: SinkKind::FunctionCall("group:beego.Warning"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Warning (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Walk",
        pattern: SinkKind::FunctionCall("group:beego.Walk"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego..Walk (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Controller.SaveToFile",
        pattern: SinkKind::FunctionCall("group:beego.Controller.SaveToFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego.Controller.SaveToFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Controller.SaveToFileWithBuffer",
        pattern: SinkKind::FunctionCall("group:beego.Controller.SaveToFileWithBuffer"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego.Controller.SaveToFileWithBuffer (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.FileSystem.Open",
        pattern: SinkKind::FunctionCall("group:beego.FileSystem.Open"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego.FileSystem.Open (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego.Controller.Redirect",
        pattern: SinkKind::FunctionCall("group:beego.Controller.Redirect"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego.Controller.Redirect (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_BEEGO_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "group:beego.Htmlquote",
        pattern: SanitizerKind::Function("group:beego..Htmlquote"),
        sanitizes: "html",
        description: "CodeQL sanitizer: group:beego..Htmlquote",
    },
    SanitizerDef {
        name: "group:beego.Htmlunquote",
        pattern: SanitizerKind::Function("group:beego..Htmlunquote"),
        sanitizes: "html",
        description: "CodeQL sanitizer: group:beego..Htmlunquote",
    },
];

static GROUP_BEEGO_GEN_IMPORTS: &[&str] = &["group:beego"];

pub static GROUP_BEEGO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:beego_generated",
    description: "Generated profile for group:beego from CodeQL/Pysa",
    detect_imports: GROUP_BEEGO_GEN_IMPORTS,
    sources: GROUP_BEEGO_GEN_SOURCES,
    sinks: GROUP_BEEGO_GEN_SINKS,
    sanitizers: GROUP_BEEGO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
