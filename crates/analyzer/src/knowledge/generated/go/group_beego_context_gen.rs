//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_BEEGO_CONTEXT_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "group:beego-context.BeegoInput.Bind",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Bind"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Bind (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Cookie",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Cookie"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Cookie (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Data",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Data"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Data (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.GetData",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.GetData"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.GetData (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Header",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Header"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Header (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Param",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Param"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Param (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Params",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Params"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Params (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Query",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Query"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Query (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Refer",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Refer"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Refer (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.Referer",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.Referer"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.Referer (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.RequestBody",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.RequestBody"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.RequestBody (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.URI",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.URI"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.URI (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.URL",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.URL"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.URL (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.BeegoInput.UserAgent",
        pattern: SourceKind::MemberAccess("group:beego-context.BeegoInput.UserAgent"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.BeegoInput.UserAgent (kind: manual)",
    },
    SourceDef {
        name: "group:beego-context.Context.GetCookie",
        pattern: SourceKind::MemberAccess("group:beego-context.Context.GetCookie"),
        taint_label: "user_input",
        description: "CodeQL source: group:beego-context.Context.GetCookie (kind: manual)",
    },
];

static GROUP_BEEGO_CONTEXT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:beego-context.BeegoOutput.Download",
        pattern: SinkKind::FunctionCall("group:beego-context.BeegoOutput.Download"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-context.BeegoOutput.Download (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:beego-context.Context.Redirect",
        pattern: SinkKind::FunctionCall("group:beego-context.Context.Redirect"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:beego-context.Context.Redirect (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_BEEGO_CONTEXT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_BEEGO_CONTEXT_GEN_IMPORTS: &[&str] = &["group:beego-context"];

pub static GROUP_BEEGO_CONTEXT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:beego_context_generated",
    description: "Generated profile for group:beego-context from CodeQL/Pysa",
    detect_imports: GROUP_BEEGO_CONTEXT_GEN_IMPORTS,
    sources: GROUP_BEEGO_CONTEXT_GEN_SOURCES,
    sinks: GROUP_BEEGO_CONTEXT_GEN_SINKS,
    sanitizers: GROUP_BEEGO_CONTEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
