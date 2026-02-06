//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_IRIS_CONTEXT_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_IRIS_CONTEXT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:iris-context.Context.SendFile",
        pattern: SinkKind::FunctionCall("group:iris-context.Context.SendFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:iris-context.Context.SendFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:iris-context.Context.ServeFile",
        pattern: SinkKind::FunctionCall("group:iris-context.Context.ServeFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:iris-context.Context.ServeFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:iris-context.Context.SendFileWithRate",
        pattern: SinkKind::FunctionCall("group:iris-context.Context.SendFileWithRate"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:iris-context.Context.SendFileWithRate (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:iris-context.Context.ServeFileWithRate",
        pattern: SinkKind::FunctionCall("group:iris-context.Context.ServeFileWithRate"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:iris-context.Context.ServeFileWithRate (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:iris-context.Context.UploadFormFiles",
        pattern: SinkKind::FunctionCall("group:iris-context.Context.UploadFormFiles"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:iris-context.Context.UploadFormFiles (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:iris-context.Context.SaveFormFile",
        pattern: SinkKind::FunctionCall("group:iris-context.Context.SaveFormFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:iris-context.Context.SaveFormFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_IRIS_CONTEXT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_IRIS_CONTEXT_GEN_IMPORTS: &[&str] = &["group:iris-context"];

pub static GROUP_IRIS_CONTEXT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:iris_context_generated",
    description: "Generated profile for group:iris-context from CodeQL/Pysa",
    detect_imports: GROUP_IRIS_CONTEXT_GEN_IMPORTS,
    sources: GROUP_IRIS_CONTEXT_GEN_SOURCES,
    sinks: GROUP_IRIS_CONTEXT_GEN_SINKS,
    sanitizers: GROUP_IRIS_CONTEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
