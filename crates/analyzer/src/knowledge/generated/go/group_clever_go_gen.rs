//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_CLEVER_GO_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_CLEVER_GO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "group:clever-go.Context.Redirect",
    pattern: SinkKind::FunctionCall("group:clever-go.Context.Redirect"),
    rule_id: "go/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: group:clever-go.Context.Redirect (kind: manual)",
    cwe: Some("CWE-74"),
}];

static GROUP_CLEVER_GO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_CLEVER_GO_GEN_IMPORTS: &[&str] = &["group:clever-go"];

pub static GROUP_CLEVER_GO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:clever_go_generated",
    description: "Generated profile for group:clever-go from CodeQL/Pysa",
    detect_imports: GROUP_CLEVER_GO_GEN_IMPORTS,
    sources: GROUP_CLEVER_GO_GEN_SOURCES,
    sinks: GROUP_CLEVER_GO_GEN_SINKS,
    sanitizers: GROUP_CLEVER_GO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
