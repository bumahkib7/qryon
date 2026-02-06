//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_BEEGO_UTILS_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_BEEGO_UTILS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "group:beego-utils.Display",
    pattern: SinkKind::FunctionCall("group:beego-utils.Display"),
    rule_id: "go/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: group:beego-utils..Display (kind: manual)",
    cwe: Some("CWE-74"),
}];

static GROUP_BEEGO_UTILS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_BEEGO_UTILS_GEN_IMPORTS: &[&str] = &["group:beego-utils"];

pub static GROUP_BEEGO_UTILS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:beego_utils_generated",
    description: "Generated profile for group:beego-utils from CodeQL/Pysa",
    detect_imports: GROUP_BEEGO_UTILS_GEN_IMPORTS,
    sources: GROUP_BEEGO_UTILS_GEN_SOURCES,
    sinks: GROUP_BEEGO_UTILS_GEN_SINKS,
    sanitizers: GROUP_BEEGO_UTILS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
