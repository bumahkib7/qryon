//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<hyper::common::buf::BufList>::push.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_IMPORTS: &[&str] =
    &["<hyper::common::buf::BufList>::push"];

pub static HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<hyper::common::buf::buflist>::push_generated",
    description: "Generated profile for <hyper::common::buf::BufList>::push from CodeQL/Pysa",
    detect_imports: HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_IMPORTS,
    sources: HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_SOURCES,
    sinks: HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_SINKS,
    sanitizers: HYPER_COMMON_BUF_BUFLIST_PUSH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
