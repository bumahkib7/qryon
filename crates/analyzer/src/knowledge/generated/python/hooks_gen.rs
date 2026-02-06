//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HOOKS_GEN_SOURCES: &[SourceDef] = &[];

static HOOKS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "hooks",
    pattern: SinkKind::FunctionCall("hooks"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: hooks (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static HOOKS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HOOKS_GEN_IMPORTS: &[&str] = &["hooks"];

pub static HOOKS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "hooks_generated",
    description: "Generated profile for hooks from CodeQL/Pysa",
    detect_imports: HOOKS_GEN_IMPORTS,
    sources: HOOKS_GEN_SOURCES,
    sinks: HOOKS_GEN_SINKS,
    sanitizers: HOOKS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
