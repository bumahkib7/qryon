//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AS_TOWER_SERVICE_SERVICE_CALL_GEN_SOURCES: &[SourceDef] = &[];

static AS_TOWER_SERVICE_SERVICE_CALL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<& as tower_service::Service>::call.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static AS_TOWER_SERVICE_SERVICE_CALL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AS_TOWER_SERVICE_SERVICE_CALL_GEN_IMPORTS: &[&str] =
    &["<& as tower_service::Service>::call"];

pub static AS_TOWER_SERVICE_SERVICE_CALL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<& as tower_service::service>::call_generated",
    description: "Generated profile for <& as tower_service::Service>::call from CodeQL/Pysa",
    detect_imports: AS_TOWER_SERVICE_SERVICE_CALL_GEN_IMPORTS,
    sources: AS_TOWER_SERVICE_SERVICE_CALL_GEN_SOURCES,
    sinks: AS_TOWER_SERVICE_SERVICE_CALL_GEN_SINKS,
    sanitizers: AS_TOWER_SERVICE_SERVICE_CALL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
