//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_SLICE_ROTATE_PTR_ROTATE_GEN_SOURCES: &[SourceDef] = &[];

static CORE_SLICE_ROTATE_PTR_ROTATE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "core::slice::rotate::ptr_rotate.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[1] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static CORE_SLICE_ROTATE_PTR_ROTATE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_SLICE_ROTATE_PTR_ROTATE_GEN_IMPORTS: &[&str] = &["core::slice::rotate::ptr_rotate"];

pub static CORE_SLICE_ROTATE_PTR_ROTATE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "core::slice::rotate::ptr_rotate_generated",
    description: "Generated profile for core::slice::rotate::ptr_rotate from CodeQL/Pysa",
    detect_imports: CORE_SLICE_ROTATE_PTR_ROTATE_GEN_IMPORTS,
    sources: CORE_SLICE_ROTATE_PTR_ROTATE_GEN_SOURCES,
    sinks: CORE_SLICE_ROTATE_PTR_ROTATE_GEN_SINKS,
    sanitizers: CORE_SLICE_ROTATE_PTR_ROTATE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
