//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<*const as core::default::Default>::default.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SINKS: &[SinkDef] = &[];

static CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_IMPORTS: &[&str] =
    &["<*const as core::default::Default>::default"];

pub static CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<*const as core::default::default>::default_generated",
    description: "Generated profile for <*const as core::default::Default>::default from CodeQL/Pysa",
    detect_imports: CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_IMPORTS,
    sources: CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SOURCES,
    sinks: CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SINKS,
    sanitizers: CONST_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
