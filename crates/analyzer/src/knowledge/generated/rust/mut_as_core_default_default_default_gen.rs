//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<*mut as core::default::Default>::default.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SINKS: &[SinkDef] = &[];

static MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_IMPORTS: &[&str] =
    &["<*mut as core::default::Default>::default"];

pub static MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<*mut as core::default::default>::default_generated",
    description: "Generated profile for <*mut as core::default::Default>::default from CodeQL/Pysa",
    detect_imports: MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_IMPORTS,
    sources: MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SOURCES,
    sinks: MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SINKS,
    sanitizers: MUT_AS_CORE_DEFAULT_DEFAULT_DEFAULT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
