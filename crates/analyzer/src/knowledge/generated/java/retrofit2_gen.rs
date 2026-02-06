//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RETROFIT2_GEN_SOURCES: &[SourceDef] = &[];

static RETROFIT2_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "retrofit2.Retrofit$Builder.baseUrl",
    pattern: SinkKind::FunctionCall("retrofit2.Retrofit$Builder.baseUrl"),
    rule_id: "java/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: retrofit2.Retrofit$Builder.baseUrl (kind: manual)",
    cwe: Some("CWE-74"),
}];

static RETROFIT2_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RETROFIT2_GEN_IMPORTS: &[&str] = &["retrofit2"];

pub static RETROFIT2_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "retrofit2_generated",
    description: "Generated profile for retrofit2 from CodeQL/Pysa",
    detect_imports: RETROFIT2_GEN_IMPORTS,
    sources: RETROFIT2_GEN_SOURCES,
    sinks: RETROFIT2_GEN_SINKS,
    sanitizers: RETROFIT2_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
