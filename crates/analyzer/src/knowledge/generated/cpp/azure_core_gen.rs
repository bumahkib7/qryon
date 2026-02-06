//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AZURE_CORE_GEN_SOURCES: &[SourceDef] = &[];

static AZURE_CORE_GEN_SINKS: &[SinkDef] = &[];

static AZURE_CORE_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "Azure::Core.Url.Encode",
    pattern: SanitizerKind::Function("Azure::Core.Url.Encode"),
    sanitizes: "url",
    description: "CodeQL sanitizer: Azure::Core.Url.Encode",
}];

static AZURE_CORE_GEN_IMPORTS: &[&str] = &["Azure::Core"];

pub static AZURE_CORE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "azure::core_generated",
    description: "Generated profile for Azure::Core from CodeQL/Pysa",
    detect_imports: AZURE_CORE_GEN_IMPORTS,
    sources: AZURE_CORE_GEN_SOURCES,
    sinks: AZURE_CORE_GEN_SINKS,
    sanitizers: AZURE_CORE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
