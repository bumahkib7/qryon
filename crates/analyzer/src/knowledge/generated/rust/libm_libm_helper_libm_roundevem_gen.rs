//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_SOURCES: &[SourceDef] = &[];

static LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<libm::libm_helper::Libm>::roundevem.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_IMPORTS: &[&str] =
    &["<libm::libm_helper::Libm>::roundevem"];

pub static LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<libm::libm_helper::libm>::roundevem_generated",
    description: "Generated profile for <libm::libm_helper::Libm>::roundevem from CodeQL/Pysa",
    detect_imports: LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_IMPORTS,
    sources: LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_SOURCES,
    sinks: LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_SINKS,
    sanitizers: LIBM_LIBM_HELPER_LIBM_ROUNDEVEM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
