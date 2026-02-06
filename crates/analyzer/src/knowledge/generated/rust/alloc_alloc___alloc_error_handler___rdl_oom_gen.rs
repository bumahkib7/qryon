//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "alloc::alloc::__alloc_error_handler::__rdl_oom.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_IMPORTS: &[&str] =
    &["alloc::alloc::__alloc_error_handler::__rdl_oom"];

pub static ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "alloc::alloc::__alloc_error_handler::__rdl_oom_generated",
        description: "Generated profile for alloc::alloc::__alloc_error_handler::__rdl_oom from CodeQL/Pysa",
        detect_imports: ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_IMPORTS,
        sources: ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_SOURCES,
        sinks: ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_SINKS,
        sanitizers: ALLOC_ALLOC___ALLOC_ERROR_HANDLER___RDL_OOM_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
