//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SOURCES: &[SourceDef] = &[];

static CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<core::ffi::c_str::CStr as core::ops::index::Index>::index.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_IMPORTS: &[&str] =
    &["<core::ffi::c_str::CStr as core::ops::index::Index>::index"];

pub static CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::ffi::c_str::cstr as core::ops::index::index>::index_generated",
        description: "Generated profile for <core::ffi::c_str::CStr as core::ops::index::Index>::index from CodeQL/Pysa",
        detect_imports: CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_IMPORTS,
        sources: CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SOURCES,
        sinks: CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SINKS,
        sanitizers: CORE_FFI_C_STR_CSTR_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
