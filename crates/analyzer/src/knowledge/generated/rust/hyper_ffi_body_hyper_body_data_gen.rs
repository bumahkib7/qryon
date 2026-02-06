//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "hyper::ffi::body::hyper_body_data.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_SINKS: &[SinkDef] = &[];

static HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_IMPORTS: &[&str] = &["hyper::ffi::body::hyper_body_data"];

pub static HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "hyper::ffi::body::hyper_body_data_generated",
    description: "Generated profile for hyper::ffi::body::hyper_body_data from CodeQL/Pysa",
    detect_imports: HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_IMPORTS,
    sources: HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_SOURCES,
    sinks: HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_SINKS,
    sanitizers: HYPER_FFI_BODY_HYPER_BODY_DATA_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
