//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<std::sys::thread_local::native::eager::Storage>::get.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_IMPORTS: &[&str] =
    &["<std::sys::thread_local::native::eager::Storage>::get"];

pub static STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys::thread_local::native::eager::storage>::get_generated",
        description: "Generated profile for <std::sys::thread_local::native::eager::Storage>::get from CodeQL/Pysa",
        detect_imports: STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_IMPORTS,
        sources: STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_SOURCES,
        sinks: STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_SINKS,
        sanitizers: STD_SYS_THREAD_LOCAL_NATIVE_EAGER_STORAGE_GET_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
