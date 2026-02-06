//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_SOURCES: &[SourceDef] =
    &[SourceDef {
        name: "<std::sys::thread_local::native::lazy::Storage>::get_or_init.ReturnValue",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
    }];

static STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_IMPORTS: &[&str] =
    &["<std::sys::thread_local::native::lazy::Storage>::get_or_init"];

pub static STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys::thread_local::native::lazy::storage>::get_or_init_generated",
        description: "Generated profile for <std::sys::thread_local::native::lazy::Storage>::get_or_init from CodeQL/Pysa",
        detect_imports: STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_IMPORTS,
        sources: STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_SOURCES,
        sinks: STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_SINKS,
        sanitizers: STD_SYS_THREAD_LOCAL_NATIVE_LAZY_STORAGE_GET_OR_INIT_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
