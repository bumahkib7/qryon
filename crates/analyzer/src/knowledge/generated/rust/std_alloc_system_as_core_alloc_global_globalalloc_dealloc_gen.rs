//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_SOURCES: &[SourceDef] =
    &[SourceDef {
        name: "<std::alloc::System as core::alloc::global::GlobalAlloc>::dealloc.Argument[0]",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "user_input",
        description: "CodeQL source: Argument[0] (kind: pointer-invalidate)",
    }];

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_SINKS: &[SinkDef] = &[];

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_IMPORTS: &[&str] =
    &["<std::alloc::System as core::alloc::global::GlobalAlloc>::dealloc"];

pub static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::alloc::system as core::alloc::global::globalalloc>::dealloc_generated",
        description: "Generated profile for <std::alloc::System as core::alloc::global::GlobalAlloc>::dealloc from CodeQL/Pysa",
        detect_imports: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_IMPORTS,
        sources: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_SOURCES,
        sinks: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_SINKS,
        sanitizers: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_GLOBAL_GLOBALALLOC_DEALLOC_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
