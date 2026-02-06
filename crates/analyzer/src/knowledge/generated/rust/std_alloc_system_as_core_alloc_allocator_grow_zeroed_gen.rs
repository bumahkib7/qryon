//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SOURCES: &[SourceDef] = &[];

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::alloc::System as core::alloc::Allocator>::grow_zeroed.Argument[2]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-size",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[2] (kind: alloc-size)",
    cwe: Some("CWE-74"),
}];

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_IMPORTS: &[&str] =
    &["<std::alloc::System as core::alloc::Allocator>::grow_zeroed"];

pub static STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::alloc::system as core::alloc::allocator>::grow_zeroed_generated",
        description: "Generated profile for <std::alloc::System as core::alloc::Allocator>::grow_zeroed from CodeQL/Pysa",
        detect_imports: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_IMPORTS,
        sources: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SOURCES,
        sinks: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SINKS,
        sanitizers: STD_ALLOC_SYSTEM_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
