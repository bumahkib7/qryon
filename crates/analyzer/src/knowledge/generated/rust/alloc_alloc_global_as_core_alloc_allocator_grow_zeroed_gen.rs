//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::alloc::Global as core::alloc::Allocator>::grow_zeroed.Argument[2]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[2] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_IMPORTS: &[&str] =
    &["<alloc::alloc::Global as core::alloc::Allocator>::grow_zeroed"];

pub static ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<alloc::alloc::global as core::alloc::allocator>::grow_zeroed_generated",
        description: "Generated profile for <alloc::alloc::Global as core::alloc::Allocator>::grow_zeroed from CodeQL/Pysa",
        detect_imports: ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_IMPORTS,
        sources: ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SOURCES,
        sinks: ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SINKS,
        sanitizers: ALLOC_ALLOC_GLOBAL_AS_CORE_ALLOC_ALLOCATOR_GROW_ZEROED_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
