//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<alloc::collections::binary_heap::BinaryHeap>::with_capacity_in.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    }];

static ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_IMPORTS: &[&str] =
    &["<alloc::collections::binary_heap::BinaryHeap>::with_capacity_in"];

pub static ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<alloc::collections::binary_heap::binaryheap>::with_capacity_in_generated",
        description: "Generated profile for <alloc::collections::binary_heap::BinaryHeap>::with_capacity_in from CodeQL/Pysa",
        detect_imports: ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_IMPORTS,
        sources: ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_SOURCES,
        sinks: ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_SINKS,
        sanitizers: ALLOC_COLLECTIONS_BINARY_HEAP_BINARYHEAP_WITH_CAPACITY_IN_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
