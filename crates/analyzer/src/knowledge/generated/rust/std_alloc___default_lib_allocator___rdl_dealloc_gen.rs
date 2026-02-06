//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::alloc::__default_lib_allocator::__rdl_dealloc.Argument[0]",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: Argument[0] (kind: pointer-invalidate)",
}];

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_SINKS: &[SinkDef] = &[];

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_IMPORTS: &[&str] =
    &["std::alloc::__default_lib_allocator::__rdl_dealloc"];

pub static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "std::alloc::__default_lib_allocator::__rdl_dealloc_generated",
        description: "Generated profile for std::alloc::__default_lib_allocator::__rdl_dealloc from CodeQL/Pysa",
        detect_imports: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_IMPORTS,
        sources: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_SOURCES,
        sinks: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_SINKS,
        sanitizers: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_DEALLOC_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
