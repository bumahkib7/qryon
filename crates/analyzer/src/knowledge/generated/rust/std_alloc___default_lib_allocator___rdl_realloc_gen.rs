//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "std::alloc::__default_lib_allocator::__rdl_realloc.Argument[0]",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "user_input",
        description: "CodeQL source: Argument[0] (kind: pointer-invalidate)",
    },
    SourceDef {
        name: "std::alloc::__default_lib_allocator::__rdl_realloc.ReturnValue",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
    },
];

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "std::alloc::__default_lib_allocator::__rdl_realloc.Argument[3]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-size",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[3] (kind: alloc-size)",
    cwe: Some("CWE-74"),
}];

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_IMPORTS: &[&str] =
    &["std::alloc::__default_lib_allocator::__rdl_realloc"];

pub static STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "std::alloc::__default_lib_allocator::__rdl_realloc_generated",
        description: "Generated profile for std::alloc::__default_lib_allocator::__rdl_realloc from CodeQL/Pysa",
        detect_imports: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_IMPORTS,
        sources: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_SOURCES,
        sinks: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_SINKS,
        sanitizers: STD_ALLOC___DEFAULT_LIB_ALLOCATOR___RDL_REALLOC_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
