//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_SOURCES:
    &[SourceDef] = &[];

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<alloc::collections::vec_deque::VecDeque as std::io::Write>::write_vectored.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_IMPORTS: &[&str] =
    &["<alloc::collections::vec_deque::VecDeque as std::io::Write>::write_vectored"];

pub static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<alloc::collections::vec_deque::vecdeque as std::io::write>::write_vectored_generated",
    description: "Generated profile for <alloc::collections::vec_deque::VecDeque as std::io::Write>::write_vectored from CodeQL/Pysa",
    detect_imports: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_IMPORTS,
    sources: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_SOURCES,
    sinks: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_SINKS,
    sanitizers: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_AS_STD_IO_WRITE_WRITE_VECTORED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
