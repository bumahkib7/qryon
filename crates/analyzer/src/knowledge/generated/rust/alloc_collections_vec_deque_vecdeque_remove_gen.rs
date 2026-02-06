//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<alloc::collections::vec_deque::VecDeque>::remove.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "<alloc::collections::vec_deque::VecDeque>::remove.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_IMPORTS: &[&str] =
    &["<alloc::collections::vec_deque::VecDeque>::remove"];

pub static ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<alloc::collections::vec_deque::vecdeque>::remove_generated",
        description: "Generated profile for <alloc::collections::vec_deque::VecDeque>::remove from CodeQL/Pysa",
        detect_imports: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_IMPORTS,
        sources: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_SOURCES,
        sinks: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_SINKS,
        sanitizers: ALLOC_COLLECTIONS_VEC_DEQUE_VECDEQUE_REMOVE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
