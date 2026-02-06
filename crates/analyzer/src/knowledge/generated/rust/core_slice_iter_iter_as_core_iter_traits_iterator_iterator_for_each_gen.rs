//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_SOURCES:
    &[SourceDef] = &[];

static CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<core::slice::iter::Iter as core::iter::traits::iterator::Iterator>::for_each.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_IMPORTS: &[&str] =
    &["<core::slice::iter::Iter as core::iter::traits::iterator::Iterator>::for_each"];

pub static CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<core::slice::iter::iter as core::iter::traits::iterator::iterator>::for_each_generated",
    description: "Generated profile for <core::slice::iter::Iter as core::iter::traits::iterator::Iterator>::for_each from CodeQL/Pysa",
    detect_imports: CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_IMPORTS,
    sources: CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_SOURCES,
    sinks: CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_SINKS,
    sanitizers: CORE_SLICE_ITER_ITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_FOR_EACH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
