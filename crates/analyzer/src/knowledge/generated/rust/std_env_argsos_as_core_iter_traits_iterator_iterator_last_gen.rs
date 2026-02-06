//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SOURCES: &[SourceDef] = &[];

static STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<std::env::ArgsOs as core::iter::traits::iterator::Iterator>::last.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    }];

static STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_IMPORTS: &[&str] =
    &["<std::env::ArgsOs as core::iter::traits::iterator::Iterator>::last"];

pub static STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::env::argsos as core::iter::traits::iterator::iterator>::last_generated",
        description: "Generated profile for <std::env::ArgsOs as core::iter::traits::iterator::Iterator>::last from CodeQL/Pysa",
        detect_imports: STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_IMPORTS,
        sources: STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SOURCES,
        sinks: STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SINKS,
        sanitizers: STD_ENV_ARGSOS_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
