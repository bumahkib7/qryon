//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SOURCES: &[SourceDef] = &[
];

static CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<clap_builder::util::flat_set::FlatSet as core::iter::traits::collect::IntoIterator>::into_iter.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_IMPORTS: &[&str] = &[
    "<clap_builder::util::flat_set::FlatSet as core::iter::traits::collect::IntoIterator>::into_iter",
];

pub static CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<clap_builder::util::flat_set::flatset as core::iter::traits::collect::intoiterator>::into_iter_generated",
    description: "Generated profile for <clap_builder::util::flat_set::FlatSet as core::iter::traits::collect::IntoIterator>::into_iter from CodeQL/Pysa",
    detect_imports: CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_IMPORTS,
    sources: CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SOURCES,
    sinks: CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SINKS,
    sanitizers: CLAP_BUILDER_UTIL_FLAT_SET_FLATSET_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
