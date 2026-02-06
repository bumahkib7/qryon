//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SOURCES:
    &[SourceDef] = &[];

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SINKS:
    &[SinkDef] = &[];

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SANITIZERS:
    &[SanitizerDef] = &[SanitizerDef {
    name: "<std::sys_common::wtf8::EncodeWide as core::iter::traits::iterator::Iterator>::next.Argument[self].Reference.Field[std::sys_common::wtf8::EncodeWide::extra]",
    pattern: SanitizerKind::Function(
        "Argument[self].Reference.Field[std::sys_common::wtf8::EncodeWide::extra]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Reference.Field[std::sys_common::wtf8::EncodeWide::extra]",
}];

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_IMPORTS:
    &[&str] =
    &["<std::sys_common::wtf8::EncodeWide as core::iter::traits::iterator::Iterator>::next"];

pub static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<std::sys_common::wtf8::encodewide as core::iter::traits::iterator::iterator>::next_generated",
    description: "Generated profile for <std::sys_common::wtf8::EncodeWide as core::iter::traits::iterator::Iterator>::next from CodeQL/Pysa",
    detect_imports:
        STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_IMPORTS,
    sources: STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SOURCES,
    sinks: STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SINKS,
    sanitizers:
        STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
