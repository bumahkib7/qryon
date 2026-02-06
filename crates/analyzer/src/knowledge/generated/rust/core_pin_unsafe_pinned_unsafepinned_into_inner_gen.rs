//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_SOURCES: &[SourceDef] = &[];

static CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_SINKS: &[SinkDef] = &[];

static CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<core::pin::unsafe_pinned::UnsafePinned>::into_inner.Argument[self].Field[core::pin::unsafe_pinned::UnsafePinned::value].Field[core::cell::UnsafeCell::value]",
        pattern: SanitizerKind::Function(
            "Argument[self].Field[core::pin::unsafe_pinned::UnsafePinned::value].Field[core::cell::UnsafeCell::value]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[core::pin::unsafe_pinned::UnsafePinned::value].Field[core::cell::UnsafeCell::value]",
    },
];

static CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_IMPORTS: &[&str] =
    &["<core::pin::unsafe_pinned::UnsafePinned>::into_inner"];

pub static CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::pin::unsafe_pinned::unsafepinned>::into_inner_generated",
        description: "Generated profile for <core::pin::unsafe_pinned::UnsafePinned>::into_inner from CodeQL/Pysa",
        detect_imports: CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_IMPORTS,
        sources: CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_SOURCES,
        sinks: CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_SINKS,
        sanitizers: CORE_PIN_UNSAFE_PINNED_UNSAFEPINNED_INTO_INNER_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
