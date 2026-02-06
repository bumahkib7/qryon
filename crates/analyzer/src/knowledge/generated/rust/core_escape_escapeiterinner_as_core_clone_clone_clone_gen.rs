//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES: &[SourceDef] = &[];

static CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS: &[SinkDef] = &[];

static CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<core::escape::EscapeIterInner as core::clone::Clone>::clone.Argument[self].Field[core::escape::EscapeIterInner::data]",
        pattern: SanitizerKind::Function(
            "Argument[self].Field[core::escape::EscapeIterInner::data]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[core::escape::EscapeIterInner::data]",
    },
];

static CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS: &[&str] =
    &["<core::escape::EscapeIterInner as core::clone::Clone>::clone"];

pub static CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::escape::escapeiterinner as core::clone::clone>::clone_generated",
        description: "Generated profile for <core::escape::EscapeIterInner as core::clone::Clone>::clone from CodeQL/Pysa",
        detect_imports: CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS,
        sources: CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES,
        sinks: CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS,
        sanitizers: CORE_ESCAPE_ESCAPEITERINNER_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
