//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES: &[SourceDef] = &[];

static CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS: &[SinkDef] = &[];

static CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<core::str::iter::EncodeUtf16 as core::clone::Clone>::clone.Argument[self].Field[core::str::iter::EncodeUtf16::extra]",
        pattern: SanitizerKind::Function(
            "Argument[self].Field[core::str::iter::EncodeUtf16::extra]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[core::str::iter::EncodeUtf16::extra]",
    },
];

static CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS: &[&str] =
    &["<core::str::iter::EncodeUtf16 as core::clone::Clone>::clone"];

pub static CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::str::iter::encodeutf16 as core::clone::clone>::clone_generated",
        description: "Generated profile for <core::str::iter::EncodeUtf16 as core::clone::Clone>::clone from CodeQL/Pysa",
        detect_imports: CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS,
        sources: CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES,
        sinks: CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS,
        sanitizers: CORE_STR_ITER_ENCODEUTF16_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
