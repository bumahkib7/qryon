//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_SINKS: &[SinkDef] = &[];

static ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<actix_multipart::safety::Safety>::clone.Argument[self].Reference.Field[actix_multipart::safety::Safety::clean]",
        pattern: SanitizerKind::Function(
            "Argument[self].Reference.Field[actix_multipart::safety::Safety::clean]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Reference.Field[actix_multipart::safety::Safety::clean]",
    },
    SanitizerDef {
        name: "<actix_multipart::safety::Safety>::clone.Argument[self].Reference.Field[actix_multipart::safety::Safety::payload]",
        pattern: SanitizerKind::Function(
            "Argument[self].Reference.Field[actix_multipart::safety::Safety::payload]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Reference.Field[actix_multipart::safety::Safety::payload]",
    },
];

static ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_IMPORTS: &[&str] =
    &["<actix_multipart::safety::Safety>::clone"];

pub static ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_multipart::safety::safety>::clone_generated",
    description: "Generated profile for <actix_multipart::safety::Safety>::clone from CodeQL/Pysa",
    detect_imports: ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_IMPORTS,
    sources: ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_SOURCES,
    sinks: ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_SINKS,
    sanitizers: ACTIX_MULTIPART_SAFETY_SAFETY_CLONE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
