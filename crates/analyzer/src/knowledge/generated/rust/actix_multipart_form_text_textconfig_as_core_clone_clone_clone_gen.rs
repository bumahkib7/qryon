//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES: &[SourceDef] =
    &[];

static ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS: &[SinkDef] = &[];

static ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS:
    &[SanitizerDef] = &[SanitizerDef {
    name: "<actix_multipart::form::text::TextConfig as core::clone::Clone>::clone.Argument[self].Field[actix_multipart::form::text::TextConfig::validate_content_type]",
    pattern: SanitizerKind::Function(
        "Argument[self].Field[actix_multipart::form::text::TextConfig::validate_content_type]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Field[actix_multipart::form::text::TextConfig::validate_content_type]",
}];

static ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS: &[&str] =
    &["<actix_multipart::form::text::TextConfig as core::clone::Clone>::clone"];

pub static ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<actix_multipart::form::text::textconfig as core::clone::clone>::clone_generated",
    description: "Generated profile for <actix_multipart::form::text::TextConfig as core::clone::Clone>::clone from CodeQL/Pysa",
    detect_imports: ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS,
    sources: ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES,
    sinks: ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS,
    sanitizers: ACTIX_MULTIPART_FORM_TEXT_TEXTCONFIG_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
