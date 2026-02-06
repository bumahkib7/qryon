//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::string::FromUtf8Error>::into_utf8_lossy.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_IMPORTS: &[&str] =
    &["<alloc::string::FromUtf8Error>::into_utf8_lossy"];

pub static ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<alloc::string::fromutf8error>::into_utf8_lossy_generated",
        description: "Generated profile for <alloc::string::FromUtf8Error>::into_utf8_lossy from CodeQL/Pysa",
        detect_imports: ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_IMPORTS,
        sources: ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_SOURCES,
        sinks: ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_SINKS,
        sanitizers: ALLOC_STRING_FROMUTF8ERROR_INTO_UTF8_LOSSY_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
