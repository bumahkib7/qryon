//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_SOURCES: &[SourceDef] = &[];

static CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<core::fmt::num::UpperHex as core::fmt::num::GenericRadix>::digit.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_IMPORTS: &[&str] =
    &["<core::fmt::num::UpperHex as core::fmt::num::GenericRadix>::digit"];

pub static CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::fmt::num::upperhex as core::fmt::num::genericradix>::digit_generated",
        description: "Generated profile for <core::fmt::num::UpperHex as core::fmt::num::GenericRadix>::digit from CodeQL/Pysa",
        detect_imports: CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_IMPORTS,
        sources: CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_SOURCES,
        sinks: CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_SINKS,
        sanitizers: CORE_FMT_NUM_UPPERHEX_AS_CORE_FMT_NUM_GENERICRADIX_DIGIT_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
