//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RAND_RANDOM_RATIO_GEN_SOURCES: &[SourceDef] = &[];

static RAND_RANDOM_RATIO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "rand::random_ratio.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "rand::random_ratio.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static RAND_RANDOM_RATIO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RAND_RANDOM_RATIO_GEN_IMPORTS: &[&str] = &["rand::random_ratio"];

pub static RAND_RANDOM_RATIO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "rand::random_ratio_generated",
    description: "Generated profile for rand::random_ratio from CodeQL/Pysa",
    detect_imports: RAND_RANDOM_RATIO_GEN_IMPORTS,
    sources: RAND_RANDOM_RATIO_GEN_SOURCES,
    sinks: RAND_RANDOM_RATIO_GEN_SINKS,
    sanitizers: RAND_RANDOM_RATIO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
