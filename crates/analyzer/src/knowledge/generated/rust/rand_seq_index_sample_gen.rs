//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RAND_SEQ_INDEX_SAMPLE_GEN_SOURCES: &[SourceDef] = &[];

static RAND_SEQ_INDEX_SAMPLE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "rand::seq::index_::sample.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "rand::seq::index_::sample.Argument[2]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[2] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static RAND_SEQ_INDEX_SAMPLE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RAND_SEQ_INDEX_SAMPLE_GEN_IMPORTS: &[&str] = &["rand::seq::index_::sample"];

pub static RAND_SEQ_INDEX_SAMPLE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "rand::seq::index_::sample_generated",
    description: "Generated profile for rand::seq::index_::sample from CodeQL/Pysa",
    detect_imports: RAND_SEQ_INDEX_SAMPLE_GEN_IMPORTS,
    sources: RAND_SEQ_INDEX_SAMPLE_GEN_SOURCES,
    sinks: RAND_SEQ_INDEX_SAMPLE_GEN_SINKS,
    sanitizers: RAND_SEQ_INDEX_SAMPLE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
