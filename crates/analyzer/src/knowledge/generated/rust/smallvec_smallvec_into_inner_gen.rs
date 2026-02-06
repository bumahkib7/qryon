//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SMALLVEC_SMALLVEC_INTO_INNER_GEN_SOURCES: &[SourceDef] = &[];

static SMALLVEC_SMALLVEC_INTO_INNER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<smallvec::SmallVec>::into_inner.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static SMALLVEC_SMALLVEC_INTO_INNER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SMALLVEC_SMALLVEC_INTO_INNER_GEN_IMPORTS: &[&str] = &["<smallvec::SmallVec>::into_inner"];

pub static SMALLVEC_SMALLVEC_INTO_INNER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<smallvec::smallvec>::into_inner_generated",
    description: "Generated profile for <smallvec::SmallVec>::into_inner from CodeQL/Pysa",
    detect_imports: SMALLVEC_SMALLVEC_INTO_INNER_GEN_IMPORTS,
    sources: SMALLVEC_SMALLVEC_INTO_INNER_GEN_SOURCES,
    sinks: SMALLVEC_SMALLVEC_INTO_INNER_GEN_SINKS,
    sanitizers: SMALLVEC_SMALLVEC_INTO_INNER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
