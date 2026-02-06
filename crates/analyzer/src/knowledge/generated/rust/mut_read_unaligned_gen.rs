//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MUT_READ_UNALIGNED_GEN_SOURCES: &[SourceDef] = &[];

static MUT_READ_UNALIGNED_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<*mut>::read_unaligned.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static MUT_READ_UNALIGNED_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MUT_READ_UNALIGNED_GEN_IMPORTS: &[&str] = &["<*mut>::read_unaligned"];

pub static MUT_READ_UNALIGNED_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<*mut>::read_unaligned_generated",
    description: "Generated profile for <*mut>::read_unaligned from CodeQL/Pysa",
    detect_imports: MUT_READ_UNALIGNED_GEN_IMPORTS,
    sources: MUT_READ_UNALIGNED_GEN_SOURCES,
    sinks: MUT_READ_UNALIGNED_GEN_SINKS,
    sanitizers: MUT_READ_UNALIGNED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
