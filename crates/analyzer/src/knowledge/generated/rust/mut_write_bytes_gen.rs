//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MUT_WRITE_BYTES_GEN_SOURCES: &[SourceDef] = &[];

static MUT_WRITE_BYTES_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<*mut>::write_bytes.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static MUT_WRITE_BYTES_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MUT_WRITE_BYTES_GEN_IMPORTS: &[&str] = &["<*mut>::write_bytes"];

pub static MUT_WRITE_BYTES_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<*mut>::write_bytes_generated",
    description: "Generated profile for <*mut>::write_bytes from CodeQL/Pysa",
    detect_imports: MUT_WRITE_BYTES_GEN_IMPORTS,
    sources: MUT_WRITE_BYTES_GEN_SOURCES,
    sinks: MUT_WRITE_BYTES_GEN_SINKS,
    sanitizers: MUT_WRITE_BYTES_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
