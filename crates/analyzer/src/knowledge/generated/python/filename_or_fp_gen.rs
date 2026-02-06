//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FILENAME_OR_FP_GEN_SOURCES: &[SourceDef] = &[];

static FILENAME_OR_FP_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "filename_or_fp",
    pattern: SinkKind::FunctionCall("filename_or_fp"),
    rule_id: "python/gen-pysa-filesystem_readwrite",
    severity: Severity::Critical,
    description: "Pysa sink: filename_or_fp (kind: FileSystem_ReadWrite)",
    cwe: Some("CWE-22"),
}];

static FILENAME_OR_FP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FILENAME_OR_FP_GEN_IMPORTS: &[&str] = &["filename_or_fp"];

pub static FILENAME_OR_FP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "filename_or_fp_generated",
    description: "Generated profile for filename_or_fp from CodeQL/Pysa",
    detect_imports: FILENAME_OR_FP_GEN_IMPORTS,
    sources: FILENAME_OR_FP_GEN_SOURCES,
    sinks: FILENAME_OR_FP_GEN_SINKS,
    sanitizers: FILENAME_OR_FP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
