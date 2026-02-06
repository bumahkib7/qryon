//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MEMCHR_MEMMEM_RFIND_GEN_SOURCES: &[SourceDef] = &[];

static MEMCHR_MEMMEM_RFIND_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "memchr::memmem::rfind.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[1] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static MEMCHR_MEMMEM_RFIND_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MEMCHR_MEMMEM_RFIND_GEN_IMPORTS: &[&str] = &["memchr::memmem::rfind"];

pub static MEMCHR_MEMMEM_RFIND_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "memchr::memmem::rfind_generated",
    description: "Generated profile for memchr::memmem::rfind from CodeQL/Pysa",
    detect_imports: MEMCHR_MEMMEM_RFIND_GEN_IMPORTS,
    sources: MEMCHR_MEMMEM_RFIND_GEN_SOURCES,
    sinks: MEMCHR_MEMMEM_RFIND_GEN_SINKS,
    sanitizers: MEMCHR_MEMMEM_RFIND_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
