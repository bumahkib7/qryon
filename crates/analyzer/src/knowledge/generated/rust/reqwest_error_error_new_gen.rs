//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_ERROR_ERROR_NEW_GEN_SOURCES: &[SourceDef] = &[];

static REQWEST_ERROR_ERROR_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<reqwest::error::Error>::new.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static REQWEST_ERROR_ERROR_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_ERROR_ERROR_NEW_GEN_IMPORTS: &[&str] = &["<reqwest::error::Error>::new"];

pub static REQWEST_ERROR_ERROR_NEW_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<reqwest::error::error>::new_generated",
    description: "Generated profile for <reqwest::error::Error>::new from CodeQL/Pysa",
    detect_imports: REQWEST_ERROR_ERROR_NEW_GEN_IMPORTS,
    sources: REQWEST_ERROR_ERROR_NEW_GEN_SOURCES,
    sinks: REQWEST_ERROR_ERROR_NEW_GEN_SINKS,
    sanitizers: REQWEST_ERROR_ERROR_NEW_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
