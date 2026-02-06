//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static KEY_FILE_GEN_SOURCES: &[SourceDef] = &[];

static KEY_FILE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "key_file",
    pattern: SinkKind::FunctionCall("key_file"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: key_file (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static KEY_FILE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static KEY_FILE_GEN_IMPORTS: &[&str] = &["key_file"];

pub static KEY_FILE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "key_file_generated",
    description: "Generated profile for key_file from CodeQL/Pysa",
    detect_imports: KEY_FILE_GEN_IMPORTS,
    sources: KEY_FILE_GEN_SOURCES,
    sinks: KEY_FILE_GEN_SINKS,
    sanitizers: KEY_FILE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
