//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CERT_FILE_GEN_SOURCES: &[SourceDef] = &[];

static CERT_FILE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "cert_file",
    pattern: SinkKind::FunctionCall("cert_file"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: cert_file (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static CERT_FILE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CERT_FILE_GEN_IMPORTS: &[&str] = &["cert_file"];

pub static CERT_FILE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cert_file_generated",
    description: "Generated profile for cert_file from CodeQL/Pysa",
    detect_imports: CERT_FILE_GEN_IMPORTS,
    sources: CERT_FILE_GEN_SOURCES,
    sinks: CERT_FILE_GEN_SINKS,
    sanitizers: CERT_FILE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
