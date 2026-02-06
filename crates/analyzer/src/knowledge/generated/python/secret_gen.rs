//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SECRET_GEN_SOURCES: &[SourceDef] = &[];

static SECRET_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "secret",
    pattern: SinkKind::FunctionCall("secret"),
    rule_id: "python/gen-pysa-authentication",
    severity: Severity::Error,
    description: "Pysa sink: secret (kind: Authentication)",
    cwe: Some("CWE-74"),
}];

static SECRET_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SECRET_GEN_IMPORTS: &[&str] = &["secret"];

pub static SECRET_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "secret_generated",
    description: "Generated profile for secret from CodeQL/Pysa",
    detect_imports: SECRET_GEN_IMPORTS,
    sources: SECRET_GEN_SOURCES,
    sinks: SECRET_GEN_SINKS,
    sanitizers: SECRET_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
