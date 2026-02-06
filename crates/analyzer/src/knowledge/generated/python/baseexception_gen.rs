//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static BASEEXCEPTION_GEN_SOURCES: &[SourceDef] = &[];

static BASEEXCEPTION_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "BaseException.__init__",
    pattern: SinkKind::FunctionCall("BaseException.__init__"),
    rule_id: "python/gen-pysa-logging",
    severity: Severity::Error,
    description: "Pysa sink: BaseException.__init__ (kind: Logging)",
    cwe: Some("CWE-74"),
}];

static BASEEXCEPTION_GEN_SANITIZERS: &[SanitizerDef] = &[];

static BASEEXCEPTION_GEN_IMPORTS: &[&str] = &["BaseException"];

pub static BASEEXCEPTION_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "baseexception_generated",
    description: "Generated profile for BaseException from CodeQL/Pysa",
    detect_imports: BASEEXCEPTION_GEN_IMPORTS,
    sources: BASEEXCEPTION_GEN_SOURCES,
    sinks: BASEEXCEPTION_GEN_SINKS,
    sanitizers: BASEEXCEPTION_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
