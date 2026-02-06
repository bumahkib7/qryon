//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CHARSET_GEN_SOURCES: &[SourceDef] = &[];

static CHARSET_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "charset",
    pattern: SinkKind::FunctionCall("charset"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: charset (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static CHARSET_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CHARSET_GEN_IMPORTS: &[&str] = &["charset"];

pub static CHARSET_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "charset_generated",
    description: "Generated profile for charset from CodeQL/Pysa",
    detect_imports: CHARSET_GEN_IMPORTS,
    sources: CHARSET_GEN_SOURCES,
    sinks: CHARSET_GEN_SINKS,
    sanitizers: CHARSET_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
