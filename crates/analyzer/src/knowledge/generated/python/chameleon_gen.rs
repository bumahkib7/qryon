//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CHAMELEON_GEN_SOURCES: &[SourceDef] = &[];

static CHAMELEON_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "chameleon.template.BaseTemplate.__init__",
    pattern: SinkKind::FunctionCall("chameleon.template.BaseTemplate.__init__"),
    rule_id: "python/gen-pysa-serversidetemplateinjection",
    severity: Severity::Error,
    description: "Pysa sink: chameleon.template.BaseTemplate.__init__ (kind: ServerSideTemplateInjection)",
    cwe: Some("CWE-74"),
}];

static CHAMELEON_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CHAMELEON_GEN_IMPORTS: &[&str] = &["chameleon"];

pub static CHAMELEON_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "chameleon_generated",
    description: "Generated profile for chameleon from CodeQL/Pysa",
    detect_imports: CHAMELEON_GEN_IMPORTS,
    sources: CHAMELEON_GEN_SOURCES,
    sinks: CHAMELEON_GEN_SINKS,
    sanitizers: CHAMELEON_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
