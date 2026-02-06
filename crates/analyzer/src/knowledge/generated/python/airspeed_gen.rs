//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AIRSPEED_GEN_SOURCES: &[SourceDef] = &[];

static AIRSPEED_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "airspeed.Template.__init__",
    pattern: SinkKind::FunctionCall("airspeed.Template.__init__"),
    rule_id: "python/gen-pysa-serversidetemplateinjection",
    severity: Severity::Error,
    description: "Pysa sink: airspeed.Template.__init__ (kind: ServerSideTemplateInjection)",
    cwe: Some("CWE-74"),
}];

static AIRSPEED_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AIRSPEED_GEN_IMPORTS: &[&str] = &["airspeed"];

pub static AIRSPEED_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "airspeed_generated",
    description: "Generated profile for airspeed from CodeQL/Pysa",
    detect_imports: AIRSPEED_GEN_IMPORTS,
    sources: AIRSPEED_GEN_SOURCES,
    sinks: AIRSPEED_GEN_SINKS,
    sanitizers: AIRSPEED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
