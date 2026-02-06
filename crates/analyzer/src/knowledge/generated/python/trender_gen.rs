//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TRENDER_GEN_SOURCES: &[SourceDef] = &[];

static TRENDER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "trender.trender.TRender.__init__",
    pattern: SinkKind::FunctionCall("trender.trender.TRender.__init__"),
    rule_id: "python/gen-pysa-serversidetemplateinjection",
    severity: Severity::Error,
    description: "Pysa sink: trender.trender.TRender.__init__ (kind: ServerSideTemplateInjection)",
    cwe: Some("CWE-74"),
}];

static TRENDER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TRENDER_GEN_IMPORTS: &[&str] = &["trender"];

pub static TRENDER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "trender_generated",
    description: "Generated profile for trender from CodeQL/Pysa",
    detect_imports: TRENDER_GEN_IMPORTS,
    sources: TRENDER_GEN_SOURCES,
    sinks: TRENDER_GEN_SINKS,
    sanitizers: TRENDER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
