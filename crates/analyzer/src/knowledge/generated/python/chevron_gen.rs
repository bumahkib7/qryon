//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CHEVRON_GEN_SOURCES: &[SourceDef] = &[];

static CHEVRON_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "chevron.renderer.render",
    pattern: SinkKind::FunctionCall("chevron.renderer.render"),
    rule_id: "python/gen-pysa-serversidetemplateinjection",
    severity: Severity::Error,
    description: "Pysa sink: chevron.renderer.render (kind: ServerSideTemplateInjection)",
    cwe: Some("CWE-74"),
}];

static CHEVRON_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CHEVRON_GEN_IMPORTS: &[&str] = &["chevron"];

pub static CHEVRON_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "chevron_generated",
    description: "Generated profile for chevron from CodeQL/Pysa",
    detect_imports: CHEVRON_GEN_IMPORTS,
    sources: CHEVRON_GEN_SOURCES,
    sinks: CHEVRON_GEN_SINKS,
    sanitizers: CHEVRON_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
