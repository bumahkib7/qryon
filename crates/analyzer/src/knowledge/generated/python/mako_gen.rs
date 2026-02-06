//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MAKO_GEN_SOURCES: &[SourceDef] = &[];

static MAKO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "mako.template.Template.__init__",
    pattern: SinkKind::FunctionCall("mako.template.Template.__init__"),
    rule_id: "python/gen-pysa-serversidetemplateinjection",
    severity: Severity::Error,
    description: "Pysa sink: mako.template.Template.__init__ (kind: ServerSideTemplateInjection)",
    cwe: Some("CWE-74"),
}];

static MAKO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MAKO_GEN_IMPORTS: &[&str] = &["mako"];

pub static MAKO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mako_generated",
    description: "Generated profile for mako from CodeQL/Pysa",
    detect_imports: MAKO_GEN_IMPORTS,
    sources: MAKO_GEN_SOURCES,
    sinks: MAKO_GEN_SINKS,
    sanitizers: MAKO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
