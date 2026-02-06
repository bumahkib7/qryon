//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GENSHI_GEN_SOURCES: &[SourceDef] = &[];

static GENSHI_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "genshi.template.base.Template.__init__",
    pattern: SinkKind::FunctionCall("genshi.template.base.Template.__init__"),
    rule_id: "python/gen-pysa-serversidetemplateinjection",
    severity: Severity::Error,
    description: "Pysa sink: genshi.template.base.Template.__init__ (kind: ServerSideTemplateInjection)",
    cwe: Some("CWE-74"),
}];

static GENSHI_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GENSHI_GEN_IMPORTS: &[&str] = &["genshi"];

pub static GENSHI_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "genshi_generated",
    description: "Generated profile for genshi from CodeQL/Pysa",
    detect_imports: GENSHI_GEN_IMPORTS,
    sources: GENSHI_GEN_SOURCES,
    sinks: GENSHI_GEN_SINKS,
    sanitizers: GENSHI_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
