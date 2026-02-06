//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CHEETAH_GEN_SOURCES: &[SourceDef] = &[];

static CHEETAH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "Cheetah.Template.Template.__init__",
    pattern: SinkKind::FunctionCall("Cheetah.Template.Template.__init__"),
    rule_id: "python/gen-pysa-serversidetemplateinjection",
    severity: Severity::Error,
    description: "Pysa sink: Cheetah.Template.Template.__init__ (kind: ServerSideTemplateInjection)",
    cwe: Some("CWE-74"),
}];

static CHEETAH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CHEETAH_GEN_IMPORTS: &[&str] = &["Cheetah"];

pub static CHEETAH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cheetah_generated",
    description: "Generated profile for Cheetah from CodeQL/Pysa",
    detect_imports: CHEETAH_GEN_IMPORTS,
    sources: CHEETAH_GEN_SOURCES,
    sinks: CHEETAH_GEN_SINKS,
    sanitizers: CHEETAH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
