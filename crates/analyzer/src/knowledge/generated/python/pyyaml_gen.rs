//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PYYAML_GEN_SOURCES: &[SourceDef] = &[];

static PYYAML_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "yaml.load_all",
    pattern: SinkKind::FunctionCall("yaml.load_all"),
    rule_id: "python/gen-pysa-execdeserializationsink",
    severity: Severity::Error,
    description: "Pysa sink: yaml.load_all (kind: ExecDeserializationSink)",
    cwe: Some("CWE-74"),
}];

static PYYAML_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PYYAML_GEN_IMPORTS: &[&str] = &["yaml"];

pub static PYYAML_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pyyaml_generated",
    description: "Generated profile for yaml from CodeQL/Pysa",
    detect_imports: PYYAML_GEN_IMPORTS,
    sources: PYYAML_GEN_SOURCES,
    sinks: PYYAML_GEN_SINKS,
    sanitizers: PYYAML_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
