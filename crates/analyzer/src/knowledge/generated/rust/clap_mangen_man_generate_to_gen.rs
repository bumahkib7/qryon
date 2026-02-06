//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_MANGEN_MAN_GENERATE_TO_GEN_SOURCES: &[SourceDef] = &[];

static CLAP_MANGEN_MAN_GENERATE_TO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<clap_mangen::Man>::generate_to.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[self] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static CLAP_MANGEN_MAN_GENERATE_TO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CLAP_MANGEN_MAN_GENERATE_TO_GEN_IMPORTS: &[&str] = &["<clap_mangen::Man>::generate_to"];

pub static CLAP_MANGEN_MAN_GENERATE_TO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<clap_mangen::man>::generate_to_generated",
    description: "Generated profile for <clap_mangen::Man>::generate_to from CodeQL/Pysa",
    detect_imports: CLAP_MANGEN_MAN_GENERATE_TO_GEN_IMPORTS,
    sources: CLAP_MANGEN_MAN_GENERATE_TO_GEN_SOURCES,
    sinks: CLAP_MANGEN_MAN_GENERATE_TO_GEN_SINKS,
    sanitizers: CLAP_MANGEN_MAN_GENERATE_TO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
