//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_SOURCES: &[SourceDef] = &[];

static CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<clap_builder::mkeymap::MKeyMap>::remove_by_name.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_IMPORTS: &[&str] =
    &["<clap_builder::mkeymap::MKeyMap>::remove_by_name"];

pub static CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<clap_builder::mkeymap::mkeymap>::remove_by_name_generated",
        description: "Generated profile for <clap_builder::mkeymap::MKeyMap>::remove_by_name from CodeQL/Pysa",
        detect_imports: CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_IMPORTS,
        sources: CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_SOURCES,
        sinks: CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_SINKS,
        sanitizers: CLAP_BUILDER_MKEYMAP_MKEYMAP_REMOVE_BY_NAME_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
