//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_GOKOGIRI_XPATH_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_GOKOGIRI_XPATH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "group:gokogiri/xpath.Compile",
    pattern: SinkKind::FunctionCall("group:gokogiri/xpath.Compile"),
    rule_id: "go/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: group:gokogiri/xpath..Compile (kind: manual)",
    cwe: Some("CWE-74"),
}];

static GROUP_GOKOGIRI_XPATH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_GOKOGIRI_XPATH_GEN_IMPORTS: &[&str] = &["group:gokogiri/xpath"];

pub static GROUP_GOKOGIRI_XPATH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:gokogiri_xpath_generated",
    description: "Generated profile for group:gokogiri/xpath from CodeQL/Pysa",
    detect_imports: GROUP_GOKOGIRI_XPATH_GEN_IMPORTS,
    sources: GROUP_GOKOGIRI_XPATH_GEN_SOURCES,
    sinks: GROUP_GOKOGIRI_XPATH_GEN_SINKS,
    sanitizers: GROUP_GOKOGIRI_XPATH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
