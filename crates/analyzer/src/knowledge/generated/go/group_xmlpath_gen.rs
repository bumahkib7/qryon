//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_XMLPATH_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_XMLPATH_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:xmlpath.Compile",
        pattern: SinkKind::FunctionCall("group:xmlpath.Compile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:xmlpath..Compile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:xmlpath.MustCompile",
        pattern: SinkKind::FunctionCall("group:xmlpath.MustCompile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:xmlpath..MustCompile (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_XMLPATH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_XMLPATH_GEN_IMPORTS: &[&str] = &["group:xmlpath"];

pub static GROUP_XMLPATH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:xmlpath_generated",
    description: "Generated profile for group:xmlpath from CodeQL/Pysa",
    detect_imports: GROUP_XMLPATH_GEN_IMPORTS,
    sources: GROUP_XMLPATH_GEN_SOURCES,
    sinks: GROUP_XMLPATH_GEN_SINKS,
    sanitizers: GROUP_XMLPATH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
