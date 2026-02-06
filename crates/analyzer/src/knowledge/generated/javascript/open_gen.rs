//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static OPEN_GEN_SOURCES: &[SourceDef] = &[];

static OPEN_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "open.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "javascript/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "open.Member[App].Argument[0]",
        pattern: SinkKind::FunctionCall("openApp"),
        rule_id: "javascript/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Member[openApp].Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
];

static OPEN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static OPEN_GEN_IMPORTS: &[&str] = &["open"];

pub static OPEN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "open_generated",
    description: "Generated profile for open from CodeQL/Pysa",
    detect_imports: OPEN_GEN_IMPORTS,
    sources: OPEN_GEN_SOURCES,
    sinks: OPEN_GEN_SINKS,
    sanitizers: OPEN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
