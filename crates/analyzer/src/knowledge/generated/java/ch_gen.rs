//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CH_GEN_SOURCES: &[SourceDef] = &[];

static CH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "ch.ethz.ssh2.Connection.authenticateWithPassword",
    pattern: SinkKind::FunctionCall("ch.ethz.ssh2.Connection.authenticateWithPassword"),
    rule_id: "java/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: ch.ethz.ssh2.Connection.authenticateWithPassword (kind: manual)",
    cwe: Some("CWE-74"),
}];

static CH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CH_GEN_IMPORTS: &[&str] = &["ch.ethz.ssh2"];

pub static CH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "ch_generated",
    description: "Generated profile for ch.ethz.ssh2 from CodeQL/Pysa",
    detect_imports: CH_GEN_IMPORTS,
    sources: CH_GEN_SOURCES,
    sinks: CH_GEN_SINKS,
    sanitizers: CH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
