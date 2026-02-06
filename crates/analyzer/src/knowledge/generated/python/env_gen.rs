//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ENV_GEN_SOURCES: &[SourceDef] = &[];

static ENV_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "env",
    pattern: SinkKind::FunctionCall("env"),
    rule_id: "python/gen-pysa-execenvsink",
    severity: Severity::Error,
    description: "Pysa sink: env (kind: ExecEnvSink)",
    cwe: Some("CWE-74"),
}];

static ENV_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ENV_GEN_IMPORTS: &[&str] = &["env"];

pub static ENV_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "env_generated",
    description: "Generated profile for env from CodeQL/Pysa",
    detect_imports: ENV_GEN_IMPORTS,
    sources: ENV_GEN_SOURCES,
    sinks: ENV_GEN_SINKS,
    sanitizers: ENV_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
