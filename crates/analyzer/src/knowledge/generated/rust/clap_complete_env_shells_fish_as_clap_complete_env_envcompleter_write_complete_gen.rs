//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_SOURCES: &[SourceDef] = &[
];

static CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_SINKS:
    &[SinkDef] = &[
    SinkDef {
        name: "<clap_complete::env::shells::Fish as clap_complete::env::EnvCompleter>::write_complete.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "<clap_complete::env::shells::Fish as clap_complete::env::EnvCompleter>::write_complete.Argument[2]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[2] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_IMPORTS: &[&str] = &[
    "<clap_complete::env::shells::Fish as clap_complete::env::EnvCompleter>::write_complete",
];

pub static CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<clap_complete::env::shells::fish as clap_complete::env::envcompleter>::write_complete_generated",
    description: "Generated profile for <clap_complete::env::shells::Fish as clap_complete::env::EnvCompleter>::write_complete from CodeQL/Pysa",
    detect_imports: CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_IMPORTS,
    sources: CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_SOURCES,
    sinks: CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_SINKS,
    sanitizers: CLAP_COMPLETE_ENV_SHELLS_FISH_AS_CLAP_COMPLETE_ENV_ENVCOMPLETER_WRITE_COMPLETE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
