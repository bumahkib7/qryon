//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_ENV_COMMON_ENV_NEW_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_ENV_COMMON_ENV_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::sys::env::common::Env>::new.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static STD_SYS_ENV_COMMON_ENV_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_ENV_COMMON_ENV_NEW_GEN_IMPORTS: &[&str] = &["<std::sys::env::common::Env>::new"];

pub static STD_SYS_ENV_COMMON_ENV_NEW_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::sys::env::common::env>::new_generated",
    description: "Generated profile for <std::sys::env::common::Env>::new from CodeQL/Pysa",
    detect_imports: STD_SYS_ENV_COMMON_ENV_NEW_GEN_IMPORTS,
    sources: STD_SYS_ENV_COMMON_ENV_NEW_GEN_SOURCES,
    sinks: STD_SYS_ENV_COMMON_ENV_NEW_GEN_SINKS,
    sanitizers: STD_SYS_ENV_COMMON_ENV_NEW_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
