//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SHELLJS_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "shelljs.Member[env]",
    pattern: SourceKind::MemberAccess("env"),
    taint_label: "env_input",
    description: "CodeQL source: Member[env] (kind: environment)",
}];

static SHELLJS_GEN_SINKS: &[SinkDef] = &[];

static SHELLJS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SHELLJS_GEN_IMPORTS: &[&str] = &["shelljs"];

pub static SHELLJS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "shelljs_generated",
    description: "Generated profile for shelljs from CodeQL/Pysa",
    detect_imports: SHELLJS_GEN_IMPORTS,
    sources: SHELLJS_GEN_SOURCES,
    sinks: SHELLJS_GEN_SINKS,
    sanitizers: SHELLJS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
