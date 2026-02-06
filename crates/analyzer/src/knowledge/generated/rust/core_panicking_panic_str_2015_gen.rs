//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_PANICKING_PANIC_STR_2015_GEN_SOURCES: &[SourceDef] = &[];

static CORE_PANICKING_PANIC_STR_2015_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "core::panicking::panic_str_2015.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CORE_PANICKING_PANIC_STR_2015_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_PANICKING_PANIC_STR_2015_GEN_IMPORTS: &[&str] = &["core::panicking::panic_str_2015"];

pub static CORE_PANICKING_PANIC_STR_2015_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "core::panicking::panic_str_2015_generated",
    description: "Generated profile for core::panicking::panic_str_2015 from CodeQL/Pysa",
    detect_imports: CORE_PANICKING_PANIC_STR_2015_GEN_IMPORTS,
    sources: CORE_PANICKING_PANIC_STR_2015_GEN_SOURCES,
    sinks: CORE_PANICKING_PANIC_STR_2015_GEN_SINKS,
    sanitizers: CORE_PANICKING_PANIC_STR_2015_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
