//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AS_UTIL_PARSETUPLE_PARSE_GEN_SOURCES: &[SourceDef] = &[];

static AS_UTIL_PARSETUPLE_PARSE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<(,) as util::ParseTuple>::parse.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static AS_UTIL_PARSETUPLE_PARSE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AS_UTIL_PARSETUPLE_PARSE_GEN_IMPORTS: &[&str] = &["<(,) as util::ParseTuple>::parse"];

pub static AS_UTIL_PARSETUPLE_PARSE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<(,) as util::parsetuple>::parse_generated",
    description: "Generated profile for <(,) as util::ParseTuple>::parse from CodeQL/Pysa",
    detect_imports: AS_UTIL_PARSETUPLE_PARSE_GEN_IMPORTS,
    sources: AS_UTIL_PARSETUPLE_PARSE_GEN_SOURCES,
    sinks: AS_UTIL_PARSETUPLE_PARSE_GEN_SINKS,
    sanitizers: AS_UTIL_PARSETUPLE_PARSE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
