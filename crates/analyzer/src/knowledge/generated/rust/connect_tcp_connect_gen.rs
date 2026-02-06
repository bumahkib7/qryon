//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CONNECT_TCP_CONNECT_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "connect-tcp::connect.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: remote)",
}];

static CONNECT_TCP_CONNECT_GEN_SINKS: &[SinkDef] = &[];

static CONNECT_TCP_CONNECT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CONNECT_TCP_CONNECT_GEN_IMPORTS: &[&str] = &["connect-tcp::connect"];

pub static CONNECT_TCP_CONNECT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "connect_tcp::connect_generated",
    description: "Generated profile for connect-tcp::connect from CodeQL/Pysa",
    detect_imports: CONNECT_TCP_CONNECT_GEN_IMPORTS,
    sources: CONNECT_TCP_CONNECT_GEN_SOURCES,
    sinks: CONNECT_TCP_CONNECT_GEN_SINKS,
    sanitizers: CONNECT_TCP_CONNECT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
