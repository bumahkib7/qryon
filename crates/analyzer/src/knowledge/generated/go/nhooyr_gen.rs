//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static NHOOYR_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "nhooyr.io/websocket.Conn.Read",
        pattern: SourceKind::MemberAccess("nhooyr.io/websocket.Conn.Read"),
        taint_label: "user_input",
        description: "CodeQL source: nhooyr.io/websocket.Conn.Read (kind: manual)",
    },
    SourceDef {
        name: "nhooyr.io/websocket.Conn.Reader",
        pattern: SourceKind::MemberAccess("nhooyr.io/websocket.Conn.Reader"),
        taint_label: "user_input",
        description: "CodeQL source: nhooyr.io/websocket.Conn.Reader (kind: manual)",
    },
];

static NHOOYR_GEN_SINKS: &[SinkDef] = &[];

static NHOOYR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static NHOOYR_GEN_IMPORTS: &[&str] = &["nhooyr.io/websocket"];

pub static NHOOYR_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "nhooyr_generated",
    description: "Generated profile for nhooyr.io/websocket from CodeQL/Pysa",
    detect_imports: NHOOYR_GEN_IMPORTS,
    sources: NHOOYR_GEN_SOURCES,
    sinks: NHOOYR_GEN_SINKS,
    sanitizers: NHOOYR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
