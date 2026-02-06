//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GOLANG_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "golang.org/x/net/websocket.Codec.Receive",
        pattern: SourceKind::MemberAccess("golang.org/x/net/websocket.Codec.Receive"),
        taint_label: "user_input",
        description: "CodeQL source: golang.org/x/net/websocket.Codec.Receive (kind: manual)",
    },
    SourceDef {
        name: "golang.org/x/net/websocket.Conn.Read",
        pattern: SourceKind::MemberAccess("golang.org/x/net/websocket.Conn.Read"),
        taint_label: "user_input",
        description: "CodeQL source: golang.org/x/net/websocket.Conn.Read (kind: manual)",
    },
];

static GOLANG_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "golang.org/x/crypto/ssh.Session.CombinedOutput",
        pattern: SinkKind::FunctionCall("golang.org/x/crypto/ssh.Session.CombinedOutput"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: golang.org/x/crypto/ssh.Session.CombinedOutput (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "golang.org/x/crypto/ssh.Session.Output",
        pattern: SinkKind::FunctionCall("golang.org/x/crypto/ssh.Session.Output"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: golang.org/x/crypto/ssh.Session.Output (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "golang.org/x/crypto/ssh.Session.Run",
        pattern: SinkKind::FunctionCall("golang.org/x/crypto/ssh.Session.Run"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: golang.org/x/crypto/ssh.Session.Run (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "golang.org/x/crypto/ssh.Session.Start",
        pattern: SinkKind::FunctionCall("golang.org/x/crypto/ssh.Session.Start"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: golang.org/x/crypto/ssh.Session.Start (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GOLANG_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "golang.org/x/net/html.EscapeString",
        pattern: SanitizerKind::Function("golang.org/x/net/html..EscapeString"),
        sanitizes: "html",
        description: "CodeQL sanitizer: golang.org/x/net/html..EscapeString",
    },
    SanitizerDef {
        name: "golang.org/x/net/html.UnescapeString",
        pattern: SanitizerKind::Function("golang.org/x/net/html..UnescapeString"),
        sanitizes: "html",
        description: "CodeQL sanitizer: golang.org/x/net/html..UnescapeString",
    },
];

static GOLANG_GEN_IMPORTS: &[&str] = &[
    "golang.org/x/net/html",
    "golang.org/x/net/websocket",
    "golang.org/x/net/context",
    "golang.org/x/crypto/ssh",
];

pub static GOLANG_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "golang_generated",
    description: "Generated profile for golang.org/x/net/html from CodeQL/Pysa",
    detect_imports: GOLANG_GEN_IMPORTS,
    sources: GOLANG_GEN_SOURCES,
    sinks: GOLANG_GEN_SINKS,
    sanitizers: GOLANG_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
