//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static _SOCKET_GEN_SOURCES: &[SourceDef] = &[];

static _SOCKET_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "_socket.socket.connect",
        pattern: SinkKind::FunctionCall("_socket.socket.connect"),
        rule_id: "python/gen-pysa-httpclientrequest_uri",
        severity: Severity::Error,
        description: "Pysa sink: _socket.socket.connect (kind: HTTPClientRequest_URI)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "_socket.socket.connect_ex",
        pattern: SinkKind::FunctionCall("_socket.socket.connect_ex"),
        rule_id: "python/gen-pysa-httpclientrequest_uri",
        severity: Severity::Error,
        description: "Pysa sink: _socket.socket.connect_ex (kind: HTTPClientRequest_URI)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "_socket.socket.send",
        pattern: SinkKind::FunctionCall("_socket.socket.send"),
        rule_id: "python/gen-pysa-httpclientrequest_data",
        severity: Severity::Error,
        description: "Pysa sink: _socket.socket.send (kind: HTTPClientRequest_DATA)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "_socket.socket.sendall",
        pattern: SinkKind::FunctionCall("_socket.socket.sendall"),
        rule_id: "python/gen-pysa-httpclientrequest_data",
        severity: Severity::Error,
        description: "Pysa sink: _socket.socket.sendall (kind: HTTPClientRequest_DATA)",
        cwe: Some("CWE-74"),
    },
];

static _SOCKET_GEN_SANITIZERS: &[SanitizerDef] = &[];

static _SOCKET_GEN_IMPORTS: &[&str] = &["_socket"];

pub static _SOCKET_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "_socket_generated",
    description: "Generated profile for _socket from CodeQL/Pysa",
    detect_imports: _SOCKET_GEN_IMPORTS,
    sources: _SOCKET_GEN_SOURCES,
    sinks: _SOCKET_GEN_SINKS,
    sanitizers: _SOCKET_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
