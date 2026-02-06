//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<std::sys::net::connection::socket::TcpListener>::ttl.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_IMPORTS: &[&str] =
    &["<std::sys::net::connection::socket::TcpListener>::ttl"];

pub static STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys::net::connection::socket::tcplistener>::ttl_generated",
        description: "Generated profile for <std::sys::net::connection::socket::TcpListener>::ttl from CodeQL/Pysa",
        detect_imports: STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_IMPORTS,
        sources: STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_SOURCES,
        sinks: STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_SINKS,
        sanitizers: STD_SYS_NET_CONNECTION_SOCKET_TCPLISTENER_TTL_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
