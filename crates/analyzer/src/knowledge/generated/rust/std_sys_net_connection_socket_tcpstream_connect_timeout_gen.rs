//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_SOURCES: &[SourceDef] =
    &[SourceDef {
        name: "<std::sys::net::connection::socket::TcpStream>::connect_timeout.ReturnValue",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue (kind: constant-source)",
    }];

static STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_IMPORTS: &[&str] =
    &["<std::sys::net::connection::socket::TcpStream>::connect_timeout"];

pub static STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys::net::connection::socket::tcpstream>::connect_timeout_generated",
        description: "Generated profile for <std::sys::net::connection::socket::TcpStream>::connect_timeout from CodeQL/Pysa",
        detect_imports: STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_IMPORTS,
        sources: STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_SOURCES,
        sinks: STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_SINKS,
        sanitizers: STD_SYS_NET_CONNECTION_SOCKET_TCPSTREAM_CONNECT_TIMEOUT_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
