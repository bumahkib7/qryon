//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_SOURCES:
    &[SourceDef] = &[SourceDef {
    name: "<std::net::tcp::TcpStream as std::os::net::linux_ext::tcp::TcpStreamExt>::deferaccept.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_SINKS:
    &[SinkDef] = &[];

static STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_IMPORTS:
    &[&str] =
    &["<std::net::tcp::TcpStream as std::os::net::linux_ext::tcp::TcpStreamExt>::deferaccept"];

pub static STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::net::tcp::tcpstream as std::os::net::linux_ext::tcp::tcpstreamext>::deferaccept_generated",
    description: "Generated profile for <std::net::tcp::TcpStream as std::os::net::linux_ext::tcp::TcpStreamExt>::deferaccept from CodeQL/Pysa",
    detect_imports: STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_IMPORTS,
    sources: STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_SOURCES,
    sinks: STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_SINKS,
    sanitizers: STD_NET_TCP_TCPSTREAM_AS_STD_OS_NET_LINUX_EXT_TCP_TCPSTREAMEXT_DEFERACCEPT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
