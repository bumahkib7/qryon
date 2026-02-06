//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<std::net::udp::UdpSocket>::broadcast.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_SINKS: &[SinkDef] = &[];

static STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_IMPORTS: &[&str] =
    &["<std::net::udp::UdpSocket>::broadcast"];

pub static STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::net::udp::udpsocket>::broadcast_generated",
    description: "Generated profile for <std::net::udp::UdpSocket>::broadcast from CodeQL/Pysa",
    detect_imports: STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_IMPORTS,
    sources: STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_SOURCES,
    sinks: STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_SINKS,
    sanitizers: STD_NET_UDP_UDPSOCKET_BROADCAST_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
