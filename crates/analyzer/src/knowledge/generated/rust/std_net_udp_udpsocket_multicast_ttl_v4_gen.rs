//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<std::net::udp::UdpSocket>::multicast_ttl_v4.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_SINKS: &[SinkDef] = &[];

static STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_IMPORTS: &[&str] =
    &["<std::net::udp::UdpSocket>::multicast_ttl_v4"];

pub static STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::net::udp::udpsocket>::multicast_ttl_v4_generated",
        description: "Generated profile for <std::net::udp::UdpSocket>::multicast_ttl_v4 from CodeQL/Pysa",
        detect_imports: STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_IMPORTS,
        sources: STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_SOURCES,
        sinks: STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_SINKS,
        sanitizers: STD_NET_UDP_UDPSOCKET_MULTICAST_TTL_V4_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
