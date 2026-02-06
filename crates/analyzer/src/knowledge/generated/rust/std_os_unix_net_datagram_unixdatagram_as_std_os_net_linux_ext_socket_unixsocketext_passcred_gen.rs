//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "<std::os::unix::net::datagram::UnixDatagram as std::os::net::linux_ext::socket::UnixSocketExt>::passcred.ReturnValue",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue (kind: constant-source)",
    },
];

static STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_SINKS: &[SinkDef] = &[
];

static STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_IMPORTS: &[&str] = &[
    "<std::os::unix::net::datagram::UnixDatagram as std::os::net::linux_ext::socket::UnixSocketExt>::passcred",
];

pub static STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::os::unix::net::datagram::unixdatagram as std::os::net::linux_ext::socket::unixsocketext>::passcred_generated",
    description: "Generated profile for <std::os::unix::net::datagram::UnixDatagram as std::os::net::linux_ext::socket::UnixSocketExt>::passcred from CodeQL/Pysa",
    detect_imports: STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_IMPORTS,
    sources: STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_SOURCES,
    sinks: STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_SINKS,
    sanitizers: STD_OS_UNIX_NET_DATAGRAM_UNIXDATAGRAM_AS_STD_OS_NET_LINUX_EXT_SOCKET_UNIXSOCKETEXT_PASSCRED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
