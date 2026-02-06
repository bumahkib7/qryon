//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<std::os::unix::net::stream::UnixStream>::take_error.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_SINKS: &[SinkDef] = &[];

static STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_IMPORTS: &[&str] =
    &["<std::os::unix::net::stream::UnixStream>::take_error"];

pub static STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::os::unix::net::stream::unixstream>::take_error_generated",
        description: "Generated profile for <std::os::unix::net::stream::UnixStream>::take_error from CodeQL/Pysa",
        detect_imports: STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_IMPORTS,
        sources: STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_SOURCES,
        sinks: STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_SINKS,
        sanitizers: STD_OS_UNIX_NET_STREAM_UNIXSTREAM_TAKE_ERROR_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
