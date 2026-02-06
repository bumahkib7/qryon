//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<tokio::net::unix::pipe::OpenOptions>::open_receiver.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_SINKS: &[SinkDef] = &[];

static TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_IMPORTS: &[&str] =
    &["<tokio::net::unix::pipe::OpenOptions>::open_receiver"];

pub static TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::net::unix::pipe::openoptions>::open_receiver_generated",
        description: "Generated profile for <tokio::net::unix::pipe::OpenOptions>::open_receiver from CodeQL/Pysa",
        detect_imports: TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_IMPORTS,
        sources: TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_SOURCES,
        sinks: TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_SINKS,
        sanitizers: TOKIO_NET_UNIX_PIPE_OPENOPTIONS_OPEN_RECEIVER_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
