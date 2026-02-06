//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_SOURCES: &[SourceDef] = &[
];

static TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<tokio::process::imp::reap::test::MockStream as tokio::signal::unix::InternalStream>::poll_recv.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_IMPORTS: &[&str] = &[
    "<tokio::process::imp::reap::test::MockStream as tokio::signal::unix::InternalStream>::poll_recv",
];

pub static TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::process::imp::reap::test::mockstream as tokio::signal::unix::internalstream>::poll_recv_generated",
    description: "Generated profile for <tokio::process::imp::reap::test::MockStream as tokio::signal::unix::InternalStream>::poll_recv from CodeQL/Pysa",
    detect_imports: TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_IMPORTS,
    sources: TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_SOURCES,
    sinks: TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_SINKS,
    sanitizers: TOKIO_PROCESS_IMP_REAP_TEST_MOCKSTREAM_AS_TOKIO_SIGNAL_UNIX_INTERNALSTREAM_POLL_RECV_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
