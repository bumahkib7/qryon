//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static BOOST_ASIO_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "boost::asio.read",
        pattern: SourceKind::MemberAccess("boost::asio.read"),
        taint_label: "user_input",
        description: "CodeQL source: boost::asio..read (kind: manual)",
    },
    SourceDef {
        name: "boost::asio.read_at",
        pattern: SourceKind::MemberAccess("boost::asio.read_at"),
        taint_label: "user_input",
        description: "CodeQL source: boost::asio..read_at (kind: manual)",
    },
    SourceDef {
        name: "boost::asio.read_until",
        pattern: SourceKind::MemberAccess("boost::asio.read_until"),
        taint_label: "user_input",
        description: "CodeQL source: boost::asio..read_until (kind: manual)",
    },
    SourceDef {
        name: "boost::asio.async_read",
        pattern: SourceKind::MemberAccess("boost::asio.async_read"),
        taint_label: "user_input",
        description: "CodeQL source: boost::asio..async_read (kind: manual)",
    },
    SourceDef {
        name: "boost::asio.async_read_at",
        pattern: SourceKind::MemberAccess("boost::asio.async_read_at"),
        taint_label: "user_input",
        description: "CodeQL source: boost::asio..async_read_at (kind: manual)",
    },
    SourceDef {
        name: "boost::asio.async_read_until",
        pattern: SourceKind::MemberAccess("boost::asio.async_read_until"),
        taint_label: "user_input",
        description: "CodeQL source: boost::asio..async_read_until (kind: manual)",
    },
];

static BOOST_ASIO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "boost::asio.write",
        pattern: SinkKind::FunctionCall("boost::asio.write"),
        rule_id: "cpp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: boost::asio..write (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "boost::asio.write_at",
        pattern: SinkKind::FunctionCall("boost::asio.write_at"),
        rule_id: "cpp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: boost::asio..write_at (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "boost::asio.async_write",
        pattern: SinkKind::FunctionCall("boost::asio.async_write"),
        rule_id: "cpp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: boost::asio..async_write (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "boost::asio.async_write_at",
        pattern: SinkKind::FunctionCall("boost::asio.async_write_at"),
        rule_id: "cpp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: boost::asio..async_write_at (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static BOOST_ASIO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static BOOST_ASIO_GEN_IMPORTS: &[&str] = &["boost::asio"];

pub static BOOST_ASIO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "boost::asio_generated",
    description: "Generated profile for boost::asio from CodeQL/Pysa",
    detect_imports: BOOST_ASIO_GEN_IMPORTS,
    sources: BOOST_ASIO_GEN_SOURCES,
    sinks: BOOST_ASIO_GEN_SINKS,
    sanitizers: BOOST_ASIO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
