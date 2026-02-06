//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES:
    &[SourceDef] = &[];

static TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<tokio_test::stream_mock::StreamMockBuilder as core::clone::Clone>::clone.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS: &[&str] =
    &["<tokio_test::stream_mock::StreamMockBuilder as core::clone::Clone>::clone"];

pub static TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<tokio_test::stream_mock::streammockbuilder as core::clone::clone>::clone_generated",
    description: "Generated profile for <tokio_test::stream_mock::StreamMockBuilder as core::clone::Clone>::clone from CodeQL/Pysa",
    detect_imports: TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS,
    sources: TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES,
    sinks: TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS,
    sanitizers: TOKIO_TEST_STREAM_MOCK_STREAMMOCKBUILDER_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
