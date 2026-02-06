//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio_test::io::Builder>::build_with_handle.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_IMPORTS: &[&str] =
    &["<tokio_test::io::Builder>::build_with_handle"];

pub static TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio_test::io::builder>::build_with_handle_generated",
        description: "Generated profile for <tokio_test::io::Builder>::build_with_handle from CodeQL/Pysa",
        detect_imports: TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_IMPORTS,
        sources: TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_SOURCES,
        sinks: TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_SINKS,
        sanitizers: TOKIO_TEST_IO_BUILDER_BUILD_WITH_HANDLE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
