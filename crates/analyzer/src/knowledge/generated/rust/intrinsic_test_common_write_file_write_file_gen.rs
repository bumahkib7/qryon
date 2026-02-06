//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_SOURCES: &[SourceDef] = &[];

static INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "intrinsic-test::common::write_file::write_file.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_IMPORTS: &[&str] =
    &["intrinsic-test::common::write_file::write_file"];

pub static INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "intrinsic_test::common::write_file::write_file_generated",
        description: "Generated profile for intrinsic-test::common::write_file::write_file from CodeQL/Pysa",
        detect_imports: INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_IMPORTS,
        sources: INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_SOURCES,
        sinks: INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_SINKS,
        sanitizers: INTRINSIC_TEST_COMMON_WRITE_FILE_WRITE_FILE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
