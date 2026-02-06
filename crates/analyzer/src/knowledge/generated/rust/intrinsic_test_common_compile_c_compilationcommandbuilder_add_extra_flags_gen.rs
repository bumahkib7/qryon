//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_SOURCES:
    &[SourceDef] = &[];

static INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<intrinsic-test::common::compile_c::CompilationCommandBuilder>::add_extra_flags.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_IMPORTS:
    &[&str] = &["<intrinsic-test::common::compile_c::CompilationCommandBuilder>::add_extra_flags"];

pub static INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<intrinsic_test::common::compile_c::compilationcommandbuilder>::add_extra_flags_generated",
    description: "Generated profile for <intrinsic-test::common::compile_c::CompilationCommandBuilder>::add_extra_flags from CodeQL/Pysa",
    detect_imports:
        INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_IMPORTS,
    sources: INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_SOURCES,
    sinks: INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_SINKS,
    sanitizers:
        INTRINSIC_TEST_COMMON_COMPILE_C_COMPILATIONCOMMANDBUILDER_ADD_EXTRA_FLAGS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
