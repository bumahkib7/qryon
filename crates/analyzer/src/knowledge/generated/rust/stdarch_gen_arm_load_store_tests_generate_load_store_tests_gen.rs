//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_SOURCES: &[SourceDef] =
    &[SourceDef {
        name: "stdarch-gen-arm::load_store_tests::generate_load_store_tests.ReturnValue",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "file_input",
        description: "CodeQL source: ReturnValue (kind: file)",
    }];

static STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "stdarch-gen-arm::load_store_tests::generate_load_store_tests.Argument[2]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Argument[2] (kind: path-injection)",
        cwe: Some("CWE-22"),
    }];

static STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_IMPORTS: &[&str] =
    &["stdarch-gen-arm::load_store_tests::generate_load_store_tests"];

pub static STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "stdarch_gen_arm::load_store_tests::generate_load_store_tests_generated",
    description: "Generated profile for stdarch-gen-arm::load_store_tests::generate_load_store_tests from CodeQL/Pysa",
    detect_imports: STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_IMPORTS,
    sources: STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_SOURCES,
    sinks: STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_SINKS,
    sanitizers: STDARCH_GEN_ARM_LOAD_STORE_TESTS_GENERATE_LOAD_STORE_TESTS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
