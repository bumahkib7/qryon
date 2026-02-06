//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_SOURCES: &[SourceDef] = &[];

static INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<intrinsic-test::common::intrinsic_helpers::TypeKind>::c_prefix.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_IMPORTS: &[&str] =
    &["<intrinsic-test::common::intrinsic_helpers::TypeKind>::c_prefix"];

pub static INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<intrinsic_test::common::intrinsic_helpers::typekind>::c_prefix_generated",
        description: "Generated profile for <intrinsic-test::common::intrinsic_helpers::TypeKind>::c_prefix from CodeQL/Pysa",
        detect_imports: INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_IMPORTS,
        sources: INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_SOURCES,
        sinks: INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_SINKS,
        sanitizers: INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_TYPEKIND_C_PREFIX_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
