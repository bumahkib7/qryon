//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_SOURCES: &[SourceDef] = &[
];

static INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<intrinsic-test::arm::intrinsic::ArmIntrinsicType as intrinsic-test::common::intrinsic_helpers::IntrinsicTypeDefinition>::rust_type.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_IMPORTS: &[&str] = &[
    "<intrinsic-test::arm::intrinsic::ArmIntrinsicType as intrinsic-test::common::intrinsic_helpers::IntrinsicTypeDefinition>::rust_type",
];

pub static INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<intrinsic_test::arm::intrinsic::armintrinsictype as intrinsic_test::common::intrinsic_helpers::intrinsictypedefinition>::rust_type_generated",
    description: "Generated profile for <intrinsic-test::arm::intrinsic::ArmIntrinsicType as intrinsic-test::common::intrinsic_helpers::IntrinsicTypeDefinition>::rust_type from CodeQL/Pysa",
    detect_imports: INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_IMPORTS,
    sources: INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_SOURCES,
    sinks: INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_SINKS,
    sanitizers: INTRINSIC_TEST_ARM_INTRINSIC_ARMINTRINSICTYPE_AS_INTRINSIC_TEST_COMMON_INTRINSIC_HELPERS_INTRINSICTYPEDEFINITION_RUST_TYPE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
