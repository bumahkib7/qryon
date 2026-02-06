//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_SOURCES: &[SourceDef] = &[];

static LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<libm_test::domain::EitherPrim>::unwrap_float.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_IMPORTS: &[&str] =
    &["<libm_test::domain::EitherPrim>::unwrap_float"];

pub static LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<libm_test::domain::eitherprim>::unwrap_float_generated",
        description: "Generated profile for <libm_test::domain::EitherPrim>::unwrap_float from CodeQL/Pysa",
        detect_imports: LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_IMPORTS,
        sources: LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_SOURCES,
        sinks: LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_SINKS,
        sanitizers: LIBM_TEST_DOMAIN_EITHERPRIM_UNWRAP_FLOAT_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
