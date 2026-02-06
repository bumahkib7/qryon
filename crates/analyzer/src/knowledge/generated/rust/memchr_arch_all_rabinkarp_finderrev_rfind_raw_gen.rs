//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_SOURCES: &[SourceDef] = &[];

static MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<memchr::arch::all::rabinkarp::FinderRev>::rfind_raw.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "<memchr::arch::all::rabinkarp::FinderRev>::rfind_raw.Argument[2]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[2] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_IMPORTS: &[&str] =
    &["<memchr::arch::all::rabinkarp::FinderRev>::rfind_raw"];

pub static MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<memchr::arch::all::rabinkarp::finderrev>::rfind_raw_generated",
        description: "Generated profile for <memchr::arch::all::rabinkarp::FinderRev>::rfind_raw from CodeQL/Pysa",
        detect_imports: MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_IMPORTS,
        sources: MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_SOURCES,
        sinks: MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_SINKS,
        sanitizers: MEMCHR_ARCH_ALL_RABINKARP_FINDERREV_RFIND_RAW_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
