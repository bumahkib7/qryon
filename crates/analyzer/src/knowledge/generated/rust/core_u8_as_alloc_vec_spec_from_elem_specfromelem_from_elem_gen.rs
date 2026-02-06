//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_SOURCES: &[SourceDef] = &[];

static CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<core::u8 as alloc::vec::spec_from_elem::SpecFromElem>::from_elem.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    }];

static CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_IMPORTS: &[&str] =
    &["<core::u8 as alloc::vec::spec_from_elem::SpecFromElem>::from_elem"];

pub static CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<core::u8 as alloc::vec::spec_from_elem::specfromelem>::from_elem_generated",
    description: "Generated profile for <core::u8 as alloc::vec::spec_from_elem::SpecFromElem>::from_elem from CodeQL/Pysa",
    detect_imports: CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_IMPORTS,
    sources: CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_SOURCES,
    sinks: CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_SINKS,
    sanitizers: CORE_U8_AS_ALLOC_VEC_SPEC_FROM_ELEM_SPECFROMELEM_FROM_ELEM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
