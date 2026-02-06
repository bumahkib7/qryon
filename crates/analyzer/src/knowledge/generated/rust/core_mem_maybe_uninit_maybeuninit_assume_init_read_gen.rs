//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_SOURCES: &[SourceDef] = &[];

static CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<core::mem::maybe_uninit::MaybeUninit>::assume_init_read.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_IMPORTS: &[&str] =
    &["<core::mem::maybe_uninit::MaybeUninit>::assume_init_read"];

pub static CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::mem::maybe_uninit::maybeuninit>::assume_init_read_generated",
        description: "Generated profile for <core::mem::maybe_uninit::MaybeUninit>::assume_init_read from CodeQL/Pysa",
        detect_imports: CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_IMPORTS,
        sources: CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_SOURCES,
        sinks: CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_SINKS,
        sanitizers: CORE_MEM_MAYBE_UNINIT_MAYBEUNINIT_ASSUME_INIT_READ_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
