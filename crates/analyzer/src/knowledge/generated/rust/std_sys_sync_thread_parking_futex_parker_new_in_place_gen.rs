//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::sys::sync::thread_parking::futex::Parker>::new_in_place.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_IMPORTS: &[&str] =
    &["<std::sys::sync::thread_parking::futex::Parker>::new_in_place"];

pub static STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys::sync::thread_parking::futex::parker>::new_in_place_generated",
        description: "Generated profile for <std::sys::sync::thread_parking::futex::Parker>::new_in_place from CodeQL/Pysa",
        detect_imports: STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_IMPORTS,
        sources: STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_SOURCES,
        sinks: STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_SINKS,
        sanitizers: STD_SYS_SYNC_THREAD_PARKING_FUTEX_PARKER_NEW_IN_PLACE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
