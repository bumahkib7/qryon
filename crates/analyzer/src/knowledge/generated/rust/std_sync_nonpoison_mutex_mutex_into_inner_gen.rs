//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_SINKS: &[SinkDef] = &[];

static STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<std::sync::nonpoison::mutex::Mutex>::into_inner.Argument[self].Field[std::sync::nonpoison::mutex::Mutex::data].Field[core::cell::UnsafeCell::value]",
        pattern: SanitizerKind::Function(
            "Argument[self].Field[std::sync::nonpoison::mutex::Mutex::data].Field[core::cell::UnsafeCell::value]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[std::sync::nonpoison::mutex::Mutex::data].Field[core::cell::UnsafeCell::value]",
    },
];

static STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_IMPORTS: &[&str] =
    &["<std::sync::nonpoison::mutex::Mutex>::into_inner"];

pub static STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sync::nonpoison::mutex::mutex>::into_inner_generated",
        description: "Generated profile for <std::sync::nonpoison::mutex::Mutex>::into_inner from CodeQL/Pysa",
        detect_imports: STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_IMPORTS,
        sources: STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_SOURCES,
        sinks: STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_SINKS,
        sanitizers: STD_SYNC_NONPOISON_MUTEX_MUTEX_INTO_INNER_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
