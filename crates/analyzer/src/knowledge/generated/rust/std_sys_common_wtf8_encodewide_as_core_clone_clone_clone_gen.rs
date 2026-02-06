//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<std::sys_common::wtf8::EncodeWide as core::clone::Clone>::clone.Argument[self].Field[std::sys_common::wtf8::EncodeWide::extra]",
        pattern: SanitizerKind::Function(
            "Argument[self].Field[std::sys_common::wtf8::EncodeWide::extra]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[std::sys_common::wtf8::EncodeWide::extra]",
    },
];

static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS: &[&str] =
    &["<std::sys_common::wtf8::EncodeWide as core::clone::Clone>::clone"];

pub static STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys_common::wtf8::encodewide as core::clone::clone>::clone_generated",
        description: "Generated profile for <std::sys_common::wtf8::EncodeWide as core::clone::Clone>::clone from CodeQL/Pysa",
        detect_imports: STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS,
        sources: STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES,
        sinks: STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS,
        sanitizers: STD_SYS_COMMON_WTF8_ENCODEWIDE_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
