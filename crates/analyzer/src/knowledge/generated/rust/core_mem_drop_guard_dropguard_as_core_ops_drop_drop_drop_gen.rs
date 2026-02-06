//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_SOURCES: &[SourceDef] = &[];

static CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<core::mem::drop_guard::DropGuard as core::ops::drop::Drop>::drop.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    }];

static CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_IMPORTS: &[&str] =
    &["<core::mem::drop_guard::DropGuard as core::ops::drop::Drop>::drop"];

pub static CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::mem::drop_guard::dropguard as core::ops::drop::drop>::drop_generated",
        description: "Generated profile for <core::mem::drop_guard::DropGuard as core::ops::drop::Drop>::drop from CodeQL/Pysa",
        detect_imports: CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_IMPORTS,
        sources: CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_SOURCES,
        sinks: CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_SINKS,
        sanitizers: CORE_MEM_DROP_GUARD_DROPGUARD_AS_CORE_OPS_DROP_DROP_DROP_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
