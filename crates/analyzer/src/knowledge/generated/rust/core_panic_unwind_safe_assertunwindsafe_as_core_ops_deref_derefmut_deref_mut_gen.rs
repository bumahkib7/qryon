//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_SOURCES:
    &[SourceDef] = &[];

static CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_SINKS:
    &[SinkDef] = &[];

static CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<core::panic::unwind_safe::AssertUnwindSafe as core::ops::deref::DerefMut>::deref_mut.Argument[self].Reference.Field[core::panic::unwind_safe::AssertUnwindSafe(0)]",
        pattern: SanitizerKind::Function("Argument[self].Reference.Field[core::panic::unwind_safe::AssertUnwindSafe(0)]"),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Reference.Field[core::panic::unwind_safe::AssertUnwindSafe(0)]",
    },
];

static CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_IMPORTS:
    &[&str] =
    &["<core::panic::unwind_safe::AssertUnwindSafe as core::ops::deref::DerefMut>::deref_mut"];

pub static CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<core::panic::unwind_safe::assertunwindsafe as core::ops::deref::derefmut>::deref_mut_generated",
    description: "Generated profile for <core::panic::unwind_safe::AssertUnwindSafe as core::ops::deref::DerefMut>::deref_mut from CodeQL/Pysa",
    detect_imports: CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_IMPORTS,
    sources: CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_SOURCES,
    sinks: CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_SINKS,
    sanitizers: CORE_PANIC_UNWIND_SAFE_ASSERTUNWINDSAFE_AS_CORE_OPS_DEREF_DEREFMUT_DEREF_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
