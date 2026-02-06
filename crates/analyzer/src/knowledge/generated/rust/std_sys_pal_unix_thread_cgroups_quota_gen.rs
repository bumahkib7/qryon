//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::sys::pal::unix::thread::cgroups::quota.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_IMPORTS: &[&str] =
    &["std::sys::pal::unix::thread::cgroups::quota"];

pub static STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::sys::pal::unix::thread::cgroups::quota_generated",
    description: "Generated profile for std::sys::pal::unix::thread::cgroups::quota from CodeQL/Pysa",
    detect_imports: STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_IMPORTS,
    sources: STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_SOURCES,
    sinks: STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_SINKS,
    sanitizers: STD_SYS_PAL_UNIX_THREAD_CGROUPS_QUOTA_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
