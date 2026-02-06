//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_SOURCES:
    &[SourceDef] = &[];

static STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<std::sys::process::unix::common::cstring_array::CStringArray>::with_capacity.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_IMPORTS: &[&str] =
    &["<std::sys::process::unix::common::cstring_array::CStringArray>::with_capacity"];

pub static STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<std::sys::process::unix::common::cstring_array::cstringarray>::with_capacity_generated",
    description: "Generated profile for <std::sys::process::unix::common::cstring_array::CStringArray>::with_capacity from CodeQL/Pysa",
    detect_imports:
        STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_IMPORTS,
    sources: STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_SOURCES,
    sinks: STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_SINKS,
    sanitizers: STD_SYS_PROCESS_UNIX_COMMON_CSTRING_ARRAY_CSTRINGARRAY_WITH_CAPACITY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
