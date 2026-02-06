//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ATL_GEN_SOURCES: &[SourceDef] = &[];

static ATL_GEN_SINKS: &[SinkDef] = &[];

static ATL_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "ATL.CComSafeArray.CComSafeArray",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.CComSafeArray"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.CComSafeArray",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.Add",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.Add"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.Add",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray<T>.Add",
        pattern: SanitizerKind::Function("ATL.CComSafeArray<T>.Add"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray<T>.Add",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.Attach",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.Attach"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.Attach",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.CopyFrom",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.CopyFrom"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.CopyFrom",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.CopyTo",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.CopyTo"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.CopyTo",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.GetAt",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.GetAt"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.GetAt",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.GetLowerBound",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.GetLowerBound"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.GetLowerBound",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.GetSafeArrayPtr",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.GetSafeArrayPtr"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.GetSafeArrayPtr",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.GetUpperBound",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.GetUpperBound"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.GetUpperBound",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.MultiDimGetAt",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.MultiDimGetAt"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.MultiDimGetAt",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.MultiDimSetAt",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.MultiDimSetAt"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.MultiDimSetAt",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.SetAt",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.SetAt"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.SetAt",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.operator LPSAFEARRAY",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.operator LPSAFEARRAY"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.operator LPSAFEARRAY",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.operator[]",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.operator[]"),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.operator[]",
    },
    SanitizerDef {
        name: "ATL.CComSafeArray.operator=",
        pattern: SanitizerKind::Function("ATL.CComSafeArray.operator="),
        sanitizes: "general",
        description: "CodeQL sanitizer: ATL.CComSafeArray.operator=",
    },
];

static ATL_GEN_IMPORTS: &[&str] = &["ATL"];

pub static ATL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "atl_generated",
    description: "Generated profile for ATL from CodeQL/Pysa",
    detect_imports: ATL_GEN_IMPORTS,
    sources: ATL_GEN_SOURCES,
    sinks: ATL_GEN_SINKS,
    sanitizers: ATL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
