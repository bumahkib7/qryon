//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTERNAL_GEN_SOURCES: &[SourceDef] = &[];

static INTERNAL_GEN_SINKS: &[SinkDef] = &[];

static INTERNAL_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "Internal.Pgo.PgoProcessor+PgoEncodedCompressedIntParser.GetEnumerator",
        pattern: SanitizerKind::Function(
            "Internal.Pgo.PgoProcessor+PgoEncodedCompressedIntParser.GetEnumerator",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Internal.Pgo.PgoProcessor+PgoEncodedCompressedIntParser.GetEnumerator",
    },
    SanitizerDef {
        name: "Internal.Pgo.PgoProcessor+PgoEncodedCompressedIntParser.PgoEncodedCompressedIntParser",
        pattern: SanitizerKind::Function(
            "Internal.Pgo.PgoProcessor+PgoEncodedCompressedIntParser.PgoEncodedCompressedIntParser",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Internal.Pgo.PgoProcessor+PgoEncodedCompressedIntParser.PgoEncodedCompressedIntParser",
    },
    SanitizerDef {
        name: "Internal.TypeSystem.Ecma.EcmaSignatureEncoder<TEntityHandleProvider>.EcmaSignatureEncoder",
        pattern: SanitizerKind::Function(
            "Internal.TypeSystem.Ecma.EcmaSignatureEncoder<TEntityHandleProvider>.EcmaSignatureEncoder",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Internal.TypeSystem.Ecma.EcmaSignatureEncoder<TEntityHandleProvider>.EcmaSignatureEncoder",
    },
    SanitizerDef {
        name: "Internal.IL.UnsafeAccessors.TryGetIL",
        pattern: SanitizerKind::Function("Internal.IL.UnsafeAccessors.TryGetIL"),
        sanitizes: "general",
        description: "CodeQL sanitizer: Internal.IL.UnsafeAccessors.TryGetIL",
    },
    SanitizerDef {
        name: "Internal.TypeSystem.ParameterizedType.get_ParameterType",
        pattern: SanitizerKind::Function("Internal.TypeSystem.ParameterizedType.get_ParameterType"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: Internal.TypeSystem.ParameterizedType.get_ParameterType",
    },
];

static INTERNAL_GEN_IMPORTS: &[&str] = &[
    "Internal.Pgo",
    "Internal.NativeFormat",
    "Internal",
    "Internal.IL.Stubs",
    "Internal.TypeSystem.Ecma",
    "Internal.IL",
    "Internal.TypeSystem",
];

pub static INTERNAL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "internal_generated",
    description: "Generated profile for Internal.Pgo from CodeQL/Pysa",
    detect_imports: INTERNAL_GEN_IMPORTS,
    sources: INTERNAL_GEN_SOURCES,
    sinks: INTERNAL_GEN_SINKS,
    sanitizers: INTERNAL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
