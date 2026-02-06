//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static K8S_GEN_SOURCES: &[SourceDef] = &[];

static K8S_GEN_SINKS: &[SinkDef] = &[];

static K8S_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "k8s.io/apimachinery/pkg/runtime.Encode",
        pattern: SanitizerKind::Function("k8s.io/apimachinery/pkg/runtime..Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: k8s.io/apimachinery/pkg/runtime..Encode",
    },
    SanitizerDef {
        name: "k8s.io/apimachinery/pkg/runtime.EncodeOrDie",
        pattern: SanitizerKind::Function("k8s.io/apimachinery/pkg/runtime..EncodeOrDie"),
        sanitizes: "general",
        description: "CodeQL sanitizer: k8s.io/apimachinery/pkg/runtime..EncodeOrDie",
    },
    SanitizerDef {
        name: "k8s.io/apimachinery/pkg/runtime.CacheableObject.CacheEncode",
        pattern: SanitizerKind::Function(
            "k8s.io/apimachinery/pkg/runtime.CacheableObject.CacheEncode",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: k8s.io/apimachinery/pkg/runtime.CacheableObject.CacheEncode",
    },
    SanitizerDef {
        name: "k8s.io/apimachinery/pkg/runtime.Encoder.Encode",
        pattern: SanitizerKind::Function("k8s.io/apimachinery/pkg/runtime.Encoder.Encode"),
        sanitizes: "general",
        description: "CodeQL sanitizer: k8s.io/apimachinery/pkg/runtime.Encoder.Encode",
    },
    SanitizerDef {
        name: "k8s.io/apimachinery/pkg/runtime.ParameterCodec.EncodeParameters",
        pattern: SanitizerKind::Function(
            "k8s.io/apimachinery/pkg/runtime.ParameterCodec.EncodeParameters",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: k8s.io/apimachinery/pkg/runtime.ParameterCodec.EncodeParameters",
    },
];

static K8S_GEN_IMPORTS: &[&str] = &["k8s.io/api/core", "k8s.io/apimachinery/pkg/runtime"];

pub static K8S_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "k8s_generated",
    description: "Generated profile for k8s.io/api/core from CodeQL/Pysa",
    detect_imports: K8S_GEN_IMPORTS,
    sources: K8S_GEN_SOURCES,
    sinks: K8S_GEN_SINKS,
    sanitizers: K8S_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
