//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "hyper::ffi::http_types::hyper_request_headers.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_SINKS: &[SinkDef] = &[];

static HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_IMPORTS: &[&str] =
    &["hyper::ffi::http_types::hyper_request_headers"];

pub static HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "hyper::ffi::http_types::hyper_request_headers_generated",
        description: "Generated profile for hyper::ffi::http_types::hyper_request_headers from CodeQL/Pysa",
        detect_imports: HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_IMPORTS,
        sources: HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_SOURCES,
        sinks: HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_SINKS,
        sanitizers: HYPER_FFI_HTTP_TYPES_HYPER_REQUEST_HEADERS_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
