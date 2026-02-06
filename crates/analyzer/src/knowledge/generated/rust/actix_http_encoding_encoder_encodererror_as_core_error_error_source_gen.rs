//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_SOURCES:
    &[SourceDef] = &[];

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_SINKS: &[SinkDef] =
    &[];

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_SANITIZERS:
    &[SanitizerDef] = &[SanitizerDef {
    name: "<actix_http::encoding::encoder::EncoderError as core::error::Error>::source.Argument[self].Field[actix_http::encoding::encoder::EncoderError::Io(0)]",
    pattern: SanitizerKind::Function(
        "Argument[self].Field[actix_http::encoding::encoder::EncoderError::Io(0)]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Field[actix_http::encoding::encoder::EncoderError::Io(0)]",
}];

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_IMPORTS: &[&str] =
    &["<actix_http::encoding::encoder::EncoderError as core::error::Error>::source"];

pub static ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<actix_http::encoding::encoder::encodererror as core::error::error>::source_generated",
    description: "Generated profile for <actix_http::encoding::encoder::EncoderError as core::error::Error>::source from CodeQL/Pysa",
    detect_imports: ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_IMPORTS,
    sources: ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_SOURCES,
    sinks: ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_SINKS,
    sanitizers: ACTIX_HTTP_ENCODING_ENCODER_ENCODERERROR_AS_CORE_ERROR_ERROR_SOURCE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
