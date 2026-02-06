//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_SOURCES: &[SourceDef] = &[
];

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_SINKS: &[SinkDef] = &[
];

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<actix_http::encoding::encoder::EncoderBody as actix_http::body::message_body::MessageBody>::try_into_bytes.Argument[self].Field[actix_http::encoding::encoder::EncoderBody::Full::body]",
        pattern: SanitizerKind::Function("Argument[self].Field[actix_http::encoding::encoder::EncoderBody::Full::body]"),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[actix_http::encoding::encoder::EncoderBody::Full::body]",
    },
];

static ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_IMPORTS: &[&str] = &[
    "<actix_http::encoding::encoder::EncoderBody as actix_http::body::message_body::MessageBody>::try_into_bytes",
];

pub static ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_http::encoding::encoder::encoderbody as actix_http::body::message_body::messagebody>::try_into_bytes_generated",
    description: "Generated profile for <actix_http::encoding::encoder::EncoderBody as actix_http::body::message_body::MessageBody>::try_into_bytes from CodeQL/Pysa",
    detect_imports: ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_IMPORTS,
    sources: ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_SOURCES,
    sinks: ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_SINKS,
    sanitizers: ACTIX_HTTP_ENCODING_ENCODER_ENCODERBODY_AS_ACTIX_HTTP_BODY_MESSAGE_BODY_MESSAGEBODY_TRY_INTO_BYTES_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
