//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_SINKS: &[SinkDef] = &[];

static ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "<actix_web::config::AppConfig>::secure.Argument[self].Reference.Field[actix_web::config::AppConfig::secure]",
    pattern: SanitizerKind::Function(
        "Argument[self].Reference.Field[actix_web::config::AppConfig::secure]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Reference.Field[actix_web::config::AppConfig::secure]",
}];

static ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_IMPORTS: &[&str] =
    &["<actix_web::config::AppConfig>::secure"];

pub static ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_web::config::appconfig>::secure_generated",
    description: "Generated profile for <actix_web::config::AppConfig>::secure from CodeQL/Pysa",
    detect_imports: ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_IMPORTS,
    sources: ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_SOURCES,
    sinks: ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_SINKS,
    sanitizers: ACTIX_WEB_CONFIG_APPCONFIG_SECURE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
