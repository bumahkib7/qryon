//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SOURCES:
    &[SourceDef] = &[];

static STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<stdarch-gen-arm::intrinsic::LLVMLink as quote::to_tokens::ToTokens>::to_tokens.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_IMPORTS:
    &[&str] = &["<stdarch-gen-arm::intrinsic::LLVMLink as quote::to_tokens::ToTokens>::to_tokens"];

pub static STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<stdarch_gen_arm::intrinsic::llvmlink as quote::to_tokens::totokens>::to_tokens_generated",
    description: "Generated profile for <stdarch-gen-arm::intrinsic::LLVMLink as quote::to_tokens::ToTokens>::to_tokens from CodeQL/Pysa",
    detect_imports:
        STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_IMPORTS,
    sources: STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SOURCES,
    sinks: STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SINKS,
    sanitizers:
        STDARCH_GEN_ARM_INTRINSIC_LLVMLINK_AS_QUOTE_TO_TOKENS_TOTOKENS_TO_TOKENS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
