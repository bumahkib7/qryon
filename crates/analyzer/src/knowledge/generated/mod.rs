//! Auto-generated framework security knowledge
//!
//! Generated from CodeQL Models-as-Data and Pysa taint stubs.
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::FrameworkProfile;
use rma_common::Language;

#[allow(warnings)]
mod cpp;
#[allow(warnings)]
mod csharp;
#[allow(warnings)]
mod go;
#[allow(warnings)]
mod java;
#[allow(warnings)]
mod javascript;
#[allow(warnings)]
mod python;
#[allow(warnings)]
mod rust;

/// Get generated framework profiles for the given language.
pub fn profiles_for_language(language: Language) -> Vec<&'static FrameworkProfile> {
    match language {
        Language::C | Language::Cpp => cpp::generated_profiles(),
        Language::CSharp => csharp::generated_profiles(),
        Language::Go => go::generated_profiles(),
        Language::Java | Language::Kotlin | Language::Scala => java::generated_profiles(),
        Language::JavaScript | Language::TypeScript => javascript::generated_profiles(),
        Language::Python => python::generated_profiles(),
        Language::Rust => rust::generated_profiles(),
        _ => vec![],
    }
}
