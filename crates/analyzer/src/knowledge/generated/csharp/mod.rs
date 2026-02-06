//! Auto-generated csharp framework profiles
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::FrameworkProfile;

mod amazon_gen;
mod dapper_gen;
mod ilcompiler_gen;
mod internal_gen;
mod microsoft_gen;
mod mysql_gen;
mod nhibernate_gen;
mod servicestack_gen;
mod system_gen;
mod windows_gen;

/// Get all generated csharp framework profiles.
pub fn generated_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &amazon_gen::AMAZON_GEN_PROFILE,
        &dapper_gen::DAPPER_GEN_PROFILE,
        &ilcompiler_gen::ILCOMPILER_GEN_PROFILE,
        &internal_gen::INTERNAL_GEN_PROFILE,
        &microsoft_gen::MICROSOFT_GEN_PROFILE,
        &mysql_gen::MYSQL_GEN_PROFILE,
        &nhibernate_gen::NHIBERNATE_GEN_PROFILE,
        &servicestack_gen::SERVICESTACK_GEN_PROFILE,
        &system_gen::SYSTEM_GEN_PROFILE,
        &windows_gen::WINDOWS_GEN_PROFILE,
    ]
}
