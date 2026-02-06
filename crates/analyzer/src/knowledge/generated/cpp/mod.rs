//! Auto-generated cpp framework profiles
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::FrameworkProfile;

mod atl_gen;
mod azure_core_gen;
mod azure_core_http_gen;
mod boost_asio_gen;

/// Get all generated cpp framework profiles.
pub fn generated_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &atl_gen::ATL_GEN_PROFILE,
        &azure_core_gen::AZURE_CORE_GEN_PROFILE,
        &azure_core_http_gen::AZURE_CORE_HTTP_GEN_PROFILE,
        &boost_asio_gen::BOOST_ASIO_GEN_PROFILE,
    ]
}
