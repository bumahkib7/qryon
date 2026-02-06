//! Auto-generated javascript framework profiles
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::FrameworkProfile;

mod apollo_server_gen;
mod aws_sdk_client_gen;
mod aws_sdk_gen;
mod axios_gen;
mod cors_gen;
mod graphql_gen;
mod hdb_gen;
mod make_dir_gen;
mod mkdirp_gen;
mod open_gen;
mod react_relay_gen;
mod relay_runtime_gen;
mod rimraf_gen;
mod sap_hana_client_extension_stream_gen;
mod sap_hana_client_gen;
mod sap_hdbext_gen;
mod shelljs_gen;
mod underscore_gen;

/// Get all generated javascript framework profiles.
pub fn generated_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &underscore_gen::UNDERSCORE_GEN_PROFILE,
        &apollo_server_gen::APOLLO_SERVER_GEN_PROFILE,
        &aws_sdk_client_gen::AWS_SDK_CLIENT_GEN_PROFILE,
        &sap_hana_client_gen::SAP_HANA_CLIENT_GEN_PROFILE,
        &sap_hana_client_extension_stream_gen::SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_PROFILE,
        &sap_hdbext_gen::SAP_HDBEXT_GEN_PROFILE,
        &aws_sdk_gen::AWS_SDK_GEN_PROFILE,
        &axios_gen::AXIOS_GEN_PROFILE,
        &cors_gen::CORS_GEN_PROFILE,
        &graphql_gen::GRAPHQL_GEN_PROFILE,
        &hdb_gen::HDB_GEN_PROFILE,
        &make_dir_gen::MAKE_DIR_GEN_PROFILE,
        &mkdirp_gen::MKDIRP_GEN_PROFILE,
        &open_gen::OPEN_GEN_PROFILE,
        &react_relay_gen::REACT_RELAY_GEN_PROFILE,
        &relay_runtime_gen::RELAY_RUNTIME_GEN_PROFILE,
        &rimraf_gen::RIMRAF_GEN_PROFILE,
        &shelljs_gen::SHELLJS_GEN_PROFILE,
    ]
}
