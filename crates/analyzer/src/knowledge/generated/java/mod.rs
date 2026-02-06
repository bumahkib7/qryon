//! Auto-generated java framework profiles
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::FrameworkProfile;

mod android_gen;
mod androidx_gen;
mod ch_gen;
mod com_gen;
mod freemarker_gen;
mod go_io_gen;
mod groovy_gen;
mod hudson_gen;
mod jakarta_gen;
mod java_gen;
mod javafx_gen;
mod jenkins_gen;
mod kotlin_gen;
mod liquibase_gen;
mod net_gen;
mod ognl_gen;
mod okhttp3_gen;
mod org_gen;
mod play_gen;
mod ratpack_gen;
mod retrofit2_gen;
mod software_gen;
mod spring_gen;
mod sun_gen;

/// Get all generated java framework profiles.
pub fn generated_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &android_gen::ANDROID_GEN_PROFILE,
        &androidx_gen::ANDROIDX_GEN_PROFILE,
        &ch_gen::CH_GEN_PROFILE,
        &com_gen::COM_GEN_PROFILE,
        &freemarker_gen::FREEMARKER_GEN_PROFILE,
        &go_io_gen::GO_IO_GEN_PROFILE,
        &groovy_gen::GROOVY_GEN_PROFILE,
        &hudson_gen::HUDSON_GEN_PROFILE,
        &jakarta_gen::JAKARTA_GEN_PROFILE,
        &java_gen::JAVA_GEN_PROFILE,
        &javafx_gen::JAVAFX_GEN_PROFILE,
        &jenkins_gen::JENKINS_GEN_PROFILE,
        &kotlin_gen::KOTLIN_GEN_PROFILE,
        &liquibase_gen::LIQUIBASE_GEN_PROFILE,
        &net_gen::NET_GEN_PROFILE,
        &ognl_gen::OGNL_GEN_PROFILE,
        &okhttp3_gen::OKHTTP3_GEN_PROFILE,
        &org_gen::ORG_GEN_PROFILE,
        &play_gen::PLAY_GEN_PROFILE,
        &ratpack_gen::RATPACK_GEN_PROFILE,
        &retrofit2_gen::RETROFIT2_GEN_PROFILE,
        &software_gen::SOFTWARE_GEN_PROFILE,
        &spring_gen::SPRING_GEN_PROFILE,
        &sun_gen::SUN_GEN_PROFILE,
    ]
}
