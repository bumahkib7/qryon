//! Rust framework profiles for security analysis
//!
//! This module provides framework-specific knowledge for Rust security analysis:
//! - Standard library (std) - always active as baseline
//! - Actix-web - popular async web framework
//! - Axum - tower-based web framework
//! - Rocket - ergonomic web framework
//!
//! Each profile defines sources, sinks, sanitizers, and dangerous patterns
//! specific to that framework.

mod actix;
mod axum;
mod rocket;
mod std_lib;

use crate::knowledge::types::FrameworkProfile;

/// Get all Rust framework profiles
///
/// Returns profiles in priority order:
/// 1. std_lib (always active as baseline)
/// 2. Framework-specific profiles (actix, axum, rocket)
pub fn all_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &std_lib::STD_LIB_PROFILE,
        &actix::ACTIX_PROFILE,
        &axum::AXUM_PROFILE,
        &rocket::ROCKET_PROFILE,
    ]
}

/// Get the standard library profile (always applicable)
pub fn std_profile() -> &'static FrameworkProfile {
    &std_lib::STD_LIB_PROFILE
}

/// Get framework-specific profiles (excluding std)
pub fn framework_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &actix::ACTIX_PROFILE,
        &axum::AXUM_PROFILE,
        &rocket::ROCKET_PROFILE,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_profiles() {
        let profiles = all_profiles();
        assert!(profiles.len() >= 4, "Should have at least 4 profiles");

        // std should be first
        assert_eq!(profiles[0].name, "std");
    }

    #[test]
    fn test_std_always_active() {
        let std = std_profile();
        // std should match any Rust code (empty detect_imports or always true)
        assert!(
            std.detect_imports.contains(&"std::"),
            "std should detect std:: imports"
        );
    }

    #[test]
    fn test_framework_detection() {
        let actix_code = "use actix_web::{web, App};";
        let axum_code = "use axum::{Router, routing::get};";
        let rocket_code = "use rocket::{get, routes};";

        assert!(
            all_profiles()
                .iter()
                .any(|p| p.name == "actix-web" && p.is_active(actix_code))
        );
        assert!(
            all_profiles()
                .iter()
                .any(|p| p.name == "axum" && p.is_active(axum_code))
        );
        assert!(
            all_profiles()
                .iter()
                .any(|p| p.name == "rocket" && p.is_active(rocket_code))
        );
    }
}
