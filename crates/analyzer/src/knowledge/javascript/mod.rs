//! JavaScript/TypeScript framework knowledge profiles
//!
//! This module contains security-relevant knowledge for popular JavaScript
//! and TypeScript frameworks including sources, sinks, sanitizers, and
//! dangerous patterns.

mod express;
mod nextjs;
mod node_core;
mod prisma;
mod react;
mod vue;

use super::types::FrameworkProfile;

pub use express::EXPRESS_PROFILE;
pub use nextjs::NEXTJS_PROFILE;
pub use node_core::NODE_CORE_PROFILE;
pub use prisma::PRISMA_PROFILE;
pub use react::REACT_PROFILE;
pub use vue::VUE_PROFILE;

/// Get all JavaScript/TypeScript framework profiles
pub fn all_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &NODE_CORE_PROFILE,
        &EXPRESS_PROFILE,
        &REACT_PROFILE,
        &NEXTJS_PROFILE,
        &VUE_PROFILE,
        &PRISMA_PROFILE,
    ]
}

/// Find profiles that match the given source code content
pub fn detect_frameworks(content: &str) -> Vec<&'static FrameworkProfile> {
    all_profiles()
        .into_iter()
        .filter(|profile| profile.is_active(content))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_profiles() {
        let profiles = all_profiles();
        assert!(!profiles.is_empty());

        // Verify all profiles have names
        for profile in &profiles {
            assert!(!profile.name.is_empty());
            assert!(!profile.detect_imports.is_empty());
        }
    }

    #[test]
    fn test_detect_express() {
        let content = r#"
            import express from 'express';
            const app = express();
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "express"));
    }

    #[test]
    fn test_detect_react() {
        let content = r#"
            import React from 'react';
            import { useState } from 'react';
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "react"));
    }

    #[test]
    fn test_detect_nextjs() {
        let content = r#"
            import { useRouter } from 'next/router';
            import Head from 'next/head';
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "nextjs"));
    }
}
