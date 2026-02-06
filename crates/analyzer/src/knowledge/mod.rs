//! Framework Knowledge Base
//!
//! This module provides security-relevant knowledge about popular frameworks
//! and libraries. It maps framework-specific APIs to taint sources, sinks,
//! and sanitizers, enabling framework-aware security analysis.
//!
//! # Architecture
//!
//! The knowledge base is organized as follows:
//! - `types`: Core type definitions (SourceKind, SinkKind, etc.)
//! - Language-specific modules: Framework profiles for each language
//!
//! Each language has its own submodule with framework-specific knowledge:
//! - Taint sources (where untrusted data enters)
//! - Taint sinks (dangerous operations)
//! - Sanitizers (functions that neutralize taint)
//! - Safe patterns (inherently safe code constructs)
//! - Dangerous patterns (code constructs to flag)
//!
//! # Usage
//!
//! ```ignore
//! use rma_analyzer::knowledge::{detect_frameworks, profiles_for_language};
//! use rma_common::Language;
//!
//! // Get all known profiles for JavaScript
//! let profiles = profiles_for_language(Language::JavaScript);
//!
//! // Detect which frameworks are used based on source content
//! let active = detect_frameworks(Language::Rust, source_content);
//!
//! // Check if a function is a known sanitizer
//! for profile in &active {
//!     let sanitizers = profile.sanitizer_patterns();
//!     // ...
//! }
//! ```

pub mod generated;
pub mod go;
pub mod java;
pub mod javascript;
pub mod merged;
pub mod python;
pub mod rust_lang;
pub mod types;

pub use merged::{KnowledgeBuilder, MergedKnowledge};
pub use types::*;

use rma_common::Language;

/// Get all framework profiles for a language
///
/// Returns all known framework profiles regardless of whether they're
/// actually used in the codebase.
pub fn profiles_for_language(language: Language) -> Vec<&'static FrameworkProfile> {
    let mut profiles = match language {
        Language::Rust => rust_lang::all_profiles(),
        Language::Go => go::all_profiles(),
        Language::JavaScript | Language::TypeScript => javascript::all_profiles(),
        Language::Python => python::all_profiles(),
        Language::Java => java::all_profiles(),
        // Other languages don't have framework profiles yet
        _ => vec![],
    };
    // Append generated profiles (complementary, not replacing hand-coded ones)
    profiles.extend(generated::profiles_for_language(language));
    profiles
}

/// Get active framework profiles for a given source file
///
/// Analyzes the source content to determine which frameworks are in use,
/// based on import patterns defined in each framework profile.
///
/// # Arguments
///
/// * `language` - The programming language
/// * `content` - The source code content to analyze
///
/// # Returns
///
/// A vector of framework profiles that match the source content.
pub fn detect_frameworks(language: Language, content: &str) -> Vec<&'static FrameworkProfile> {
    profiles_for_language(language)
        .into_iter()
        .filter(|profile| profile.is_active(content))
        .collect()
}

/// Detect frameworks from import statements
///
/// This is a more efficient method when you already have a list of
/// import statements extracted from the AST.
pub fn detect_frameworks_from_imports(
    language: Language,
    imports: &[&str],
) -> Vec<&'static FrameworkProfile> {
    let profiles = profiles_for_language(language);

    profiles
        .into_iter()
        .filter(|profile| {
            profile
                .detect_imports
                .iter()
                .any(|pattern| imports.iter().any(|import| import.contains(pattern)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profiles_for_language() {
        // Rust should have profiles
        let rust_profiles = profiles_for_language(Language::Rust);
        assert!(!rust_profiles.is_empty(), "Should have Rust profiles");
        assert!(
            rust_profiles.iter().any(|p| p.name == "std"),
            "Should have std library profile"
        );

        // JavaScript should have profiles
        let js_profiles = profiles_for_language(Language::JavaScript);
        assert!(!js_profiles.is_empty(), "Should have JavaScript profiles");

        // TypeScript should share JavaScript profiles
        let ts_profiles = profiles_for_language(Language::TypeScript);
        assert_eq!(
            js_profiles.len(),
            ts_profiles.len(),
            "JS and TS should share profiles"
        );

        // Go should have profiles
        let go_profiles = profiles_for_language(Language::Go);
        assert!(!go_profiles.is_empty(), "Should have Go profiles");

        // Python should have profiles
        let python_profiles = profiles_for_language(Language::Python);
        assert!(!python_profiles.is_empty(), "Should have Python profiles");

        // Java should have profiles
        let java_profiles = profiles_for_language(Language::Java);
        assert!(!java_profiles.is_empty(), "Should have Java profiles");

        // Unknown language has no profiles
        let unknown_profiles = profiles_for_language(Language::Unknown);
        assert!(
            unknown_profiles.is_empty(),
            "Unknown language has no profiles"
        );
    }

    #[test]
    fn test_rust_framework_detection() {
        let content = r#"
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() {
    HttpServer::new(|| App::new()).bind("127.0.0.1:8080");
}
"#;
        let profiles = detect_frameworks(Language::Rust, content);
        assert!(
            profiles.iter().any(|p| p.name == "actix-web"),
            "Should detect actix-web"
        );
    }

    #[test]
    fn test_javascript_framework_detection() {
        let content = r#"
import express from 'express';
const app = express();
"#;
        let profiles = detect_frameworks(Language::JavaScript, content);
        assert!(
            profiles.iter().any(|p| p.name == "express"),
            "Should detect express"
        );
    }

    #[test]
    fn test_go_framework_detection() {
        let content = r#"
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
}
"#;
        let profiles = detect_frameworks(Language::Go, content);
        assert!(
            profiles.iter().any(|p| p.name == "gin"),
            "Should detect gin"
        );
    }

    #[test]
    fn test_python_framework_detection() {
        let content = r#"
from flask import Flask, request
app = Flask(__name__)
"#;
        let profiles = detect_frameworks(Language::Python, content);
        assert!(
            profiles.iter().any(|p| p.name == "flask"),
            "Should detect flask"
        );
    }

    #[test]
    fn test_java_framework_detection() {
        let content = r#"
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class MyController {}
"#;
        let profiles = detect_frameworks(Language::Java, content);
        assert!(
            profiles.iter().any(|p| p.name == "spring"),
            "Should detect spring"
        );
    }
}
