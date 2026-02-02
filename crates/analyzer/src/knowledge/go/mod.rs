//! Go framework knowledge profiles
//!
//! This module contains security-relevant knowledge for popular Go frameworks
//! and the standard library, including sources, sinks, sanitizers, and
//! dangerous patterns.

mod echo;
mod gin;
mod gorm;
mod net_http;

use super::types::FrameworkProfile;

pub use echo::ECHO_PROFILE;
pub use gin::GIN_PROFILE;
pub use gorm::GORM_PROFILE;
pub use net_http::NET_HTTP_PROFILE;

/// Get all Go framework profiles
pub fn all_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &NET_HTTP_PROFILE,
        &GIN_PROFILE,
        &ECHO_PROFILE,
        &GORM_PROFILE,
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
    fn test_detect_net_http() {
        let content = r#"
            package main

            import "net/http"

            func handler(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte("Hello"))
            }
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "net/http"));
    }

    #[test]
    fn test_detect_gin() {
        let content = r#"
            package main

            import "github.com/gin-gonic/gin"

            func main() {
                r := gin.Default()
                r.Run()
            }
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "gin"));
    }

    #[test]
    fn test_detect_echo() {
        let content = r#"
            package main

            import "github.com/labstack/echo/v4"

            func main() {
                e := echo.New()
                e.Start(":8080")
            }
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "echo"));
    }

    #[test]
    fn test_detect_gorm() {
        let content = r#"
            package main

            import "gorm.io/gorm"

            func main() {
                db, _ := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
            }
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "gorm"));
    }
}
