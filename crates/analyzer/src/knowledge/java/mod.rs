//! Java framework knowledge profiles
//!
//! This module contains security-relevant knowledge for popular Java
//! frameworks and standard library APIs including sources, sinks, sanitizers,
//! and dangerous patterns.
//!
//! # Framework Coverage
//!
//! - **JDBC**: Core database connectivity (java.sql, javax.sql)
//! - **Spring**: Spring Framework and Spring Boot web stack
//! - **Jakarta EE**: Servlet API and Jakarta EE components
//!
//! # Usage
//!
//! ```rust,ignore
//! use rma_analyzer::knowledge::java;
//!
//! // Get all Java profiles
//! let profiles = java::all_profiles();
//!
//! // Detect frameworks in source code
//! let active = java::detect_frameworks(source_content);
//! ```

mod jakarta;
mod jdbc;
mod spring;

use super::types::FrameworkProfile;

pub use jakarta::JAKARTA_PROFILE;
pub use jdbc::JDBC_PROFILE;
pub use spring::SPRING_PROFILE;

/// Get all Java framework profiles
///
/// Returns profiles in order of specificity:
/// 1. JDBC (most fundamental, used by Spring Data/JPA)
/// 2. Spring Framework
/// 3. Jakarta EE / Servlet API
pub fn all_profiles() -> Vec<&'static FrameworkProfile> {
    vec![&JDBC_PROFILE, &SPRING_PROFILE, &JAKARTA_PROFILE]
}

/// Detect which frameworks are active in the given source content
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
        assert_eq!(profiles.len(), 3);

        // Verify all profiles have names and detection patterns
        for profile in &profiles {
            assert!(!profile.name.is_empty());
            assert!(!profile.detect_imports.is_empty());
        }
    }

    #[test]
    fn test_detect_jdbc() {
        let content = r#"
            import java.sql.Connection;
            import java.sql.PreparedStatement;

            Connection conn = dataSource.getConnection();
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "jdbc"));
    }

    #[test]
    fn test_detect_spring() {
        let content = r#"
            import org.springframework.web.bind.annotation.RestController;
            import org.springframework.web.bind.annotation.GetMapping;

            @RestController
            public class MyController {}
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "spring"));
    }

    #[test]
    fn test_detect_jakarta() {
        let content = r#"
            import jakarta.servlet.http.HttpServletRequest;
            import jakarta.servlet.http.HttpServletResponse;

            public class MyServlet extends HttpServlet {}
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "jakarta"));
    }

    #[test]
    fn test_detect_javax_servlet() {
        // Legacy javax.servlet should also detect Jakarta profile
        let content = r#"
            import javax.servlet.http.HttpServletRequest;

            public class LegacyServlet extends HttpServlet {}
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "jakarta"));
    }

    #[test]
    fn test_spring_boot_detection() {
        let content = r#"
            import org.springframework.boot.SpringApplication;
            import org.springframework.boot.autoconfigure.SpringBootApplication;

            @SpringBootApplication
            public class Application {
                public static void main(String[] args) {
                    SpringApplication.run(Application.class, args);
                }
            }
        "#;
        let detected = detect_frameworks(content);
        assert!(detected.iter().any(|p| p.name == "spring"));
    }
}
