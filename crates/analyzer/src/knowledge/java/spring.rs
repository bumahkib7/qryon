//! Spring Framework profile
//!
//! Covers Spring Framework, Spring Boot, Spring MVC, Spring Data, and Spring Security.
//! This is the most comprehensive Java framework profile covering:
//!
//! - Web request sources (@RequestParam, @PathVariable, @RequestBody, etc.)
//! - Template injection sinks (Thymeleaf, JSP)
//! - SQL injection via JdbcTemplate
//! - Command injection via Runtime
//! - SSRF via RestTemplate, WebClient
//! - Path traversal via file operations
//! - Auto-escaping sanitizers (Thymeleaf th:text)
//! - Safe patterns (JPA, Spring Data repositories)
//! - Dependency Injection annotations (@Autowired, @Inject, etc.)

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

// =============================================================================
// Dependency Injection Annotations
// =============================================================================

/// DI (Dependency Injection) annotations used in Spring and Jakarta EE
///
/// These annotations indicate that a field is managed by the container and
/// should not trigger "uninitialized" warnings in typestate analysis.
#[allow(dead_code)]
pub static DI_ANNOTATIONS: &[&str] = &[
    "@Autowired",
    "@Inject",
    "@Resource",
    "@Value",
    "@PersistenceContext",
    "@PersistenceUnit",
    "@EJB",
    "@ManagedProperty",
    // Lombok annotations that generate constructors/injection
    "@RequiredArgsConstructor",
    "@AllArgsConstructor",
];

/// Test lifecycle annotations that indicate setup methods
///
/// Variables initialized in these methods should be available in test methods.
#[allow(dead_code)]
pub static TEST_SETUP_ANNOTATIONS: &[&str] = &[
    "@Before",
    "@BeforeEach",
    "@BeforeAll",
    "@BeforeClass",
    "@BeforeMethod",  // TestNG
    "@PostConstruct", // Used for initialization
];

/// Test lifecycle annotations for teardown
#[allow(dead_code)]
pub static TEST_TEARDOWN_ANNOTATIONS: &[&str] = &[
    "@After",
    "@AfterEach",
    "@AfterAll",
    "@AfterClass",
    "@AfterMethod", // TestNG
    "@PreDestroy",
];

/// Check if a line contains a DI annotation
#[allow(dead_code)]
pub fn has_di_annotation(line: &str) -> bool {
    DI_ANNOTATIONS.iter().any(|ann| line.contains(ann))
}

/// Check if a line contains a test setup annotation
#[allow(dead_code)]
pub fn has_test_setup_annotation(line: &str) -> bool {
    TEST_SETUP_ANNOTATIONS.iter().any(|ann| line.contains(ann))
}

/// Check if a line contains a test teardown annotation
#[allow(dead_code)]
pub fn has_test_teardown_annotation(line: &str) -> bool {
    TEST_TEARDOWN_ANNOTATIONS
        .iter()
        .any(|ann| line.contains(ann))
}

/// Extract field name from a DI-annotated line
///
/// Examples:
/// - `@Autowired private DataSource dataSource;` -> Some("dataSource")
/// - `@Inject DataSource ds;` -> Some("ds")
/// - `@Value("${db.url}") String url;` -> Some("url")
#[allow(dead_code)]
pub fn extract_di_field_name(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Skip if no DI annotation
    if !has_di_annotation(trimmed) {
        return None;
    }

    // Find the part after the annotation(s)
    // Handle multiple annotations like @Autowired @Qualifier("main")
    let mut remaining = trimmed;
    while remaining.starts_with('@') {
        // Skip the annotation
        if let Some(paren_pos) = remaining.find('(') {
            // Has parameters, find closing paren
            let mut depth = 0;
            let mut end_pos = paren_pos;
            for (i, c) in remaining[paren_pos..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end_pos = paren_pos + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            remaining = remaining[end_pos..].trim_start();
        } else if let Some(space_pos) = remaining.find(' ') {
            remaining = remaining[space_pos..].trim_start();
        } else {
            return None;
        }
    }

    // Now we should have: [modifiers] Type fieldName;
    // Extract the last word before the semicolon
    let field_part = remaining.trim_end_matches(';').trim();
    let words: Vec<&str> = field_part.split_whitespace().collect();

    // The field name is the last word
    words.last().map(|s| s.to_string())
}

/// Spring Framework profile for comprehensive web security analysis
pub static SPRING_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "spring",
    description: "Spring Framework, Spring Boot, Spring MVC, Spring Data - comprehensive Java web stack",

    detect_imports: &[
        "org.springframework",
        "spring-boot",
        "import org.springframework.",
        "@SpringBootApplication",
        "@RestController",
        "@Controller",
        "@Service",
        "@Repository",
        "@Component",
        "@Autowired",
    ],

    // =========================================================================
    // Sources - Where untrusted data enters Spring applications
    // =========================================================================
    sources: &[
        // Request parameter annotations
        SourceDef {
            name: "@RequestParam",
            pattern: SourceKind::TypeExtractor("@RequestParam"),
            taint_label: "user_input",
            description: "Query parameter from HTTP request - untrusted user input",
        },
        SourceDef {
            name: "@PathVariable",
            pattern: SourceKind::TypeExtractor("@PathVariable"),
            taint_label: "user_input",
            description: "Path variable from URL - untrusted user input",
        },
        SourceDef {
            name: "@RequestBody",
            pattern: SourceKind::TypeExtractor("@RequestBody"),
            taint_label: "user_input",
            description: "Request body (JSON/XML) - untrusted user input",
        },
        SourceDef {
            name: "@RequestHeader",
            pattern: SourceKind::TypeExtractor("@RequestHeader"),
            taint_label: "user_input",
            description: "HTTP header value - can be manipulated by attacker",
        },
        SourceDef {
            name: "@CookieValue",
            pattern: SourceKind::TypeExtractor("@CookieValue"),
            taint_label: "user_input",
            description: "Cookie value - can be manipulated by attacker",
        },
        SourceDef {
            name: "@ModelAttribute",
            pattern: SourceKind::TypeExtractor("@ModelAttribute"),
            taint_label: "user_input",
            description: "Model attribute from form submission - untrusted user input",
        },
        // HttpServletRequest methods
        SourceDef {
            name: "HttpServletRequest.getParameter",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParameter",
            },
            taint_label: "user_input",
            description: "Request parameter via servlet API - untrusted user input",
        },
        SourceDef {
            name: "HttpServletRequest.getHeader",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getHeader",
            },
            taint_label: "user_input",
            description: "HTTP header via servlet API - can be manipulated",
        },
        SourceDef {
            name: "HttpServletRequest.getParameterValues",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParameterValues",
            },
            taint_label: "user_input",
            description: "Multiple parameter values - untrusted user input",
        },
        SourceDef {
            name: "HttpServletRequest.getParameterMap",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParameterMap",
            },
            taint_label: "user_input",
            description: "All parameters as map - untrusted user input",
        },
        // File upload
        SourceDef {
            name: "MultipartFile.getOriginalFilename",
            pattern: SourceKind::MethodOnType {
                type_pattern: "MultipartFile",
                method: "getOriginalFilename",
            },
            taint_label: "user_input",
            description: "Uploaded filename - can be crafted for path traversal",
        },
        SourceDef {
            name: "MultipartFile.getBytes",
            pattern: SourceKind::MethodOnType {
                type_pattern: "MultipartFile",
                method: "getBytes",
            },
            taint_label: "user_file",
            description: "Uploaded file content - untrusted binary data",
        },
        SourceDef {
            name: "MultipartFile.getInputStream",
            pattern: SourceKind::MethodOnType {
                type_pattern: "MultipartFile",
                method: "getInputStream",
            },
            taint_label: "user_file",
            description: "Uploaded file stream - untrusted binary data",
        },
        // WebSocket
        SourceDef {
            name: "WebSocketMessage",
            pattern: SourceKind::TypeExtractor("@MessageMapping"),
            taint_label: "user_input",
            description: "WebSocket message payload - untrusted user input",
        },
        // Spring Security
        SourceDef {
            name: "Principal.getName",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Principal",
                method: "getName",
            },
            taint_label: "user_identifier",
            description: "User principal name - may be used in queries",
        },
    ],

    // =========================================================================
    // Sinks - Where tainted data becomes dangerous
    // =========================================================================
    sinks: &[
        // XSS via response body
        SinkDef {
            name: "ResponseEntity.body-tainted",
            pattern: SinkKind::ResponseBody("ResponseEntity"),
            rule_id: "java/spring-xss-response",
            severity: Severity::Error,
            description: "Tainted data in ResponseEntity body may cause XSS if returned as HTML/text",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "ModelAndView-tainted",
            pattern: SinkKind::ResponseBody("ModelAndView"),
            rule_id: "java/spring-xss-model",
            severity: Severity::Warning,
            description: "Tainted data in ModelAndView - ensure template auto-escaping is enabled",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "Model.addAttribute-tainted",
            pattern: SinkKind::MethodCall("addAttribute"),
            rule_id: "java/spring-xss-model",
            severity: Severity::Warning,
            description: "Tainted data added to Model - ensure template auto-escaping",
            cwe: Some("CWE-79"),
        },
        // SQL injection via JdbcTemplate
        SinkDef {
            name: "JdbcTemplate.query-concat",
            pattern: SinkKind::MethodCall("query"),
            rule_id: "java/spring-sql-injection",
            severity: Severity::Critical,
            description: "JdbcTemplate.query() with string concatenation allows SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "JdbcTemplate.update-concat",
            pattern: SinkKind::MethodCall("update"),
            rule_id: "java/spring-sql-injection",
            severity: Severity::Critical,
            description: "JdbcTemplate.update() with string concatenation allows SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "JdbcTemplate.execute-concat",
            pattern: SinkKind::MethodCall("execute"),
            rule_id: "java/spring-sql-injection",
            severity: Severity::Critical,
            description: "JdbcTemplate.execute() with string concatenation allows SQL injection",
            cwe: Some("CWE-89"),
        },
        SinkDef {
            name: "NamedParameterJdbcTemplate-concat",
            pattern: SinkKind::MethodCall("queryForObject"),
            rule_id: "java/spring-sql-injection",
            severity: Severity::Critical,
            description: "JDBC query with string concatenation allows SQL injection",
            cwe: Some("CWE-89"),
        },
        // Command injection - Runtime.getRuntime()
        SinkDef {
            name: "Runtime.getRuntime-tainted",
            pattern: SinkKind::MethodCall("getRuntime"),
            rule_id: "java/spring-command-injection",
            severity: Severity::Critical,
            description: "Runtime.getRuntime() with tainted input allows command injection",
            cwe: Some("CWE-78"),
        },
        SinkDef {
            name: "ProcessBuilder-tainted",
            pattern: SinkKind::FunctionCall("ProcessBuilder"),
            rule_id: "java/spring-command-injection",
            severity: Severity::Critical,
            description: "ProcessBuilder with tainted input allows command injection",
            cwe: Some("CWE-78"),
        },
        // SSRF
        SinkDef {
            name: "URL-tainted",
            pattern: SinkKind::FunctionCall("new URL"),
            rule_id: "java/spring-ssrf",
            severity: Severity::Critical,
            description: "new URL() with tainted input can cause SSRF (Server-Side Request Forgery)",
            cwe: Some("CWE-918"),
        },
        SinkDef {
            name: "RestTemplate.getForObject-tainted",
            pattern: SinkKind::MethodCall("getForObject"),
            rule_id: "java/spring-ssrf",
            severity: Severity::Critical,
            description: "RestTemplate with tainted URL can cause SSRF",
            cwe: Some("CWE-918"),
        },
        SinkDef {
            name: "RestTemplate.exchange-tainted",
            pattern: SinkKind::MethodCall("exchange"),
            rule_id: "java/spring-ssrf",
            severity: Severity::Critical,
            description: "RestTemplate.exchange() with tainted URL can cause SSRF",
            cwe: Some("CWE-918"),
        },
        SinkDef {
            name: "WebClient.get-tainted",
            pattern: SinkKind::MethodCall("uri"),
            rule_id: "java/spring-ssrf",
            severity: Severity::Critical,
            description: "WebClient with tainted URI can cause SSRF",
            cwe: Some("CWE-918"),
        },
        // Open redirect
        SinkDef {
            name: "redirect-tainted",
            pattern: SinkKind::FunctionCall("redirect:"),
            rule_id: "java/spring-open-redirect",
            severity: Severity::Error,
            description: "Redirect with tainted URL can cause open redirect vulnerability",
            cwe: Some("CWE-601"),
        },
        SinkDef {
            name: "HttpServletResponse.sendRedirect",
            pattern: SinkKind::MethodCall("sendRedirect"),
            rule_id: "java/spring-open-redirect",
            severity: Severity::Error,
            description: "sendRedirect() with tainted URL can cause open redirect",
            cwe: Some("CWE-601"),
        },
        // Path traversal
        SinkDef {
            name: "File-tainted",
            pattern: SinkKind::FunctionCall("new File"),
            rule_id: "java/spring-path-traversal",
            severity: Severity::Critical,
            description: "new File() with tainted input can cause path traversal",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "Paths.get-tainted",
            pattern: SinkKind::FunctionCall("Paths.get"),
            rule_id: "java/spring-path-traversal",
            severity: Severity::Critical,
            description: "Paths.get() with tainted input can cause path traversal",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "ResourceLoader-tainted",
            pattern: SinkKind::MethodCall("getResource"),
            rule_id: "java/spring-path-traversal",
            severity: Severity::Error,
            description: "ResourceLoader with tainted path can cause path traversal",
            cwe: Some("CWE-22"),
        },
        // Template injection (SSTI)
        SinkDef {
            name: "Thymeleaf-th:utext",
            pattern: SinkKind::TemplateInsertion,
            rule_id: "java/spring-ssti",
            severity: Severity::Critical,
            description: "th:utext outputs raw HTML without escaping - XSS vulnerability",
            cwe: Some("CWE-79"),
        },
        // LDAP injection
        SinkDef {
            name: "LdapTemplate.search-tainted",
            pattern: SinkKind::MethodCall("search"),
            rule_id: "java/spring-ldap-injection",
            severity: Severity::Critical,
            description: "LdapTemplate with tainted filter can cause LDAP injection",
            cwe: Some("CWE-90"),
        },
        // Log injection
        SinkDef {
            name: "Logger-tainted",
            pattern: SinkKind::MethodCall("info"),
            rule_id: "java/spring-log-injection",
            severity: Severity::Warning,
            description: "Logging tainted data without sanitization can cause log injection/forging",
            cwe: Some("CWE-117"),
        },
        // Expression Language injection
        SinkDef {
            name: "SpEL-tainted",
            pattern: SinkKind::MethodCall("parseExpression"),
            rule_id: "java/spring-expression-injection",
            severity: Severity::Critical,
            description: "SpEL with tainted input can cause expression injection (RCE)",
            cwe: Some("CWE-917"),
        },
    ],

    // =========================================================================
    // Sanitizers - Functions that neutralize tainted data
    // =========================================================================
    sanitizers: &[
        // Thymeleaf auto-escaping
        SanitizerDef {
            name: "Thymeleaf th:text",
            pattern: SanitizerKind::TemplateEngine("th:text"),
            sanitizes: "html",
            description: "Thymeleaf th:text auto-escapes HTML entities (safe)",
        },
        SanitizerDef {
            name: "Thymeleaf th:attr",
            pattern: SanitizerKind::TemplateEngine("th:attr"),
            sanitizes: "html",
            description: "Thymeleaf th:attr auto-escapes attribute values",
        },
        // Spring HtmlUtils
        SanitizerDef {
            name: "HtmlUtils.htmlEscape",
            pattern: SanitizerKind::Function("HtmlUtils.htmlEscape"),
            sanitizes: "html",
            description: "Spring HtmlUtils.htmlEscape() escapes HTML special characters",
        },
        SanitizerDef {
            name: "HtmlUtils.htmlEscapeDecimal",
            pattern: SanitizerKind::Function("HtmlUtils.htmlEscapeDecimal"),
            sanitizes: "html",
            description: "Spring HtmlUtils decimal encoding for HTML",
        },
        // OWASP Java Encoder
        SanitizerDef {
            name: "Encode.forHtml",
            pattern: SanitizerKind::Function("Encode.forHtml"),
            sanitizes: "html",
            description: "OWASP Java Encoder for HTML context",
        },
        SanitizerDef {
            name: "Encode.forHtmlAttribute",
            pattern: SanitizerKind::Function("Encode.forHtmlAttribute"),
            sanitizes: "html_attr",
            description: "OWASP Java Encoder for HTML attribute context",
        },
        SanitizerDef {
            name: "Encode.forHtmlContent",
            pattern: SanitizerKind::Function("Encode.forHtmlContent"),
            sanitizes: "html",
            description: "OWASP Java Encoder for HTML content",
        },
        SanitizerDef {
            name: "Encode.forJavaScript",
            pattern: SanitizerKind::Function("Encode.forJavaScript"),
            sanitizes: "javascript",
            description: "OWASP Java Encoder for JavaScript context",
        },
        SanitizerDef {
            name: "Encode.forCssString",
            pattern: SanitizerKind::Function("Encode.forCssString"),
            sanitizes: "css",
            description: "OWASP Java Encoder for CSS string context",
        },
        SanitizerDef {
            name: "Encode.forUriComponent",
            pattern: SanitizerKind::Function("Encode.forUriComponent"),
            sanitizes: "url",
            description: "OWASP Java Encoder for URL component context",
        },
        // Jsoup HTML sanitizer
        SanitizerDef {
            name: "Jsoup.clean",
            pattern: SanitizerKind::Function("Jsoup.clean"),
            sanitizes: "html",
            description: "Jsoup HTML sanitizer removes dangerous tags/attributes",
        },
        // Spring Web utilities
        SanitizerDef {
            name: "UriUtils.encode",
            pattern: SanitizerKind::Function("UriUtils.encode"),
            sanitizes: "url",
            description: "Spring UriUtils.encode() for URL encoding",
        },
        SanitizerDef {
            name: "UriComponentsBuilder",
            pattern: SanitizerKind::Function("UriComponentsBuilder"),
            sanitizes: "url",
            description: "Spring UriComponentsBuilder safely builds URLs",
        },
        // Input validation
        SanitizerDef {
            name: "@Valid",
            pattern: SanitizerKind::Function("@Valid"),
            sanitizes: "validation",
            description: "Bean Validation annotation validates input",
        },
        SanitizerDef {
            name: "@Validated",
            pattern: SanitizerKind::Function("@Validated"),
            sanitizes: "validation",
            description: "Spring @Validated triggers validation",
        },
    ],

    // =========================================================================
    // Safe Patterns - Inherently safe APIs
    // =========================================================================
    safe_patterns: &[
        // JPA/Hibernate
        SafePattern {
            name: "JPA named parameters",
            pattern: ":\\w+",
            reason: "JPA named parameters (:param) are parameterized and safe from injection",
        },
        SafePattern {
            name: "JPA positional parameters",
            pattern: "\\?\\d+",
            reason: "JPA positional parameters (?1, ?2) are parameterized and safe",
        },
        SafePattern {
            name: "CriteriaBuilder",
            pattern: "CriteriaBuilder",
            reason: "JPA Criteria API builds queries programmatically (type-safe)",
        },
        SafePattern {
            name: "Specification",
            pattern: "Specification<",
            reason: "Spring Data Specifications build queries safely",
        },
        // Spring Data repositories
        SafePattern {
            name: "Spring Data derived queries",
            pattern: "findBy|findAllBy|countBy|deleteBy|existsBy",
            reason: "Spring Data derived query methods are safe from injection",
        },
        SafePattern {
            name: "Spring Data @Query with params",
            pattern: "@Query.*:\\w+",
            reason: "Spring Data @Query with named parameters is safe",
        },
        SafePattern {
            name: "Spring Data repository interface",
            pattern: "extends.*Repository<",
            reason: "Spring Data repository methods are safe",
        },
        // JDBC with parameters
        SafePattern {
            name: "JdbcTemplate with args",
            pattern: "jdbcTemplate\\.(query|update)\\([^)]*,\\s*new Object\\[\\]",
            reason: "JdbcTemplate with Object[] args uses prepared statements",
        },
        SafePattern {
            name: "JdbcTemplate with varargs",
            pattern: "jdbcTemplate\\.(queryForObject|queryForList)\\([^)]*,\\s*\\w+\\)",
            reason: "JdbcTemplate methods with parameters are safe",
        },
        SafePattern {
            name: "NamedParameterJdbcTemplate",
            pattern: "namedParameterJdbcTemplate",
            reason: "NamedParameterJdbcTemplate uses named parameters (safe)",
        },
        // Path validation
        SafePattern {
            name: "FilenameUtils.getName",
            pattern: "FilenameUtils.getName",
            reason: "Apache Commons FilenameUtils.getName() strips path components",
        },
        SafePattern {
            name: "Path.normalize",
            pattern: "\\.normalize\\(",
            reason: "Path.normalize() removes .. traversal attempts",
        },
        // URL validation
        SafePattern {
            name: "URL whitelist check",
            pattern: "allowedHosts|whitelistedUrls|allowedDomains",
            reason: "URL whitelist validation prevents SSRF",
        },
    ],

    // =========================================================================
    // Dangerous Patterns - Common security anti-patterns
    // =========================================================================
    dangerous_patterns: &[
        // String concatenation in queries
        DangerousPattern {
            name: "JdbcTemplate string concat",
            pattern: PatternKind::Regex(r#"jdbcTemplate\.\w+\([^)]*"\s*\+\s*"#),
            rule_id: "java/spring-sql-concat",
            severity: Severity::Critical,
            description: "JdbcTemplate with string concatenation - use parameterized queries",
            cwe: Some("CWE-89"),
        },
        // JPQL concatenation
        DangerousPattern {
            name: "JPQL string concat",
            pattern: PatternKind::Regex(r#"createQuery\([^)]*"\s*\+\s*"#),
            rule_id: "java/spring-jpql-concat",
            severity: Severity::Critical,
            description: "JPQL with string concatenation - use named parameters",
            cwe: Some("CWE-89"),
        },
        // Thymeleaf th:utext (no escaping)
        DangerousPattern {
            name: "Thymeleaf th:utext",
            pattern: PatternKind::Regex(r#"th:utext"#),
            rule_id: "java/spring-xss-utext",
            severity: Severity::Error,
            description: "th:utext outputs raw HTML without escaping - use th:text for user content",
            cwe: Some("CWE-79"),
        },
        // Disabled CSRF
        DangerousPattern {
            name: "CSRF disabled",
            pattern: PatternKind::Regex(r#"csrf\(\)\.disable\(\)"#),
            rule_id: "java/spring-csrf-disabled",
            severity: Severity::Warning,
            description: "CSRF protection disabled - only safe for stateless APIs",
            cwe: Some("CWE-352"),
        },
        // Disabled CORS restrictions
        DangerousPattern {
            name: "CORS allow all",
            pattern: PatternKind::Regex(r#"allowedOrigins\(\s*"\*"\s*\)"#),
            rule_id: "java/spring-cors-wildcard",
            severity: Severity::Warning,
            description: "CORS allows all origins - restrict to known domains",
            cwe: Some("CWE-942"),
        },
        // Mass assignment
        DangerousPattern {
            name: "Bind all fields",
            pattern: PatternKind::Regex(r#"@ModelAttribute.*\bbind\b"#),
            rule_id: "java/spring-mass-assignment",
            severity: Severity::Warning,
            description: "Consider using @InitBinder to whitelist allowed fields",
            cwe: Some("CWE-915"),
        },
        // Actuator endpoints exposed
        DangerousPattern {
            name: "Actuator web exposure",
            pattern: PatternKind::Regex(
                r#"management\.endpoints\.web\.exposure\.include\s*=\s*\*"#,
            ),
            rule_id: "java/spring-actuator-exposure",
            severity: Severity::Error,
            description: "All actuator endpoints exposed - restrict to health,info",
            cwe: Some("CWE-200"),
        },
        // Hardcoded secrets
        DangerousPattern {
            name: "Hardcoded secret",
            pattern: PatternKind::Regex(r#"(password|secret|apiKey)\s*=\s*"[^"]+""#),
            rule_id: "java/spring-hardcoded-secret",
            severity: Severity::Critical,
            description: "Hardcoded secret - use environment variables or vault",
            cwe: Some("CWE-798"),
        },
        // Insecure random
        DangerousPattern {
            name: "Insecure random",
            pattern: PatternKind::Construct("new Random()"),
            rule_id: "java/spring-insecure-random",
            severity: Severity::Warning,
            description: "Use SecureRandom for security-sensitive random numbers",
            cwe: Some("CWE-330"),
        },
        // String + in loop (performance)
        DangerousPattern {
            name: "String concat in loop",
            pattern: PatternKind::Regex(r#"for\s*\([^)]*\)\s*\{[^}]*\+=\s*"[^}]*\}"#),
            rule_id: "java/spring-string-concat-loop",
            severity: Severity::Warning,
            description: "String concatenation in loop - use StringBuilder",
            cwe: None,
        },
        // .equals() on possibly null
        DangerousPattern {
            name: "Equals on possibly null",
            pattern: PatternKind::Regex(r#"\w+\.equals\([^)]*\)"#),
            rule_id: "java/spring-null-equals",
            severity: Severity::Info,
            description: "Consider using Objects.equals() or put constant first to avoid NPE",
            cwe: Some("CWE-476"),
        },
        // Map.get without null check
        DangerousPattern {
            name: "Map.get without null check",
            pattern: PatternKind::Regex(r#"\.get\([^)]*\)\.[^g]"#),
            rule_id: "java/spring-map-get-npe",
            severity: Severity::Info,
            description: "Map.get() may return null - check before using or use getOrDefault()",
            cwe: Some("CWE-476"),
        },
        // stream findFirst().get() without isPresent
        DangerousPattern {
            name: "Optional.get without check",
            pattern: PatternKind::Regex(r#"(findFirst|findAny)\(\)\.get\(\)"#),
            rule_id: "java/spring-optional-get",
            severity: Severity::Warning,
            description: "Optional.get() without isPresent() throws NoSuchElementException - use orElse()",
            cwe: None,
        },
        // HashMap across threads
        DangerousPattern {
            name: "HashMap in concurrent context",
            pattern: PatternKind::Regex(r#"(static|volatile)\s+HashMap"#),
            rule_id: "java/spring-concurrent-hashmap",
            severity: Severity::Warning,
            description: "HashMap is not thread-safe - use ConcurrentHashMap for shared state",
            cwe: Some("CWE-362"),
        },
        // ObjectInputStream.readObject
        DangerousPattern {
            name: "Unsafe deserialization",
            pattern: PatternKind::MethodCall("readObject"),
            rule_id: "java/spring-unsafe-deserialization",
            severity: Severity::Critical,
            description: "ObjectInputStream.readObject() on untrusted data can lead to RCE",
            cwe: Some("CWE-502"),
        },
    ],

    // =========================================================================
    // Resource Types - Resources requiring lifecycle management
    // =========================================================================
    resource_types: &[
        ResourceType {
            name: "RestTemplate",
            acquire_pattern: "new RestTemplate() | restTemplateBuilder.build()",
            release_pattern: "N/A (reusable)",
            leak_consequence: "Consider using WebClient for reactive streams",
        },
        ResourceType {
            name: "WebClient",
            acquire_pattern: "WebClient.create() | WebClient.builder().build()",
            release_pattern: "N/A (managed by reactor)",
            leak_consequence: "Ensure proper subscription management",
        },
        ResourceType {
            name: "InputStream",
            acquire_pattern: "request.getInputStream() | file.getInputStream()",
            release_pattern: "close() | try-with-resources",
            leak_consequence: "Memory leak, file descriptor exhaustion",
        },
        ResourceType {
            name: "OutputStream",
            acquire_pattern: "response.getOutputStream() | new FileOutputStream()",
            release_pattern: "close() | try-with-resources",
            leak_consequence: "Memory leak, data not flushed, file descriptor exhaustion",
        },
        ResourceType {
            name: "EntityManager",
            acquire_pattern: "entityManagerFactory.createEntityManager()",
            release_pattern: "close()",
            leak_consequence: "Database connection leak, memory leak",
        },
        ResourceType {
            name: "Session (Hibernate)",
            acquire_pattern: "sessionFactory.openSession()",
            release_pattern: "close()",
            leak_consequence: "Database connection leak",
        },
        ResourceType {
            name: "Lock",
            acquire_pattern: "lock.lock() | lock.tryLock()",
            release_pattern: "unlock() in finally block",
            leak_consequence: "Deadlock, other threads blocked indefinitely",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spring_detection() {
        assert!(SPRING_PROFILE.is_active("import org.springframework.web.bind.annotation.*;"));
        assert!(SPRING_PROFILE.is_active("@SpringBootApplication"));
        assert!(SPRING_PROFILE.is_active("@RestController"));
        assert!(SPRING_PROFILE.is_active("@Autowired"));
        assert!(!SPRING_PROFILE.is_active("import jakarta.servlet.*;"));
    }

    #[test]
    fn test_spring_has_sources() {
        assert!(!SPRING_PROFILE.sources.is_empty());

        // Check for key source patterns
        let source_names: Vec<&str> = SPRING_PROFILE.sources.iter().map(|s| s.name).collect();
        assert!(source_names.contains(&"@RequestParam"));
        assert!(source_names.contains(&"@PathVariable"));
        assert!(source_names.contains(&"@RequestBody"));
        assert!(source_names.contains(&"HttpServletRequest.getParameter"));
    }

    #[test]
    fn test_spring_has_sinks() {
        assert!(!SPRING_PROFILE.sinks.is_empty());

        // Check for key sink patterns
        let sink_names: Vec<&str> = SPRING_PROFILE.sinks.iter().map(|s| s.name).collect();
        assert!(sink_names.iter().any(|n| n.contains("JdbcTemplate")));
        assert!(sink_names.iter().any(|n| n.contains("Runtime")));
        assert!(sink_names.iter().any(|n| n.contains("File")));
    }

    #[test]
    fn test_spring_has_sanitizers() {
        assert!(!SPRING_PROFILE.sanitizers.is_empty());

        let sanitizer_names: Vec<&str> = SPRING_PROFILE.sanitizers.iter().map(|s| s.name).collect();
        assert!(sanitizer_names.iter().any(|n| n.contains("Thymeleaf")));
        assert!(sanitizer_names.iter().any(|n| n.contains("HtmlUtils")));
        assert!(sanitizer_names.iter().any(|n| n.contains("Jsoup")));
    }

    #[test]
    fn test_spring_has_safe_patterns() {
        assert!(!SPRING_PROFILE.safe_patterns.is_empty());

        let pattern_names: Vec<&str> = SPRING_PROFILE
            .safe_patterns
            .iter()
            .map(|p| p.name)
            .collect();
        assert!(pattern_names.iter().any(|n| n.contains("JPA")));
        assert!(pattern_names.iter().any(|n| n.contains("Spring Data")));
    }

    #[test]
    fn test_spring_dangerous_patterns() {
        assert!(!SPRING_PROFILE.dangerous_patterns.is_empty());

        // Check for Java-specific patterns
        let pattern_names: Vec<&str> = SPRING_PROFILE
            .dangerous_patterns
            .iter()
            .map(|p| p.name)
            .collect();
        assert!(pattern_names.iter().any(|n| n.contains("concat")));
        assert!(pattern_names.iter().any(|n| n.contains("th:utext")));
        assert!(pattern_names.iter().any(|n| n.contains("Optional")));
    }

    #[test]
    fn test_di_annotations() {
        assert!(has_di_annotation("@Autowired private DataSource ds;"));
        assert!(has_di_annotation("@Inject DataSource ds;"));
        assert!(has_di_annotation("@Value(\"${db.url}\") String url;"));
        assert!(!has_di_annotation("private DataSource ds;"));
    }

    #[test]
    fn test_test_setup_annotations() {
        assert!(has_test_setup_annotation("@Before"));
        assert!(has_test_setup_annotation("@BeforeEach"));
        assert!(has_test_setup_annotation("@BeforeAll public void setUp()"));
        assert!(!has_test_setup_annotation("@Test public void test()"));
    }

    #[test]
    fn test_extract_di_field_name() {
        assert_eq!(
            extract_di_field_name("@Autowired private DataSource dataSource;"),
            Some("dataSource".to_string())
        );
        assert_eq!(
            extract_di_field_name("@Inject DataSource ds;"),
            Some("ds".to_string())
        );
        assert_eq!(
            extract_di_field_name("@Value(\"${db.url}\") String url;"),
            Some("url".to_string())
        );
        assert_eq!(extract_di_field_name("private DataSource ds;"), None);
    }
}
