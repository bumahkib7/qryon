//! Fix command for automated dependency vulnerability remediation
//!
//! This module implements the `rma fix` command which:
//! - Scans dependencies for vulnerabilities using OSV
//! - Discovers available versions from package registries
//! - Validates candidate versions for safety using OSV
//! - Generates a fix plan with the best safe versions
//! - Applies fixes to lockfiles/manifests
//! - Optionally creates git branches and commits

use anyhow::{Context, Result};
use rma_analyzer::providers::AnalysisProvider;
use rma_analyzer::providers::osv::OsvProvider;
use rma_analyzer::providers::registry::{
    CratesIoVersionSource, GoVersionSource, NpmVersionSource, PyPiVersionSource, VersionInfo,
    VersionSource, VersionSourceConfig,
    semver_utils::{self, BumpCategory, SemVer},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

// ============================================================================
// Known Replacements for Unmaintained Crates
// ============================================================================

/// Known drop-in replacements for unmaintained packages
/// Sources: RustSec, npm advisories, PyPI, Go advisories, community knowledge
/// Format: (ecosystem, unmaintained_pkg, replacement_pkg, notes)
pub const KNOWN_REPLACEMENTS_BY_ECOSYSTEM: &[(&str, &str, &str, &str)] = &[
    // =========================================================================
    // RUST / crates.io
    // =========================================================================
    // From RustSec advisories (2024-2025)
    ("crates.io", "adler", "adler2", "Direct fork, same API"),
    (
        "crates.io",
        "rustls-pemfile",
        "rustls-pki-types",
        "Use rustls-pki-types >= 1.9.0",
    ),
    ("crates.io", "ring", "aws-lc-rs", "AWS-backed alternative"),
    (
        "crates.io",
        "gcc",
        "cc",
        "cc crate is the maintained successor",
    ),
    (
        "crates.io",
        "rand_os",
        "getrandom",
        "Use getrandom for OS randomness",
    ),
    (
        "crates.io",
        "opentelemetry-jaeger",
        "opentelemetry-otlp",
        "Use OTLP exporter",
    ),
    ("crates.io", "tempdir", "tempfile", "tempfile::tempdir()"),
    (
        "crates.io",
        "fxhash",
        "rustc-hash",
        "Drop-in replacement, same API",
    ),
    (
        "crates.io",
        "instant",
        "web-time",
        "Cross-platform Instant for WASM",
    ),
    ("crates.io", "failure", "anyhow", "Modern error handling"),
    (
        "crates.io",
        "error-chain",
        "thiserror",
        "Derive-based error types",
    ),
    (
        "crates.io",
        "lazy_static",
        "once_cell",
        "once_cell::sync::Lazy or std::sync::LazyLock",
    ),
    (
        "crates.io",
        "stdweb",
        "web-sys",
        "Official wasm-bindgen web APIs",
    ),
    ("crates.io", "serde_yaml", "serde_yml", "Community fork"),
    ("crates.io", "difference", "similar", "Modern diff library"),
    ("crates.io", "chrono-tz", "jiff", "Modern timezone library"),
    (
        "crates.io",
        "number_prefix",
        "humansize",
        "Human-readable sizes",
    ),
    ("crates.io", "hyper-tls", "hyper-rustls", "Pure Rust TLS"),
    ("crates.io", "native-tls", "rustls", "Pure Rust TLS"),
    ("crates.io", "mio-extras", "mio", "Merged into mio 0.7+"),
    ("crates.io", "tokio-core", "tokio", "Use tokio directly"),
    (
        "crates.io",
        "futures-preview",
        "futures",
        "Use stable futures",
    ),
    // =========================================================================
    // NPM / JavaScript / TypeScript
    // =========================================================================
    // Security-related replacements
    (
        "npm",
        "request",
        "node-fetch",
        "request is deprecated, use node-fetch or axios",
    ),
    (
        "npm",
        "request",
        "axios",
        "request is deprecated, use axios or node-fetch",
    ),
    (
        "npm",
        "request-promise",
        "node-fetch",
        "Use node-fetch with native promises",
    ),
    ("npm", "node-uuid", "uuid", "Renamed to uuid"),
    (
        "npm",
        "uuid",
        "crypto.randomUUID",
        "Use native crypto.randomUUID() in Node 19+",
    ),
    (
        "npm",
        "querystring",
        "URLSearchParams",
        "Use native URLSearchParams",
    ),
    (
        "npm",
        "mkdirp",
        "fs.mkdir",
        "Use fs.mkdir with {recursive: true}",
    ),
    (
        "npm",
        "rimraf",
        "fs.rm",
        "Use fs.rm with {recursive: true} in Node 14+",
    ),
    (
        "npm",
        "left-pad",
        "String.padStart",
        "Use native padStart()",
    ),
    // Deprecated/unmaintained packages
    (
        "npm",
        "moment",
        "date-fns",
        "Moment.js is in maintenance mode",
    ),
    (
        "npm",
        "moment",
        "dayjs",
        "Lightweight alternative to moment",
    ),
    (
        "npm",
        "moment",
        "luxon",
        "Modern datetime by Moment.js team",
    ),
    ("npm", "underscore", "lodash", "Lodash is more maintained"),
    (
        "npm",
        "lodash",
        "es-toolkit",
        "Modern ES toolkit, smaller bundle",
    ),
    ("npm", "colors", "chalk", "colors had supply chain incident"),
    ("npm", "chalk", "picocolors", "Smaller, faster alternative"),
    (
        "npm",
        "faker",
        "@faker-js/faker",
        "Original faker was deleted, use fork",
    ),
    (
        "npm",
        "node-sass",
        "sass",
        "node-sass deprecated, use dart-sass",
    ),
    (
        "npm",
        "tslint",
        "eslint",
        "TSLint deprecated, use ESLint + typescript-eslint",
    ),
    ("npm", "istanbul", "nyc", "istanbul renamed to nyc"),
    ("npm", "nyc", "c8", "c8 uses native V8 coverage"),
    (
        "npm",
        "mocha",
        "vitest",
        "Vitest is modern, fast test runner",
    ),
    (
        "npm",
        "jasmine",
        "vitest",
        "Consider Vitest for modern testing",
    ),
    (
        "npm",
        "enzyme",
        "@testing-library/react",
        "Enzyme unmaintained for React 18+",
    ),
    (
        "npm",
        "react-router-dom",
        "@tanstack/react-router",
        "Type-safe alternative",
    ),
    ("npm", "redux", "zustand", "Simpler state management"),
    (
        "npm",
        "redux",
        "@reduxjs/toolkit",
        "If staying with Redux, use RTK",
    ),
    ("npm", "classnames", "clsx", "clsx is smaller and faster"),
    (
        "npm",
        "express-validator",
        "zod",
        "Zod for schema validation",
    ),
    ("npm", "joi", "zod", "Zod is TypeScript-first"),
    ("npm", "yup", "zod", "Zod has better TypeScript support"),
    (
        "npm",
        "formik",
        "react-hook-form",
        "Better performance, smaller bundle",
    ),
    (
        "npm",
        "body-parser",
        "express.json",
        "Built into Express 4.16+",
    ),
    ("npm", "morgan", "pino-http", "Pino is faster"),
    ("npm", "winston", "pino", "Pino is faster for production"),
    (
        "npm",
        "dotenv",
        "process.env",
        "Use --env-file in Node 20.6+",
    ),
    (
        "npm",
        "cross-env",
        "process.env",
        "Use --env-file in Node 20.6+",
    ),
    (
        "npm",
        "nodemon",
        "node --watch",
        "Use --watch in Node 18.11+",
    ),
    ("npm", "ts-node", "tsx", "tsx is faster, uses esbuild"),
    (
        "npm",
        "husky",
        "lefthook",
        "lefthook is faster, no npm deps",
    ),
    // =========================================================================
    // PYTHON / PyPI
    // =========================================================================
    // Deprecated/unmaintained packages
    ("PyPI", "nose", "pytest", "nose is unmaintained, use pytest"),
    ("PyPI", "mock", "unittest.mock", "mock merged into stdlib"),
    ("PyPI", "imp", "importlib", "imp deprecated in Python 3.4"),
    (
        "PyPI",
        "optparse",
        "argparse",
        "optparse deprecated, use argparse",
    ),
    ("PyPI", "pipes", "shlex", "pipes deprecated"),
    (
        "PyPI",
        "formatter",
        "string.Template",
        "formatter module deprecated",
    ),
    // Security/best practices
    (
        "PyPI",
        "pycrypto",
        "pycryptodome",
        "PyCrypto unmaintained, has vulns",
    ),
    (
        "PyPI",
        "python-jose",
        "joserfc",
        "python-jose has known issues",
    ),
    ("PyPI", "pyjwt", "joserfc", "joserfc is more modern"),
    ("PyPI", "requests", "httpx", "httpx supports async"),
    ("PyPI", "aiohttp", "httpx", "httpx unified sync/async"),
    (
        "PyPI",
        "urllib3",
        "httpx",
        "Consider httpx for new projects",
    ),
    (
        "PyPI",
        "BeautifulSoup",
        "beautifulsoup4",
        "Use beautifulsoup4 package name",
    ),
    ("PyPI", "bs4", "beautifulsoup4", "Use beautifulsoup4"),
    ("PyPI", "PIL", "Pillow", "PIL is unmaintained, use Pillow"),
    (
        "PyPI",
        "sklearn",
        "scikit-learn",
        "Use correct package name",
    ),
    (
        "PyPI",
        "cv2",
        "opencv-python",
        "cv2 is import name, not package",
    ),
    (
        "PyPI",
        "dateutil",
        "python-dateutil",
        "Correct package name",
    ),
    (
        "PyPI",
        "yaml",
        "PyYAML",
        "yaml is import, PyYAML is package",
    ),
    ("PyPI", "dotenv", "python-dotenv", "Correct package name"),
    // Async/modern replacements
    ("PyPI", "celery", "dramatiq", "dramatiq is simpler, modern"),
    ("PyPI", "celery", "arq", "arq is async-native with Redis"),
    ("PyPI", "flask", "fastapi", "FastAPI for async APIs"),
    ("PyPI", "flask", "litestar", "Litestar (formerly Starlite)"),
    (
        "PyPI",
        "django-rest-framework",
        "django-ninja",
        "Faster, type hints",
    ),
    ("PyPI", "pipenv", "poetry", "Poetry is more popular now"),
    ("PyPI", "pipenv", "uv", "uv is blazing fast (Rust-based)"),
    ("PyPI", "pip", "uv", "uv for faster installs"),
    ("PyPI", "virtualenv", "venv", "Use stdlib venv"),
    ("PyPI", "pytz", "zoneinfo", "zoneinfo in stdlib Python 3.9+"),
    (
        "PyPI",
        "dateparser",
        "dateutil",
        "dateutil is more maintained",
    ),
    // =========================================================================
    // GO / golang
    // =========================================================================
    // Deprecated/archived packages
    (
        "Go",
        "github.com/pkg/errors",
        "errors",
        "Use stdlib errors with fmt.Errorf %w",
    ),
    (
        "Go",
        "github.com/go-kit/kit",
        "github.com/go-kit/log",
        "go-kit split into smaller pkgs",
    ),
    ("Go", "io/ioutil", "io", "ioutil deprecated in Go 1.16"),
    (
        "Go",
        "github.com/dgrijalva/jwt-go",
        "github.com/golang-jwt/jwt/v5",
        "Original unmaintained",
    ),
    (
        "Go",
        "github.com/gorilla/mux",
        "net/http",
        "Use stdlib ServeMux in Go 1.22+",
    ),
    (
        "Go",
        "github.com/gorilla/mux",
        "github.com/go-chi/chi",
        "chi is maintained",
    ),
    (
        "Go",
        "github.com/gorilla/websocket",
        "nhooyr.io/websocket",
        "nhooyr is more maintained",
    ),
    (
        "Go",
        "github.com/gorilla/sessions",
        "github.com/alexedwards/scs",
        "scs is actively maintained",
    ),
    (
        "Go",
        "github.com/gin-gonic/gin",
        "github.com/labstack/echo/v4",
        "Both active, echo simpler",
    ),
    (
        "Go",
        "github.com/sirupsen/logrus",
        "log/slog",
        "Use stdlib slog in Go 1.21+",
    ),
    (
        "Go",
        "github.com/uber-go/zap",
        "log/slog",
        "slog is now in stdlib",
    ),
    (
        "Go",
        "github.com/go-redis/redis",
        "github.com/redis/go-redis/v9",
        "Renamed package",
    ),
    (
        "Go",
        "github.com/gomodule/redigo",
        "github.com/redis/go-redis/v9",
        "go-redis more popular",
    ),
    (
        "Go",
        "github.com/jinzhu/gorm",
        "gorm.io/gorm",
        "GORM v2 is the new home",
    ),
    ("Go", "gopkg.in/yaml.v2", "gopkg.in/yaml.v3", "Use yaml.v3"),
    (
        "Go",
        "github.com/satori/go.uuid",
        "github.com/google/uuid",
        "satori unmaintained",
    ),
    (
        "Go",
        "github.com/gofrs/uuid",
        "github.com/google/uuid",
        "google/uuid is most used",
    ),
    (
        "Go",
        "github.com/urfave/cli",
        "github.com/urfave/cli/v2",
        "Use v2",
    ),
    (
        "Go",
        "github.com/spf13/viper",
        "github.com/knadh/koanf",
        "koanf is simpler, no reflect",
    ),
    (
        "Go",
        "github.com/mitchellh/mapstructure",
        "encoding/json",
        "Consider stdlib for simple cases",
    ),
    (
        "Go",
        "github.com/stretchr/testify",
        "testing",
        "stdlib testing + go-cmp",
    ),
    (
        "Go",
        "github.com/golang/protobuf",
        "google.golang.org/protobuf",
        "New protobuf API",
    ),
    (
        "Go",
        "github.com/gogo/protobuf",
        "google.golang.org/protobuf",
        "gogo deprecated",
    ),
    // =========================================================================
    // MAVEN / Java
    // =========================================================================
    (
        "Maven",
        "junit:junit",
        "org.junit.jupiter:junit-jupiter",
        "JUnit 5 is current",
    ),
    (
        "Maven",
        "log4j:log4j",
        "org.apache.logging.log4j:log4j-core",
        "Log4j 1.x has CVEs",
    ),
    (
        "Maven",
        "commons-logging:commons-logging",
        "org.slf4j:slf4j-api",
        "SLF4J is modern standard",
    ),
    (
        "Maven",
        "javax.servlet:servlet-api",
        "jakarta.servlet:jakarta.servlet-api",
        "Jakarta EE naming",
    ),
    (
        "Maven",
        "javax.*",
        "jakarta.*",
        "Java EE renamed to Jakarta EE",
    ),
    (
        "Maven",
        "org.apache.httpcomponents:httpclient",
        "java.net.http.HttpClient",
        "Use JDK 11+ HttpClient",
    ),
    (
        "Maven",
        "com.google.code.gson:gson",
        "com.fasterxml.jackson.core:jackson-databind",
        "Jackson more features",
    ),
    (
        "Maven",
        "org.json:json",
        "com.fasterxml.jackson.core:jackson-databind",
        "Jackson is faster",
    ),
    (
        "Maven",
        "joda-time:joda-time",
        "java.time",
        "Use java.time in JDK 8+",
    ),
    (
        "Maven",
        "org.apache.commons:commons-lang3",
        "java.util",
        "Many utils now in stdlib",
    ),
    (
        "Maven",
        "com.google.guava:guava",
        "java.util",
        "Many features now in JDK",
    ),
    (
        "Maven",
        "org.hibernate:hibernate-core",
        "org.hibernate.orm:hibernate-core",
        "New group ID",
    ),
    (
        "Maven",
        "mysql:mysql-connector-java",
        "com.mysql:mysql-connector-j",
        "New artifact ID",
    ),
    (
        "Maven",
        "org.projectlombok:lombok",
        "record",
        "Use JDK 16+ records where possible",
    ),
    (
        "Maven",
        "io.springfox:springfox-swagger2",
        "org.springdoc:springdoc-openapi-ui",
        "Springfox unmaintained",
    ),
];

/// Get replacement suggestion for an unmaintained package (ecosystem-aware)
fn get_replacement_suggestion(
    ecosystem: &str,
    package: &str,
) -> Option<(&'static str, &'static str)> {
    KNOWN_REPLACEMENTS_BY_ECOSYSTEM
        .iter()
        .find(|(eco, pkg, _, _)| *eco == ecosystem && *pkg == package)
        .map(|(_, _, replacement, notes)| (*replacement, *notes))
}

// ============================================================================
// Types and Configuration
// ============================================================================

/// Fix strategy for version selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FixStrategy {
    /// Pick the lowest version that fixes the vulnerability (minimal breaking changes)
    Minimal,
    /// Pick the best version considering bump size, safety, and adoption
    #[default]
    Best,
    /// Pick the latest safe version
    Latest,
}

impl std::str::FromStr for FixStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "minimal" => Ok(Self::Minimal),
            "best" => Ok(Self::Best),
            "latest" => Ok(Self::Latest),
            _ => Err(format!("Unknown strategy: {}", s)),
        }
    }
}

impl std::fmt::Display for FixStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixStrategy::Minimal => write!(f, "minimal"),
            FixStrategy::Best => write!(f, "best"),
            FixStrategy::Latest => write!(f, "latest"),
        }
    }
}

/// Maximum version bump allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum MaxBump {
    Patch,
    Minor,
    Major,
    #[default]
    Any,
}

impl std::str::FromStr for MaxBump {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "patch" => Ok(Self::Patch),
            "minor" => Ok(Self::Minor),
            "major" => Ok(Self::Major),
            "any" => Ok(Self::Any),
            _ => Err(format!("Unknown max bump: {}", s)),
        }
    }
}

impl MaxBump {
    fn allows(&self, bump: BumpCategory) -> bool {
        match self {
            MaxBump::Patch => bump == BumpCategory::Patch,
            MaxBump::Minor => bump <= BumpCategory::Minor,
            MaxBump::Major | MaxBump::Any => true,
        }
    }
}

/// Arguments for the fix command
#[derive(Debug, Clone)]
pub struct FixArgs {
    pub path: PathBuf,
    /// Fix strategy
    pub strategy: FixStrategy,
    /// Maximum version bump
    pub max_bump: MaxBump,
    /// Allow prerelease versions
    pub allow_prerelease: bool,
    /// Allow yanked versions
    pub allow_yanked: bool,
    /// Offline mode (cache only)
    pub offline: bool,
    /// Show detailed candidate analysis
    pub explain: bool,
    /// Dry run (show plan without applying)
    pub dry_run: bool,
    /// Apply fixes
    pub apply: bool,
    /// Git branch name
    pub branch_name: Option<String>,
    /// Create git commit
    pub commit: bool,
    /// Commit message prefix
    pub commit_prefix: String,
    /// Force operations even if working tree is dirty
    pub force: bool,
    /// Skip git operations
    pub no_git: bool,
    /// Limit number of upgrades
    pub limit: Option<usize>,
    /// Force specific versions (pkg@ver)
    pub targets: Vec<String>,
    /// Allow vulnerable target versions
    pub allow_vulnerable_target: bool,
    /// Output format
    pub format: OutputFormat,
}

impl Default for FixArgs {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            strategy: FixStrategy::Best,
            max_bump: MaxBump::Any,
            allow_prerelease: false,
            allow_yanked: false,
            offline: false,
            explain: false,
            dry_run: true,
            apply: false,
            branch_name: None,
            commit: false,
            commit_prefix: "rma:".to_string(),
            force: false,
            no_git: false,
            limit: None,
            targets: vec![],
            allow_vulnerable_target: false,
            format: OutputFormat::Pretty,
        }
    }
}

/// Output format for fix results
#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Pretty,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

// ============================================================================
// Fix Plan Types
// ============================================================================

/// Action to take for a fix
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FixAction {
    /// Upgrade to a specific version
    UpgradeTo { version: String },
    /// Upgrade without specific version (run cargo update, npm update, etc.)
    UpgradeUnspecified,
    /// Upgrade parent package to unlock transitive dependency
    UpgradeParent {
        parent_package: String,
        parent_version: Option<String>,
        reason: String,
    },
    /// Replace with a different crate (for unmaintained packages)
    ReplaceWith { replacement: String, notes: String },
    /// No fix available
    NoFixAvailable { reason: String },
}

/// A single fix item in the plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixItem {
    /// Ecosystem (crates.io, npm, PyPI, Go, Maven)
    pub ecosystem: String,
    /// Package name
    pub package: String,
    /// Current installed version
    pub current_version: String,
    /// Action to take
    pub action: FixAction,
    /// Advisory IDs being fixed
    pub advisory_ids: Vec<String>,
    /// File that led to detection
    pub source_file: PathBuf,
    /// Bump category if upgrading
    pub bump_category: Option<BumpCategory>,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Reason for selection
    pub reason: String,
    /// Skipped candidates (if explain mode)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_candidates: Vec<SkippedCandidate>,
}

/// A skipped candidate version with reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedCandidate {
    pub version: String,
    pub reason: String,
    /// Vulnerability IDs if still vulnerable
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vuln_ids: Vec<String>,
}

/// Complete fix plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixPlan {
    /// Items to fix
    pub items: Vec<FixItem>,
    /// Items skipped with reasons
    pub skipped: Vec<SkippedItem>,
    /// Total vulnerabilities found
    pub total_vulns: usize,
    /// Total fixable
    pub total_fixable: usize,
    /// Timestamp
    pub timestamp: String,
}

/// An item that was skipped
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedItem {
    pub ecosystem: String,
    pub package: String,
    pub current_version: String,
    pub reason: String,
    pub advisory_ids: Vec<String>,
}

/// Result of applying fixes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    pub plan: FixPlan,
    /// Files modified
    pub files_modified: Vec<PathBuf>,
    /// Commands executed
    pub commands_executed: Vec<String>,
    /// Git branch created
    pub branch_created: Option<String>,
    /// Git commit hash
    pub commit_hash: Option<String>,
    /// Errors encountered
    pub errors: Vec<String>,
    /// Whether all fixes were applied successfully
    pub success: bool,
}

// ============================================================================
// Vulnerability Discovery
// ============================================================================

/// Vulnerability found in a dependency
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VulnerableDep {
    pub ecosystem: String,
    pub package: String,
    pub installed_version: String,
    pub advisory_ids: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub source_file: PathBuf,
    pub severity: String,
    /// Whether this is a transitive (indirect) dependency
    pub is_transitive: bool,
    /// Parent package that constrains this dependency (for transitive deps)
    pub constrained_by: Option<String>,
}

/// Discover vulnerable dependencies using OSV
fn discover_vulnerabilities(path: &Path, offline: bool) -> Result<Vec<VulnerableDep>> {
    use rma_common::OsvProviderConfig;

    let osv_config = OsvProviderConfig {
        offline,
        ..Default::default()
    };
    let osv_provider = OsvProvider::new(osv_config);
    if !osv_provider.is_available() && !offline {
        anyhow::bail!("OSV provider is not available");
    }

    let findings = osv_provider.analyze_directory(path)?;

    // Convert findings to VulnerableDep
    let mut vulns: HashMap<(String, String, String), VulnerableDep> = HashMap::new();

    // Check which packages are direct dependencies
    let direct_deps = get_direct_dependencies(path);

    for finding in findings {
        // Parse ecosystem and package from finding - use source file for detection
        let ecosystem = extract_ecosystem(&finding.rule_id, &finding.location.file);
        let (package, version) = parse_package_version(&finding.message, &finding.snippet);

        if package.is_empty() || version.is_empty() {
            continue;
        }

        // Extract advisory IDs and fixed versions from suggestion
        let (advisory_ids, fixed_versions) = parse_fix_info(&finding.suggestion);

        // Check if this is a transitive dependency
        let is_transitive = !direct_deps.contains(&package);

        let key = (ecosystem.clone(), package.clone(), version.clone());

        vulns
            .entry(key)
            .and_modify(|v| {
                // Merge advisory IDs
                for id in &advisory_ids {
                    if !v.advisory_ids.contains(id) {
                        v.advisory_ids.push(id.clone());
                    }
                }
                // Merge fixed versions
                for fv in &fixed_versions {
                    if !v.fixed_versions.contains(fv) {
                        v.fixed_versions.push(fv.clone());
                    }
                }
            })
            .or_insert_with(|| VulnerableDep {
                ecosystem,
                package,
                installed_version: version,
                advisory_ids,
                fixed_versions,
                source_file: finding.location.file.clone(),
                severity: finding.severity.to_string(),
                is_transitive,
                constrained_by: None, // TODO: Parse from cargo tree or lockfile
            });
    }

    Ok(vulns.into_values().collect())
}

/// Get list of direct dependencies from manifest files
fn get_direct_dependencies(path: &Path) -> std::collections::HashSet<String> {
    let mut direct_deps = std::collections::HashSet::new();

    // Parse Cargo.toml for Rust dependencies
    let cargo_toml = path.join("Cargo.toml");
    if cargo_toml.exists()
        && let Ok(content) = fs::read_to_string(&cargo_toml)
        && let Ok(toml_value) = content.parse::<toml::Value>()
    {
        // Check [dependencies]
        if let Some(deps) = toml_value.get("dependencies").and_then(|d| d.as_table()) {
            for key in deps.keys() {
                direct_deps.insert(key.clone());
            }
        }
        // Check [dev-dependencies]
        if let Some(deps) = toml_value
            .get("dev-dependencies")
            .and_then(|d| d.as_table())
        {
            for key in deps.keys() {
                direct_deps.insert(key.clone());
            }
        }
        // Check [build-dependencies]
        if let Some(deps) = toml_value
            .get("build-dependencies")
            .and_then(|d| d.as_table())
        {
            for key in deps.keys() {
                direct_deps.insert(key.clone());
            }
        }
        // Check workspace members' dependencies
        if let Some(workspace) = toml_value.get("workspace")
            && let Some(deps) = workspace.get("dependencies").and_then(|d| d.as_table())
        {
            for key in deps.keys() {
                direct_deps.insert(key.clone());
            }
        }
    }

    // Parse package.json for npm dependencies
    let package_json = path.join("package.json");
    if package_json.exists()
        && let Ok(content) = fs::read_to_string(&package_json)
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
    {
        if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            for key in deps.keys() {
                direct_deps.insert(key.clone());
            }
        }
        if let Some(deps) = json.get("devDependencies").and_then(|d| d.as_object()) {
            for key in deps.keys() {
                direct_deps.insert(key.clone());
            }
        }
    }

    direct_deps
}

/// Detect ecosystem from the source lockfile path
fn detect_ecosystem_from_file(source_file: &Path) -> Option<String> {
    let filename = source_file.file_name()?.to_str()?;
    match filename {
        "Cargo.lock" => Some("crates.io".to_string()),
        "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => Some("npm".to_string()),
        "go.mod" | "go.sum" => Some("Go".to_string()),
        "requirements.txt" | "Pipfile.lock" | "poetry.lock" => Some("PyPI".to_string()),
        "pom.xml" | "build.gradle" | "build.gradle.kts" => Some("Maven".to_string()),
        _ => None,
    }
}

fn extract_ecosystem(rule_id: &str, source_file: &Path) -> String {
    // First try to detect from source file (most reliable)
    if let Some(eco) = detect_ecosystem_from_file(source_file) {
        return eco;
    }

    // Fall back to rule_id parsing
    if rule_id.contains("RUSTSEC") || rule_id.contains("crates.io") {
        "crates.io".to_string()
    } else if rule_id.contains("npm") {
        "npm".to_string()
    } else if rule_id.contains("PyPI") || rule_id.contains("python") {
        "PyPI".to_string()
    } else if rule_id.contains("Go") || rule_id.contains("golang") {
        "Go".to_string()
    } else if rule_id.contains("Maven") {
        "Maven".to_string()
    } else {
        // Try to infer from the rule_id format
        let parts: Vec<&str> = rule_id.split('/').collect();
        if parts.len() >= 2 {
            parts[1].to_string()
        } else {
            "unknown".to_string()
        }
    }
}

fn parse_package_version(message: &str, snippet: &Option<String>) -> (String, String) {
    // Try to parse from message format: "package v1.2.3: description"
    let re = regex::Regex::new(r"^([^\s]+)\s+v?(\d+\.\d+\.\d+[^\s:]*)").ok();
    if let Some(re) = re
        && let Some(caps) = re.captures(message)
    {
        return (
            caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string(),
            caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
        );
    }

    // Try snippet format: package = "version"
    if let Some(snippet) = snippet {
        let re = regex::Regex::new(r#"([^\s=]+)\s*=\s*"([^"]+)""#).ok();
        if let Some(re) = re
            && let Some(caps) = re.captures(snippet)
        {
            return (
                caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string(),
                caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
            );
        }
    }

    (String::new(), String::new())
}

fn parse_fix_info(suggestion: &Option<String>) -> (Vec<String>, Vec<String>) {
    let mut advisory_ids = Vec::new();
    let mut fixed_versions = Vec::new();

    if let Some(suggestion) = suggestion {
        // Extract advisory IDs (GHSA-xxx, RUSTSEC-xxx, CVE-xxx)
        let id_re = regex::Regex::new(r"(GHSA-[a-z0-9-]+|RUSTSEC-\d+-\d+|CVE-\d+-\d+)").ok();
        if let Some(re) = id_re {
            for cap in re.captures_iter(suggestion) {
                if let Some(id) = cap.get(1) {
                    let id_str = id.as_str().to_string();
                    if !advisory_ids.contains(&id_str) {
                        advisory_ids.push(id_str);
                    }
                }
            }
        }

        // Extract fixed versions from "Patched in: X.Y.Z" or "upgrade to X.Y.Z"
        let ver_re =
            regex::Regex::new(r"(?:Patched in|upgrade to|fixed in)[:\s]+([v\d][^\s,]+)").ok();
        if let Some(re) = ver_re {
            for cap in re.captures_iter(suggestion) {
                if let Some(ver) = cap.get(1) {
                    let ver_str = ver.as_str().trim_start_matches('v').to_string();
                    if !fixed_versions.contains(&ver_str) {
                        fixed_versions.push(ver_str);
                    }
                }
            }
        }
    }

    (advisory_ids, fixed_versions)
}

// ============================================================================
// OSV Safety Validation
// ============================================================================

/// Summary of vulnerabilities for an exact version
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VulnSummary {
    pub id: String,
    pub severity: String,
    pub summary: String,
}

/// Check if a specific version has vulnerabilities using OSV
fn osv_vulns_for_exact(ecosystem: &str, package: &str, version: &str) -> Result<Vec<VulnSummary>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let osv_ecosystem = match ecosystem {
        "crates.io" => "crates.io",
        "npm" => "npm",
        "PyPI" => "PyPI",
        "Go" => "Go",
        "Maven" => "Maven",
        _ => return Ok(vec![]),
    };

    let query = serde_json::json!({
        "version": version,
        "package": {
            "name": package,
            "ecosystem": osv_ecosystem
        }
    });

    let response = client
        .post("https://api.osv.dev/v1/query")
        .json(&query)
        .send()
        .context("Failed to query OSV")?;

    if !response.status().is_success() {
        return Ok(vec![]); // Assume safe if API fails
    }

    #[derive(Deserialize)]
    struct OsvQueryResponse {
        vulns: Option<Vec<OsvVuln>>,
    }

    #[derive(Deserialize)]
    struct OsvVuln {
        id: String,
        summary: Option<String>,
        severity: Option<Vec<OsvSeverity>>,
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct OsvSeverity {
        score: Option<String>,
        #[serde(rename = "type")]
        severity_type: Option<String>,
    }

    let osv_response: OsvQueryResponse =
        response.json().unwrap_or(OsvQueryResponse { vulns: None });

    let vulns = osv_response
        .vulns
        .unwrap_or_default()
        .into_iter()
        .map(|v| {
            let severity = v
                .severity
                .and_then(|s| s.first().and_then(|s| s.score.clone()))
                .unwrap_or_else(|| "unknown".to_string());

            VulnSummary {
                id: v.id,
                severity,
                summary: v.summary.unwrap_or_default(),
            }
        })
        .collect();

    Ok(vulns)
}

// ============================================================================
// Candidate Scoring and Selection
// ============================================================================

/// Score a candidate version
#[derive(Debug, Clone)]
struct CandidateScore {
    version: String,
    is_safe: bool,
    vuln_count: usize,
    bump_category: BumpCategory,
    bump_distance: u32,
    popularity: u64,
    recency_score: u32,
}

impl CandidateScore {
    fn total_score(&self) -> i64 {
        if !self.is_safe {
            return -(self.vuln_count as i64 * 1000);
        }

        let mut score: i64 = 10000; // Base score for safe versions

        // Prefer smaller bumps
        score -= match self.bump_category {
            BumpCategory::Patch => 0,
            BumpCategory::Minor => 100,
            BumpCategory::Major => 500,
        };

        // Prefer smaller version jumps
        score -= (self.bump_distance as i64).min(100);

        // Slight preference for popular versions
        score += (self.popularity.min(10000) / 100) as i64;

        // Slight preference for newer versions
        score += self.recency_score as i64;

        score
    }
}

/// Select the best version from candidates
fn select_best_version(
    current_version: &str,
    candidates: &[VersionInfo],
    ecosystem: &str,
    package: &str,
    args: &FixArgs,
    skipped: &mut Vec<SkippedCandidate>,
) -> Result<Option<(String, BumpCategory, u8, String)>> {
    let current = match SemVer::parse(current_version) {
        Some(v) => v,
        None => {
            debug!("Cannot parse current version: {}", current_version);
            return Ok(None);
        }
    };

    // Filter and sort candidates
    let mut valid_candidates: Vec<(VersionInfo, SemVer)> = candidates
        .iter()
        .filter_map(|v| {
            let sv = SemVer::parse(&v.version)?;

            // Must be greater than current
            if sv <= current {
                return None;
            }

            // Check bump limit
            let bump = semver_utils::classify_bump(&current, &sv);
            if !args.max_bump.allows(bump) {
                skipped.push(SkippedCandidate {
                    version: v.version.clone(),
                    reason: format!("exceeds max bump ({} > {:?})", bump, args.max_bump),
                    vuln_ids: vec![],
                });
                return None;
            }

            // Check prerelease
            if !args.allow_prerelease && (v.prerelease || sv.is_prerelease()) {
                skipped.push(SkippedCandidate {
                    version: v.version.clone(),
                    reason: "prerelease version".to_string(),
                    vuln_ids: vec![],
                });
                return None;
            }

            // Check yanked
            if !args.allow_yanked && v.yanked {
                skipped.push(SkippedCandidate {
                    version: v.version.clone(),
                    reason: "yanked version".to_string(),
                    vuln_ids: vec![],
                });
                return None;
            }

            Some((v.clone(), sv))
        })
        .collect();

    // Sort by semver (ascending for minimal, descending for latest)
    valid_candidates.sort_by(|a, b| a.1.cmp(&b.1));

    if valid_candidates.is_empty() {
        return Ok(None);
    }

    // Apply strategy
    match args.strategy {
        FixStrategy::Minimal => {
            // Find first safe version
            for (v, sv) in &valid_candidates {
                let vulns = osv_vulns_for_exact(ecosystem, package, &v.version)?;
                if vulns.is_empty() {
                    let bump = semver_utils::classify_bump(&current, sv);
                    return Ok(Some((
                        v.version.clone(),
                        bump,
                        90,
                        "minimal safe version".to_string(),
                    )));
                }
                skipped.push(SkippedCandidate {
                    version: v.version.clone(),
                    reason: "still vulnerable".to_string(),
                    vuln_ids: vulns.into_iter().map(|v| v.id).collect(),
                });
            }
        }

        FixStrategy::Latest => {
            // Find highest safe version (scan from top)
            for (v, sv) in valid_candidates.iter().rev() {
                let vulns = osv_vulns_for_exact(ecosystem, package, &v.version)?;
                if vulns.is_empty() {
                    let bump = semver_utils::classify_bump(&current, sv);
                    return Ok(Some((
                        v.version.clone(),
                        bump,
                        85,
                        "latest safe version".to_string(),
                    )));
                }
                skipped.push(SkippedCandidate {
                    version: v.version.clone(),
                    reason: "still vulnerable".to_string(),
                    vuln_ids: vulns.into_iter().map(|v| v.id).collect(),
                });
            }
        }

        FixStrategy::Best => {
            // Score all candidates and pick best
            let mut scored: Vec<CandidateScore> = Vec::new();

            for (v, sv) in &valid_candidates {
                let vulns = osv_vulns_for_exact(ecosystem, package, &v.version)?;
                let bump = semver_utils::classify_bump(&current, sv);
                // Use saturating_sub to prevent underflow
                let bump_distance = sv.major.saturating_sub(current.major) * 10000
                    + sv.minor.saturating_sub(current.minor) * 100
                    + sv.patch.saturating_sub(current.patch);

                if !vulns.is_empty() {
                    skipped.push(SkippedCandidate {
                        version: v.version.clone(),
                        reason: "still vulnerable".to_string(),
                        vuln_ids: vulns.iter().map(|v| v.id.clone()).collect(),
                    });
                }

                scored.push(CandidateScore {
                    version: v.version.clone(),
                    is_safe: vulns.is_empty(),
                    vuln_count: vulns.len(),
                    bump_category: bump,
                    bump_distance,
                    popularity: v.downloads.unwrap_or(0),
                    recency_score: 0, // Could compute from published_at
                });
            }

            // Sort by score (descending)
            scored.sort_by_key(|s| std::cmp::Reverse(s.total_score()));

            // Return best safe version
            if let Some(best) = scored.iter().find(|s| s.is_safe) {
                return Ok(Some((
                    best.version.clone(),
                    best.bump_category,
                    95,
                    format!(
                        "best safe version ({} bump, score: {})",
                        best.bump_category,
                        best.total_score()
                    ),
                )));
            }

            // If no safe version, return least-bad but mark as no fix
            if let Some(least_bad) = scored.first() {
                return Ok(Some((
                    least_bad.version.clone(),
                    least_bad.bump_category,
                    30,
                    format!(
                        "least vulnerable ({} vulns remaining)",
                        least_bad.vuln_count
                    ),
                )));
            }
        }
    }

    Ok(None)
}

// ============================================================================
// Fix Plan Generation
// ============================================================================

/// Generate a fix plan for vulnerable dependencies
pub fn generate_fix_plan(args: &FixArgs) -> Result<FixPlan> {
    info!("Generating fix plan for {}", args.path.display());

    // Discover vulnerabilities
    let vulns = discover_vulnerabilities(&args.path, args.offline)?;
    let total_vulns = vulns.len();

    info!("Found {} vulnerable packages", total_vulns);

    // Create version sources
    let source_config = VersionSourceConfig {
        offline: args.offline,
        ..Default::default()
    };

    let crates_source = CratesIoVersionSource::new(source_config.clone());
    let npm_source = NpmVersionSource::new(source_config.clone());
    let pypi_source = PyPiVersionSource::new(source_config.clone());
    let go_source = GoVersionSource::new(source_config);

    let mut items = Vec::new();
    let mut skipped_items = Vec::new();

    // Process each vulnerability
    for vuln in vulns {
        // Check if this is a transitive dependency that can't be directly upgraded
        if vuln.is_transitive {
            // Check for known replacement first (ecosystem-aware)
            if let Some((replacement, notes)) =
                get_replacement_suggestion(&vuln.ecosystem, &vuln.package)
            {
                items.push(FixItem {
                    ecosystem: vuln.ecosystem.clone(),
                    package: vuln.package.clone(),
                    current_version: vuln.installed_version.clone(),
                    action: FixAction::ReplaceWith {
                        replacement: replacement.to_string(),
                        notes: notes.to_string(),
                    },
                    advisory_ids: vuln.advisory_ids,
                    source_file: vuln.source_file,
                    bump_category: None,
                    confidence: 70,
                    reason: format!("unmaintained package, replace with {}", replacement),
                    skipped_candidates: vec![],
                });
                continue;
            }

            // For transitive deps without fix, suggest parent upgrade
            if vuln.fixed_versions.is_empty() {
                skipped_items.push(SkippedItem {
                    ecosystem: vuln.ecosystem,
                    package: vuln.package,
                    current_version: vuln.installed_version,
                    reason:
                        "transitive dependency - upgrade parent package or wait for upstream fix"
                            .to_string(),
                    advisory_ids: vuln.advisory_ids,
                });
                continue;
            }
        }

        // Check for known replacement for unmaintained packages (even if direct dep)
        if vuln.fixed_versions.is_empty()
            && let Some((replacement, notes)) =
                get_replacement_suggestion(&vuln.ecosystem, &vuln.package)
        {
            items.push(FixItem {
                ecosystem: vuln.ecosystem.clone(),
                package: vuln.package.clone(),
                current_version: vuln.installed_version.clone(),
                action: FixAction::ReplaceWith {
                    replacement: replacement.to_string(),
                    notes: notes.to_string(),
                },
                advisory_ids: vuln.advisory_ids,
                source_file: vuln.source_file,
                bump_category: None,
                confidence: 70,
                reason: format!("unmaintained package, replace with {}", replacement),
                skipped_candidates: vec![],
            });
            continue;
        }

        // Check for forced target
        let forced_target = args.targets.iter().find_map(|t| {
            let parts: Vec<&str> = t.splitn(2, '@').collect();
            if parts.len() == 2 && parts[0] == vuln.package {
                Some(parts[1].to_string())
            } else {
                None
            }
        });

        if let Some(target_version) = forced_target {
            // Validate forced target
            if !args.allow_vulnerable_target {
                let target_vulns =
                    osv_vulns_for_exact(&vuln.ecosystem, &vuln.package, &target_version)?;
                if !target_vulns.is_empty() {
                    skipped_items.push(SkippedItem {
                        ecosystem: vuln.ecosystem,
                        package: vuln.package,
                        current_version: vuln.installed_version,
                        reason: format!(
                            "forced target {} is still vulnerable (use --allow-vulnerable-target)",
                            target_version
                        ),
                        advisory_ids: vuln.advisory_ids,
                    });
                    continue;
                }
            }

            let bump = if let (Some(current), Some(target)) = (
                SemVer::parse(&vuln.installed_version),
                SemVer::parse(&target_version),
            ) {
                Some(semver_utils::classify_bump(&current, &target))
            } else {
                None
            };

            items.push(FixItem {
                ecosystem: vuln.ecosystem,
                package: vuln.package,
                current_version: vuln.installed_version,
                action: FixAction::UpgradeTo {
                    version: target_version.clone(),
                },
                advisory_ids: vuln.advisory_ids,
                source_file: vuln.source_file,
                bump_category: bump,
                confidence: 100,
                reason: "forced target version".to_string(),
                skipped_candidates: vec![],
            });
            continue;
        }

        // Get available versions from registry
        let versions_result: Result<Vec<VersionInfo>> = match vuln.ecosystem.as_str() {
            "crates.io" => crates_source.list_versions(&vuln.package),
            "npm" => npm_source.list_versions(&vuln.package),
            "PyPI" => pypi_source.list_versions(&vuln.package),
            "Go" => go_source.list_versions(&vuln.package),
            _ => {
                skipped_items.push(SkippedItem {
                    ecosystem: vuln.ecosystem,
                    package: vuln.package,
                    current_version: vuln.installed_version,
                    reason: "unsupported ecosystem".to_string(),
                    advisory_ids: vuln.advisory_ids,
                });
                continue;
            }
        };

        let versions = match versions_result {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to get versions for {}: {}", vuln.package, e);

                // Fall back to OSV-suggested versions
                if !vuln.fixed_versions.is_empty() {
                    let best_fix = vuln
                        .fixed_versions
                        .iter()
                        .max_by(|a, b| semver_utils::compare_versions(a, b));

                    if let Some(fix_ver) = best_fix {
                        let bump = if let (Some(current), Some(target)) = (
                            SemVer::parse(&vuln.installed_version),
                            SemVer::parse(fix_ver),
                        ) {
                            Some(semver_utils::classify_bump(&current, &target))
                        } else {
                            None
                        };

                        items.push(FixItem {
                            ecosystem: vuln.ecosystem,
                            package: vuln.package,
                            current_version: vuln.installed_version,
                            action: FixAction::UpgradeTo {
                                version: fix_ver.clone(),
                            },
                            advisory_ids: vuln.advisory_ids,
                            source_file: vuln.source_file,
                            bump_category: bump,
                            confidence: 70,
                            reason: "OSV-suggested fix version".to_string(),
                            skipped_candidates: vec![],
                        });
                        continue;
                    }
                }

                skipped_items.push(SkippedItem {
                    ecosystem: vuln.ecosystem,
                    package: vuln.package,
                    current_version: vuln.installed_version,
                    reason: format!("failed to fetch versions: {}", e),
                    advisory_ids: vuln.advisory_ids,
                });
                continue;
            }
        };

        // Select best version
        let mut skipped_candidates = Vec::new();
        let selection = select_best_version(
            &vuln.installed_version,
            &versions,
            &vuln.ecosystem,
            &vuln.package,
            args,
            &mut skipped_candidates,
        )?;

        match selection {
            Some((version, bump, confidence, reason)) => {
                // Check if it's actually safe
                let is_safe =
                    osv_vulns_for_exact(&vuln.ecosystem, &vuln.package, &version)?.is_empty();

                if is_safe || confidence < 50 {
                    items.push(FixItem {
                        ecosystem: vuln.ecosystem,
                        package: vuln.package,
                        current_version: vuln.installed_version,
                        action: FixAction::UpgradeTo { version },
                        advisory_ids: vuln.advisory_ids,
                        source_file: vuln.source_file,
                        bump_category: Some(bump),
                        confidence,
                        reason,
                        skipped_candidates: if args.explain {
                            skipped_candidates
                        } else {
                            vec![]
                        },
                    });
                } else {
                    items.push(FixItem {
                        ecosystem: vuln.ecosystem.clone(),
                        package: vuln.package.clone(),
                        current_version: vuln.installed_version.clone(),
                        action: FixAction::NoFixAvailable {
                            reason: format!(
                                "no safe version found; {} is least vulnerable",
                                version
                            ),
                        },
                        advisory_ids: vuln.advisory_ids,
                        source_file: vuln.source_file,
                        bump_category: None,
                        confidence: 0,
                        reason: "no safe upgrade path".to_string(),
                        skipped_candidates: if args.explain {
                            skipped_candidates
                        } else {
                            vec![]
                        },
                    });
                }
            }
            None => {
                // Check if we can just run update without specific version
                if !vuln.fixed_versions.is_empty() {
                    items.push(FixItem {
                        ecosystem: vuln.ecosystem,
                        package: vuln.package,
                        current_version: vuln.installed_version,
                        action: FixAction::UpgradeUnspecified,
                        advisory_ids: vuln.advisory_ids,
                        source_file: vuln.source_file,
                        bump_category: None,
                        confidence: 50,
                        reason: "fix exists but version selection failed".to_string(),
                        skipped_candidates: if args.explain {
                            skipped_candidates
                        } else {
                            vec![]
                        },
                    });
                } else {
                    skipped_items.push(SkippedItem {
                        ecosystem: vuln.ecosystem,
                        package: vuln.package,
                        current_version: vuln.installed_version,
                        reason: "no fix available".to_string(),
                        advisory_ids: vuln.advisory_ids,
                    });
                }
            }
        }
    }

    // Apply limit
    if let Some(limit) = args.limit {
        items.truncate(limit);
    }

    // Sort by ecosystem, then package
    items.sort_by(|a, b| (&a.ecosystem, &a.package).cmp(&(&b.ecosystem, &b.package)));

    let total_fixable = items
        .iter()
        .filter(|i| !matches!(i.action, FixAction::NoFixAvailable { .. }))
        .count();

    Ok(FixPlan {
        items,
        skipped: skipped_items,
        total_vulns,
        total_fixable,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

// ============================================================================
// Fix Application
// ============================================================================

/// Apply fixes from the plan
fn apply_fixes(plan: &FixPlan, args: &FixArgs) -> Result<FixResult> {
    let mut result = FixResult {
        plan: plan.clone(),
        files_modified: vec![],
        commands_executed: vec![],
        branch_created: None,
        commit_hash: None,
        errors: vec![],
        success: true,
    };

    // Check git status if needed
    if !args.no_git && (args.branch_name.is_some() || args.commit) {
        if !is_git_repo(&args.path) {
            if args.commit || args.branch_name.is_some() {
                result.errors.push("Not a git repository".to_string());
                result.success = false;
                return Ok(result);
            }
        } else if !args.force && is_working_tree_dirty(&args.path)? {
            result
                .errors
                .push("Working tree is dirty. Use --force to override.".to_string());
            result.success = false;
            return Ok(result);
        }

        // Create branch if requested
        if let Some(ref branch_name) = args.branch_name {
            match create_git_branch(&args.path, branch_name) {
                Ok(()) => {
                    result.branch_created = Some(branch_name.clone());
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("Failed to create branch: {}", e));
                    result.success = false;
                    return Ok(result);
                }
            }
        }
    }

    // Group fixes by ecosystem (only include automatically applicable actions)
    let mut by_ecosystem: HashMap<String, Vec<&FixItem>> = HashMap::new();
    for item in &plan.items {
        // Skip actions that require manual intervention
        match &item.action {
            FixAction::NoFixAvailable { .. } => continue,
            FixAction::ReplaceWith { .. } => {
                // Log the manual action needed
                result.commands_executed.push(format!(
                    "# MANUAL: Replace {} with recommended replacement",
                    item.package
                ));
                continue;
            }
            FixAction::UpgradeParent { parent_package, .. } => {
                // Log the manual action needed
                result.commands_executed.push(format!(
                    "# MANUAL: Upgrade {} to unlock {}",
                    parent_package, item.package
                ));
                continue;
            }
            _ => {}
        }
        by_ecosystem
            .entry(item.ecosystem.clone())
            .or_default()
            .push(item);
    }

    // Apply fixes per ecosystem
    for (ecosystem, items) in &by_ecosystem {
        match ecosystem.as_str() {
            "crates.io" => {
                for item in items {
                    let cmd = match &item.action {
                        FixAction::UpgradeTo { version } => {
                            format!("cargo update -p {} --precise {}", item.package, version)
                        }
                        FixAction::UpgradeUnspecified => {
                            format!("cargo update -p {}", item.package)
                        }
                        _ => continue,
                    };

                    result.commands_executed.push(cmd.clone());

                    let output = Command::new("sh")
                        .arg("-c")
                        .arg(&cmd)
                        .current_dir(&args.path)
                        .output();

                    match output {
                        Ok(out) if out.status.success() => {
                            if let Some(lockfile) = find_cargo_lock(&args.path)
                                && !result.files_modified.contains(&lockfile)
                            {
                                result.files_modified.push(lockfile);
                            }
                        }
                        Ok(out) => {
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            result.errors.push(format!(
                                "Command failed: {} - {}",
                                cmd,
                                stderr.trim()
                            ));
                            result.success = false;
                        }
                        Err(e) => {
                            result
                                .errors
                                .push(format!("Failed to execute {}: {}", cmd, e));
                            result.success = false;
                        }
                    }
                }
            }

            "npm" => {
                // Check if package.json exists
                let pkg_json = find_package_json(&args.path);
                if pkg_json.is_none() {
                    // Skip npm if no package.json - likely a false positive
                    result
                        .commands_executed
                        .push("# SKIPPED: No package.json found, npm packages skipped".to_string());
                    continue;
                }

                let pkg_json = pkg_json.unwrap();
                let mut has_npm_changes = false;

                // For npm, we need to update package.json if it's a direct dependency
                for item in items {
                    if let FixAction::UpgradeTo { version } = &item.action {
                        // Try to update package.json
                        if update_package_json(&pkg_json, &item.package, version)? {
                            if !result.files_modified.contains(&pkg_json) {
                                result.files_modified.push(pkg_json.clone());
                            }
                            has_npm_changes = true;
                        }
                    }
                }

                // Only run npm install if we made changes
                if has_npm_changes {
                    let cmd = "npm install --package-lock-only";
                    result.commands_executed.push(cmd.to_string());

                    let output = Command::new("sh")
                        .arg("-c")
                        .arg(cmd)
                        .current_dir(&args.path)
                        .output();

                    match output {
                        Ok(out) if out.status.success() => {
                            if let Some(lockfile) = find_npm_lock(&args.path)
                                && !result.files_modified.contains(&lockfile)
                            {
                                result.files_modified.push(lockfile);
                            }
                        }
                        Ok(out) => {
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            result
                                .errors
                                .push(format!("npm install failed: {}", stderr.trim()));
                        }
                        Err(e) => {
                            result
                                .errors
                                .push(format!("Failed to run npm install: {}", e));
                        }
                    }
                }
            }

            "PyPI" => {
                // Update requirements.txt
                for item in items {
                    if let FixAction::UpgradeTo { version } = &item.action
                        && let Some(req_txt) = find_requirements_txt(&args.path)
                        && update_requirements_txt(&req_txt, &item.package, version)?
                        && !result.files_modified.contains(&req_txt)
                    {
                        result.files_modified.push(req_txt);
                    }
                }
            }

            "Go" => {
                for item in items {
                    let cmd = match &item.action {
                        FixAction::UpgradeTo { version } => {
                            format!("go get {}@v{} && go mod tidy", item.package, version)
                        }
                        FixAction::UpgradeUnspecified => {
                            format!("go get -u {} && go mod tidy", item.package)
                        }
                        _ => continue,
                    };

                    result.commands_executed.push(cmd.clone());

                    let output = Command::new("sh")
                        .arg("-c")
                        .arg(&cmd)
                        .current_dir(&args.path)
                        .output();

                    match output {
                        Ok(out) if out.status.success() => {
                            let go_mod = args.path.join("go.mod");
                            let go_sum = args.path.join("go.sum");
                            if go_mod.exists() && !result.files_modified.contains(&go_mod) {
                                result.files_modified.push(go_mod);
                            }
                            if go_sum.exists() && !result.files_modified.contains(&go_sum) {
                                result.files_modified.push(go_sum);
                            }
                        }
                        Ok(out) => {
                            let stderr = String::from_utf8_lossy(&out.stderr);
                            result
                                .errors
                                .push(format!("Go command failed: {}", stderr.trim()));
                        }
                        Err(e) => {
                            result.errors.push(format!("Failed to run go: {}", e));
                        }
                    }
                }
            }

            "Maven" => {
                // For Maven, just print recommendations
                for item in items {
                    if let FixAction::UpgradeTo { version } = &item.action {
                        result.commands_executed.push(format!(
                            "# Update {} to {} in pom.xml/build.gradle",
                            item.package, version
                        ));
                    }
                }
            }

            _ => {
                result
                    .errors
                    .push(format!("Unsupported ecosystem: {}", ecosystem));
            }
        }
    }

    // Commit if requested
    if !args.no_git && args.commit && !result.files_modified.is_empty() && result.success {
        let commit_msg = generate_commit_message(&args.commit_prefix, &plan.items);

        match create_git_commit(&args.path, &result.files_modified, &commit_msg) {
            Ok(hash) => {
                result.commit_hash = Some(hash);
            }
            Err(e) => {
                result.errors.push(format!("Failed to commit: {}", e));
                result.success = false;
            }
        }
    }

    Ok(result)
}

fn find_cargo_lock(path: &Path) -> Option<PathBuf> {
    let lock = path.join("Cargo.lock");
    if lock.exists() { Some(lock) } else { None }
}

fn find_package_json(path: &Path) -> Option<PathBuf> {
    let pkg = path.join("package.json");
    if pkg.exists() { Some(pkg) } else { None }
}

fn find_npm_lock(path: &Path) -> Option<PathBuf> {
    let lock = path.join("package-lock.json");
    if lock.exists() {
        return Some(lock);
    }
    let yarn = path.join("yarn.lock");
    if yarn.exists() {
        return Some(yarn);
    }
    let pnpm = path.join("pnpm-lock.yaml");
    if pnpm.exists() {
        return Some(pnpm);
    }
    None
}

fn find_requirements_txt(path: &Path) -> Option<PathBuf> {
    let req = path.join("requirements.txt");
    if req.exists() { Some(req) } else { None }
}

fn update_package_json(path: &Path, package: &str, version: &str) -> Result<bool> {
    let content = fs::read_to_string(path)?;
    let mut json: serde_json::Value = serde_json::from_str(&content)?;

    let mut modified = false;

    // Check dependencies
    if let Some(deps) = json.get_mut("dependencies").and_then(|d| d.as_object_mut())
        && deps.contains_key(package)
    {
        deps.insert(
            package.to_string(),
            serde_json::Value::String(format!("^{}", version)),
        );
        modified = true;
    }

    // Check devDependencies
    if let Some(deps) = json
        .get_mut("devDependencies")
        .and_then(|d| d.as_object_mut())
        && deps.contains_key(package)
    {
        deps.insert(
            package.to_string(),
            serde_json::Value::String(format!("^{}", version)),
        );
        modified = true;
    }

    if modified {
        let new_content = serde_json::to_string_pretty(&json)?;
        fs::write(path, new_content)?;
    }

    Ok(modified)
}

fn update_requirements_txt(path: &Path, package: &str, version: &str) -> Result<bool> {
    let content = fs::read_to_string(path)?;
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut modified = false;

    for line in &mut lines {
        // Match patterns like: package==X.Y.Z or package>=X.Y.Z
        let pattern = format!(r"^{}[=><]", regex::escape(package));
        if let Ok(re) = regex::Regex::new(&pattern)
            && re.is_match(line)
        {
            *line = format!("{}=={}", package, version);
            modified = true;
        }
    }

    if modified {
        fs::write(path, lines.join("\n"))?;
    }

    Ok(modified)
}

// ============================================================================
// Git Operations
// ============================================================================

fn is_git_repo(path: &Path) -> bool {
    path.join(".git").exists()
        || Command::new("git")
            .args(["rev-parse", "--git-dir"])
            .current_dir(path)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

fn is_working_tree_dirty(path: &Path) -> Result<bool> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(path)
        .output()
        .context("Failed to check git status")?;

    Ok(!output.stdout.is_empty())
}

fn create_git_branch(path: &Path, name: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["checkout", "-b", name])
        .current_dir(path)
        .output()
        .context("Failed to create git branch")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git checkout -b failed: {}", stderr.trim());
    }

    Ok(())
}

fn create_git_commit(path: &Path, files: &[PathBuf], message: &str) -> Result<String> {
    // Stage files
    for file in files {
        let relative = file
            .strip_prefix(path)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();

        let output = Command::new("git")
            .args(["add", &relative])
            .current_dir(path)
            .output()
            .context("Failed to stage file")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("git add failed: {}", stderr.trim());
        }
    }

    // Commit
    let output = Command::new("git")
        .args(["commit", "-m", message])
        .current_dir(path)
        .output()
        .context("Failed to create commit")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git commit failed: {}", stderr.trim());
    }

    // Get commit hash
    let hash_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(path)
        .output()
        .context("Failed to get commit hash")?;

    Ok(String::from_utf8_lossy(&hash_output.stdout)
        .trim()
        .to_string())
}

fn generate_commit_message(prefix: &str, items: &[FixItem]) -> String {
    let mut msg = format!(
        "{} fix {} vulnerable dependencies (created by rma)\n\n",
        prefix,
        items
            .iter()
            .filter(|i| !matches!(i.action, FixAction::NoFixAvailable { .. }))
            .count()
    );

    for item in items {
        if let FixAction::UpgradeTo { version } = &item.action {
            msg.push_str(&format!(
                "- {} {} {} -> {} [{}]\n",
                item.ecosystem,
                item.package,
                item.current_version,
                version,
                item.advisory_ids.join(", ")
            ));
        }
    }

    msg.push_str("\nGenerated by RMA (Rust Monorepo Analyzer)");
    msg
}

// ============================================================================
// Output Formatting
// ============================================================================

fn print_fix_plan(plan: &FixPlan, args: &FixArgs) {
    use colored::*;

    println!();
    println!("{}", "═".repeat(70).blue());
    println!(
        "{}",
        "  🔧 RMA Fix Plan                                                    "
            .bold()
            .blue()
    );
    println!("{}", "═".repeat(70).blue());
    println!();

    println!(
        "  {} vulnerable packages found, {} fixable",
        plan.total_vulns.to_string().yellow(),
        plan.total_fixable.to_string().green()
    );
    println!();

    if plan.items.is_empty() && plan.skipped.is_empty() {
        println!("  {} No vulnerabilities found!", "✓".green());
        return;
    }

    // Group by ecosystem
    let mut by_ecosystem: HashMap<&str, Vec<&FixItem>> = HashMap::new();
    for item in &plan.items {
        by_ecosystem.entry(&item.ecosystem).or_default().push(item);
    }

    for (ecosystem, items) in &by_ecosystem {
        println!("  {} {}", "▶".cyan(), ecosystem.bold());
        println!();

        for item in items {
            let (icon, action_str) = match &item.action {
                FixAction::UpgradeTo { version } => {
                    let bump_str = item
                        .bump_category
                        .map(|b| format!(" ({})", b))
                        .unwrap_or_default();
                    (
                        "✓".green(),
                        format!(
                            "{} → {}{}",
                            item.current_version.red(),
                            version.green(),
                            bump_str.dimmed()
                        ),
                    )
                }
                FixAction::UpgradeUnspecified => (
                    "✓".green(),
                    format!("{} → {}", item.current_version.red(), "latest".yellow()),
                ),
                FixAction::UpgradeParent {
                    parent_package,
                    parent_version,
                    reason,
                } => {
                    let ver = parent_version
                        .as_ref()
                        .map(|v| format!("@{}", v))
                        .unwrap_or_default();
                    (
                        "↑".cyan(),
                        format!(
                            "{} (upgrade {} {}{})",
                            item.current_version.dimmed(),
                            parent_package.cyan(),
                            ver,
                            format!(" - {}", reason).dimmed()
                        ),
                    )
                }
                FixAction::ReplaceWith { replacement, notes } => (
                    "⇄".magenta(),
                    format!(
                        "{} → {} ({})",
                        item.current_version.red(),
                        replacement.magenta(),
                        notes.dimmed()
                    ),
                ),
                FixAction::NoFixAvailable { reason } => (
                    "⚠".yellow(),
                    format!("{} ⚠ {}", item.current_version.red(), reason.yellow()),
                ),
            };

            println!("    {} {} {}", icon, item.package.bold(), action_str);

            if !item.advisory_ids.is_empty() {
                println!(
                    "      {} {}",
                    "IDs:".dimmed(),
                    item.advisory_ids.join(", ").dimmed()
                );
            }

            println!(
                "      {} {} (confidence: {}%)",
                "Reason:".dimmed(),
                item.reason.dimmed(),
                item.confidence
            );

            if args.explain && !item.skipped_candidates.is_empty() {
                println!("      {} Skipped candidates:", "→".dimmed());
                for skip in &item.skipped_candidates {
                    let vuln_str = if skip.vuln_ids.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", skip.vuln_ids.join(", "))
                    };
                    println!(
                        "        {} {} - {}{}",
                        "·".dimmed(),
                        skip.version,
                        skip.reason.dimmed(),
                        vuln_str.dimmed()
                    );
                }
            }

            println!();
        }
    }

    if !plan.skipped.is_empty() {
        println!("  {} Skipped packages:", "⚠".yellow());
        for item in &plan.skipped {
            println!(
                "    {} {} {} - {}",
                "·".dimmed(),
                item.package,
                item.current_version.dimmed(),
                item.reason.yellow()
            );
        }
        println!();
    }

    if args.dry_run && !args.apply {
        println!(
            "  {} This is a dry run. Use {} to apply fixes.",
            "ℹ".blue(),
            "--apply".cyan()
        );
    }
}

fn print_fix_result(result: &FixResult, _args: &FixArgs) {
    use colored::*;

    println!();
    println!("{}", "─".repeat(70).blue());
    println!("{}", "  Fix Results".bold());
    println!("{}", "─".repeat(70).blue());
    println!();

    if result.success {
        println!("  {} Fixes applied successfully!", "✓".green());
    } else {
        println!("  {} Some fixes failed", "✗".red());
    }

    if !result.commands_executed.is_empty() {
        println!();
        println!("  {} Commands executed:", "▶".cyan());
        for cmd in &result.commands_executed {
            println!("    $ {}", cmd.dimmed());
        }
    }

    if !result.files_modified.is_empty() {
        println!();
        println!("  {} Files modified:", "▶".cyan());
        for file in &result.files_modified {
            println!("    {}", file.display().to_string().green());
        }
    }

    if let Some(ref branch) = result.branch_created {
        println!();
        println!("  {} Branch created: {}", "▶".cyan(), branch.green());
    }

    if let Some(ref hash) = result.commit_hash {
        println!();
        println!("  {} Commit: {}", "▶".cyan(), hash.green());
    }

    if !result.errors.is_empty() {
        println!();
        println!("  {} Errors:", "▶".red());
        for err in &result.errors {
            println!("    {}", err.red());
        }
    }

    println!();

    // Print next steps
    if let Some(branch) = &result.branch_created {
        println!("  {} Next steps:", "ℹ".blue());
        println!("    $ git push -u origin {}", branch);
        println!("    Then create a pull request for review.");
    }
}

fn print_json_output(plan: &FixPlan, result: Option<&FixResult>) {
    #[derive(Serialize)]
    struct JsonOutput<'a> {
        plan: &'a FixPlan,
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<&'a FixResult>,
    }

    let output = JsonOutput { plan, result };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Run the fix command
pub fn run(args: FixArgs) -> Result<()> {
    // Generate fix plan
    let plan = generate_fix_plan(&args)?;

    // Output based on format
    match args.format {
        OutputFormat::Pretty => {
            print_fix_plan(&plan, &args);
        }
        OutputFormat::Json => {
            if !args.apply {
                print_json_output(&plan, None);
                return Ok(());
            }
        }
    }

    // Apply if requested
    if args.apply {
        let result = apply_fixes(&plan, &args)?;

        match args.format {
            OutputFormat::Pretty => {
                print_fix_result(&result, &args);
            }
            OutputFormat::Json => {
                print_json_output(&plan, Some(&result));
            }
        }

        if !result.success {
            std::process::exit(1);
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_strategy_parsing() {
        assert_eq!(
            "minimal".parse::<FixStrategy>().unwrap(),
            FixStrategy::Minimal
        );
        assert_eq!("best".parse::<FixStrategy>().unwrap(), FixStrategy::Best);
        assert_eq!(
            "latest".parse::<FixStrategy>().unwrap(),
            FixStrategy::Latest
        );
    }

    #[test]
    fn test_max_bump_allows() {
        assert!(MaxBump::Patch.allows(BumpCategory::Patch));
        assert!(!MaxBump::Patch.allows(BumpCategory::Minor));
        assert!(!MaxBump::Patch.allows(BumpCategory::Major));

        assert!(MaxBump::Minor.allows(BumpCategory::Patch));
        assert!(MaxBump::Minor.allows(BumpCategory::Minor));
        assert!(!MaxBump::Minor.allows(BumpCategory::Major));

        assert!(MaxBump::Any.allows(BumpCategory::Major));
    }

    #[test]
    fn test_parse_package_version() {
        let (pkg, ver) = parse_package_version("serde v1.0.0: serialization bug", &None);
        assert_eq!(pkg, "serde");
        assert_eq!(ver, "1.0.0");

        let (pkg, ver) = parse_package_version("", &Some(r#"tokio = "1.25.0""#.to_string()));
        assert_eq!(pkg, "tokio");
        assert_eq!(ver, "1.25.0");
    }

    #[test]
    fn test_parse_fix_info() {
        let suggestion = Some(
            "Advisory: RUSTSEC-2021-0123\nPatched in: 1.2.3, 1.3.0\nMore info: https://..."
                .to_string(),
        );
        let (ids, versions) = parse_fix_info(&suggestion);
        assert!(ids.contains(&"RUSTSEC-2021-0123".to_string()));
        assert!(versions.contains(&"1.2.3".to_string()));
    }

    #[test]
    fn test_extract_ecosystem() {
        use std::path::Path;
        // Test with Cargo.lock file
        assert_eq!(
            extract_ecosystem("osv/RUSTSEC-2021-0001", Path::new("Cargo.lock")),
            "crates.io"
        );
        // Test with package-lock.json
        assert_eq!(
            extract_ecosystem("osv/GHSA-abcd-1234", Path::new("package-lock.json")),
            "npm"
        );
        // Test with fallback to rule_id
        assert_eq!(
            extract_ecosystem("osv/PyPI/something", Path::new("unknown.txt")),
            "PyPI"
        );
    }

    #[test]
    fn test_fix_plan_deduplication() {
        // Simulated test for deduplication
        let vuln1 = VulnerableDep {
            ecosystem: "crates.io".to_string(),
            package: "test-pkg".to_string(),
            installed_version: "1.0.0".to_string(),
            advisory_ids: vec!["GHSA-1".to_string()],
            fixed_versions: vec!["1.1.0".to_string()],
            source_file: PathBuf::from("Cargo.lock"),
            severity: "high".to_string(),
            is_transitive: false,
            constrained_by: None,
        };

        let vuln2 = VulnerableDep {
            ecosystem: "crates.io".to_string(),
            package: "test-pkg".to_string(),
            installed_version: "1.0.0".to_string(),
            advisory_ids: vec!["RUSTSEC-1".to_string()],
            fixed_versions: vec!["1.1.0".to_string()],
            source_file: PathBuf::from("Cargo.lock"),
            severity: "high".to_string(),
            is_transitive: false,
            constrained_by: None,
        };

        // Test that merge works
        let mut merged = vuln1.clone();
        for id in &vuln2.advisory_ids {
            if !merged.advisory_ids.contains(id) {
                merged.advisory_ids.push(id.clone());
            }
        }

        assert_eq!(merged.advisory_ids.len(), 2);
        assert!(merged.advisory_ids.contains(&"GHSA-1".to_string()));
        assert!(merged.advisory_ids.contains(&"RUSTSEC-1".to_string()));
    }

    #[test]
    fn test_generate_commit_message() {
        let items = vec![FixItem {
            ecosystem: "crates.io".to_string(),
            package: "serde".to_string(),
            current_version: "1.0.0".to_string(),
            action: FixAction::UpgradeTo {
                version: "1.0.1".to_string(),
            },
            advisory_ids: vec!["RUSTSEC-2021-0001".to_string()],
            source_file: PathBuf::from("Cargo.lock"),
            bump_category: Some(BumpCategory::Patch),
            confidence: 95,
            reason: "test".to_string(),
            skipped_candidates: vec![],
        }];

        let msg = generate_commit_message("rma:", &items);
        assert!(msg.contains("rma:"));
        assert!(msg.contains("created by rma"));
        assert!(msg.contains("serde"));
        assert!(msg.contains("1.0.0"));
        assert!(msg.contains("1.0.1"));
    }
}
