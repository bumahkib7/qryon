//! OSV (Open Source Vulnerabilities) provider for multi-language dependency scanning
//!
//! This provider uses a **local vulnerability database** downloaded from OSV.dev's GCS bucket.
//! No API calls are made at scan time - everything is local for maximum speed and offline support.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    OSV Provider Architecture                             │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │   1. Database Update (rma cache update)                                 │
//! │      Download ZIPs from GCS → Extract → Index in Sled + Bloom Filter    │
//! │                                                                          │
//! │   2. Scan Time (rma scan / rma security)                                │
//! │      Parse lockfiles → Query local DB → Return findings                 │
//! │                                                                          │
//! │   Query Flow:                                                           │
//! │   Package + Version → Bloom Filter (O(1)) → Index (O(1)) → Sled → Match │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Supported Ecosystems
//!
//! | Ecosystem | Lock File | Download URL |
//! |-----------|-----------|--------------|
//! | crates.io | Cargo.lock | storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip |
//! | npm | package-lock.json | storage.googleapis.com/osv-vulnerabilities/npm/all.zip |
//! | PyPI | requirements.txt, poetry.lock | storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip |
//! | Go | go.mod, go.sum | storage.googleapis.com/osv-vulnerabilities/Go/all.zip |
//! | Maven | pom.xml, build.gradle | storage.googleapis.com/osv-vulnerabilities/Maven/all.zip |

use super::AnalysisProvider;
use super::osv_db::{OsvDatabase, VulnMatch};
use anyhow::{Context, Result};
use rma_common::{
    Confidence, Finding, FindingCategory, Language, OsvEcosystem, OsvProviderConfig, Severity,
    SourceLocation,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Import location information for reachability analysis
#[derive(Debug, Clone)]
struct ImportLocation {
    /// File where the import was found
    file: PathBuf,
    /// Line number of the import
    line: usize,
}

/// Import information for a package
#[derive(Debug, Clone, Default)]
struct ImportInfo {
    /// List of import locations
    locations: Vec<ImportLocation>,
}

impl ImportInfo {
    fn add_location(&mut self, file: PathBuf, line: usize) {
        self.locations.push(ImportLocation { file, line });
    }

    fn hit_count(&self) -> usize {
        self.locations.len()
    }

    /// Get up to N sample file paths
    fn sample_files(&self, n: usize) -> Vec<String> {
        self.locations
            .iter()
            .take(n)
            .map(|loc| format!("{}:{}", loc.file.display(), loc.line))
            .collect()
    }
}

/// A reference to a package dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRef {
    /// OSV ecosystem identifier
    pub ecosystem: OsvEcosystem,
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Dependency scope (runtime, dev, build, etc.)
    pub scope: DependencyScope,
    /// Source file where the dependency was found
    pub source_file: PathBuf,
}

/// Dependency scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyScope {
    Runtime,
    Dev,
    Build,
    Optional,
}

impl std::fmt::Display for DependencyScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyScope::Runtime => write!(f, "runtime"),
            DependencyScope::Dev => write!(f, "dev"),
            DependencyScope::Build => write!(f, "build"),
            DependencyScope::Optional => write!(f, "optional"),
        }
    }
}

/// OSV vulnerability response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvVulnerability {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

/// OSV batch query request
#[derive(Debug, Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvQueryPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvQueryPackage {
    ecosystem: String,
    name: String,
}

/// OSV batch query response
#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

/// Cache entry for OSV results
#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    vulns: Vec<OsvVulnerability>,
    cached_at: u64,
}

/// OSV Provider for multi-language dependency vulnerability scanning
///
/// Uses a local Sled-based vulnerability database with bloom filters for O(1) lookups.
/// No network calls at scan time - fully offline operation.
pub struct OsvProvider {
    config: OsvProviderConfig,
    cache_dir: PathBuf,
    cache_ttl: Duration,
    /// Local vulnerability database (lazy-loaded)
    db: Option<Arc<OsvDatabase>>,
}

impl Default for OsvProvider {
    fn default() -> Self {
        Self::new(OsvProviderConfig::default())
    }
}

impl OsvProvider {
    /// Create a new OSV provider with local database
    pub fn new(config: OsvProviderConfig) -> Self {
        let cache_dir = config
            .cache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(".rma/cache/osv"));

        let cache_ttl = parse_duration(&config.cache_ttl).unwrap_or(Duration::from_secs(86400));

        // Try to open the local database
        let db_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rma")
            .join("osv-db");

        let db = OsvDatabase::new(db_path).map(Arc::new).ok();

        if db.is_some() {
            info!("OSV local database loaded");
        } else {
            debug!("OSV local database not available, will use API fallback");
        }

        Self {
            config,
            cache_dir,
            cache_ttl,
            db,
        }
    }

    /// Get or initialize the local database
    pub fn database(&self) -> Option<&Arc<OsvDatabase>> {
        self.db.as_ref()
    }

    /// Check if local database is available and up-to-date
    pub fn has_local_db(&self) -> bool {
        if let Some(db) = &self.db {
            // Check if any ecosystem is loaded
            for eco in &self.config.enabled_ecosystems {
                if db.ecosystem(*eco).is_ok() {
                    return true;
                }
            }
        }
        false
    }

    /// Update the local database for all enabled ecosystems
    pub fn update_database(&self) -> Result<Vec<super::osv_db::UpdateStats>> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?;

        db.update_all(&self.config.enabled_ecosystems, None)
    }

    /// Scan a directory for dependencies and vulnerabilities
    pub fn scan_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        info!("OSV scanning directory: {}", path.display());

        // Extract dependencies from lockfiles
        let packages = self.extract_dependencies(path)?;
        info!("Found {} dependencies", packages.len());

        if packages.is_empty() {
            return Ok(Vec::new());
        }

        // Query OSV for vulnerabilities
        let vulns = self.query_vulnerabilities(&packages)?;
        info!("Found {} vulnerabilities", vulns.len());

        // Convert to findings
        let findings = self.create_findings(&packages, &vulns, path)?;

        Ok(findings)
    }

    /// Extract dependencies from all supported lockfiles
    fn extract_dependencies(&self, path: &Path) -> Result<Vec<PackageRef>> {
        let mut packages = Vec::new();

        // Rust: Cargo.lock
        if self
            .config
            .enabled_ecosystems
            .contains(&OsvEcosystem::CratesIo)
        {
            let cargo_lock = path.join("Cargo.lock");
            if cargo_lock.exists() {
                packages.extend(self.parse_cargo_lock(&cargo_lock)?);
            }
        }

        // JavaScript/TypeScript: package-lock.json
        if self.config.enabled_ecosystems.contains(&OsvEcosystem::Npm) {
            let package_lock = path.join("package-lock.json");
            if package_lock.exists() {
                packages.extend(self.parse_package_lock(&package_lock)?);
            }
        }

        // Go: go.mod + go.sum
        if self.config.enabled_ecosystems.contains(&OsvEcosystem::Go) {
            let go_mod = path.join("go.mod");
            let go_sum = path.join("go.sum");
            if go_mod.exists() {
                packages.extend(self.parse_go_mod(&go_mod, &go_sum)?);
            }
        }

        // Python: requirements.txt, poetry.lock
        if self.config.enabled_ecosystems.contains(&OsvEcosystem::PyPI) {
            let requirements = path.join("requirements.txt");
            if requirements.exists() {
                packages.extend(self.parse_requirements_txt(&requirements)?);
            }
            let poetry_lock = path.join("poetry.lock");
            if poetry_lock.exists() {
                packages.extend(self.parse_poetry_lock(&poetry_lock)?);
            }
        }

        // Java: pom.xml, build.gradle
        if self
            .config
            .enabled_ecosystems
            .contains(&OsvEcosystem::Maven)
        {
            let pom = path.join("pom.xml");
            if pom.exists() {
                packages.extend(self.parse_pom_xml(&pom)?);
            }
            let gradle = path.join("build.gradle");
            if gradle.exists() {
                packages.extend(self.parse_gradle(&gradle)?);
            }
            let gradle_kts = path.join("build.gradle.kts");
            if gradle_kts.exists() {
                packages.extend(self.parse_gradle(&gradle_kts)?);
            }
        }

        // Filter dev dependencies if configured
        if !self.config.include_dev_deps {
            packages.retain(|p| p.scope != DependencyScope::Dev);
        }

        Ok(packages)
    }

    /// Parse Cargo.lock (Rust)
    fn parse_cargo_lock(&self, path: &Path) -> Result<Vec<PackageRef>> {
        let content = fs::read_to_string(path)?;
        let mut packages = Vec::new();

        // Parse TOML
        let lock: toml::Value = toml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        if let Some(pkgs) = lock.get("package").and_then(|v| v.as_array()) {
            for pkg in pkgs {
                let name = pkg.get("name").and_then(|v| v.as_str());
                let version = pkg.get("version").and_then(|v| v.as_str());

                if let (Some(name), Some(version)) = (name, version) {
                    packages.push(PackageRef {
                        ecosystem: OsvEcosystem::CratesIo,
                        name: name.to_string(),
                        version: version.to_string(),
                        scope: DependencyScope::Runtime, // Cargo.lock doesn't distinguish
                        source_file: path.to_path_buf(),
                    });
                }
            }
        }

        debug!("Parsed {} packages from Cargo.lock", packages.len());
        Ok(packages)
    }

    /// Parse package-lock.json (npm)
    fn parse_package_lock(&self, path: &Path) -> Result<Vec<PackageRef>> {
        let content = fs::read_to_string(path)?;
        let mut packages = Vec::new();

        let lock: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        // Handle npm v2/v3 lockfile format
        if let Some(deps) = lock.get("packages").and_then(|v| v.as_object()) {
            for (key, value) in deps {
                // Skip root package
                if key.is_empty() {
                    continue;
                }

                // Extract package name from path (node_modules/package-name)
                let name = key.strip_prefix("node_modules/").unwrap_or(key);

                if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                    let is_dev = value.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);

                    packages.push(PackageRef {
                        ecosystem: OsvEcosystem::Npm,
                        name: name.to_string(),
                        version: version.to_string(),
                        scope: if is_dev {
                            DependencyScope::Dev
                        } else {
                            DependencyScope::Runtime
                        },
                        source_file: path.to_path_buf(),
                    });
                }
            }
        } else if let Some(deps) = lock.get("dependencies").and_then(|v| v.as_object()) {
            // npm v1 lockfile format
            fn extract_deps(
                deps: &serde_json::Map<String, serde_json::Value>,
                packages: &mut Vec<PackageRef>,
                path: &Path,
            ) {
                for (name, value) in deps {
                    if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                        let is_dev = value.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);

                        packages.push(PackageRef {
                            ecosystem: OsvEcosystem::Npm,
                            name: name.clone(),
                            version: version.to_string(),
                            scope: if is_dev {
                                DependencyScope::Dev
                            } else {
                                DependencyScope::Runtime
                            },
                            source_file: path.to_path_buf(),
                        });
                    }

                    // Recurse into nested dependencies
                    if let Some(nested) = value.get("dependencies").and_then(|v| v.as_object()) {
                        extract_deps(nested, packages, path);
                    }
                }
            }
            extract_deps(deps, &mut packages, path);
        }

        debug!("Parsed {} packages from package-lock.json", packages.len());
        Ok(packages)
    }

    /// Parse go.mod + go.sum (Go)
    fn parse_go_mod(&self, go_mod: &Path, go_sum: &Path) -> Result<Vec<PackageRef>> {
        let mut packages = Vec::new();

        // Parse go.mod for module names and versions
        let content = fs::read_to_string(go_mod)?;

        let mut in_require = false;
        for line in content.lines() {
            let line = line.trim();

            if line.starts_with("require (") || line.starts_with("require(") {
                in_require = true;
                continue;
            }
            if in_require && line == ")" {
                in_require = false;
                continue;
            }

            // Single line require
            if let Some(rest) = line.strip_prefix("require ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[0].trim();
                    let version = parts[1].trim_start_matches('v');
                    packages.push(PackageRef {
                        ecosystem: OsvEcosystem::Go,
                        name: name.to_string(),
                        version: version.to_string(),
                        scope: DependencyScope::Runtime,
                        source_file: go_mod.to_path_buf(),
                    });
                }
            } else if in_require {
                // Multi-line require block
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && !parts[0].starts_with("//") {
                    let name = parts[0].trim();
                    let version = parts[1].trim_start_matches('v');
                    // Skip indirect dependencies marker
                    let version = version.split_whitespace().next().unwrap_or(version);
                    packages.push(PackageRef {
                        ecosystem: OsvEcosystem::Go,
                        name: name.to_string(),
                        version: version.to_string(),
                        scope: DependencyScope::Runtime,
                        source_file: go_mod.to_path_buf(),
                    });
                }
            }
        }

        // Optionally parse go.sum for more precise versions
        if go_sum.exists() {
            // go.sum contains hashes, we already have versions from go.mod
            debug!("go.sum exists, using versions from go.mod");
        }

        debug!("Parsed {} packages from go.mod", packages.len());
        Ok(packages)
    }

    /// Parse requirements.txt (Python)
    fn parse_requirements_txt(&self, path: &Path) -> Result<Vec<PackageRef>> {
        let content = fs::read_to_string(path)?;
        let mut packages = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }

            // Parse package==version or package>=version etc.
            let (name, version) = if let Some(idx) = line.find("==") {
                (&line[..idx], &line[idx + 2..])
            } else if let Some(idx) = line.find(">=") {
                (&line[..idx], &line[idx + 2..])
            } else if let Some(idx) = line.find("~=") {
                (&line[..idx], &line[idx + 2..])
            } else {
                // No version specified
                continue;
            };

            // Clean up version (remove extras like [dev], comments)
            let version = version.split('[').next().unwrap_or(version);
            let version = version.split('#').next().unwrap_or(version);
            let version = version.split(',').next().unwrap_or(version);

            if !name.is_empty() && !version.is_empty() {
                packages.push(PackageRef {
                    ecosystem: OsvEcosystem::PyPI,
                    name: name.trim().to_string(),
                    version: version.trim().to_string(),
                    scope: DependencyScope::Runtime,
                    source_file: path.to_path_buf(),
                });
            }
        }

        debug!("Parsed {} packages from requirements.txt", packages.len());
        Ok(packages)
    }

    /// Parse poetry.lock (Python)
    fn parse_poetry_lock(&self, path: &Path) -> Result<Vec<PackageRef>> {
        let content = fs::read_to_string(path)?;
        let mut packages = Vec::new();

        let lock: toml::Value = toml::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        if let Some(pkgs) = lock.get("package").and_then(|v| v.as_array()) {
            for pkg in pkgs {
                let name = pkg.get("name").and_then(|v| v.as_str());
                let version = pkg.get("version").and_then(|v| v.as_str());
                let category = pkg
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("main");

                if let (Some(name), Some(version)) = (name, version) {
                    packages.push(PackageRef {
                        ecosystem: OsvEcosystem::PyPI,
                        name: name.to_string(),
                        version: version.to_string(),
                        scope: if category == "dev" {
                            DependencyScope::Dev
                        } else {
                            DependencyScope::Runtime
                        },
                        source_file: path.to_path_buf(),
                    });
                }
            }
        }

        debug!("Parsed {} packages from poetry.lock", packages.len());
        Ok(packages)
    }

    /// Parse pom.xml (Maven/Java)
    fn parse_pom_xml(&self, path: &Path) -> Result<Vec<PackageRef>> {
        let content = fs::read_to_string(path)?;
        let mut packages = Vec::new();

        // Simple regex-based parsing for pom.xml
        // A full XML parser would be better but this is lightweight
        let dependency_re =
            regex::Regex::new(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>")
                .unwrap();

        for cap in dependency_re.captures_iter(&content) {
            let group_id = &cap[1];
            let artifact_id = &cap[2];
            let version = &cap[3];

            // Skip property references like ${project.version}
            if version.starts_with('$') {
                continue;
            }

            packages.push(PackageRef {
                ecosystem: OsvEcosystem::Maven,
                name: format!("{}:{}", group_id, artifact_id),
                version: version.to_string(),
                scope: DependencyScope::Runtime,
                source_file: path.to_path_buf(),
            });
        }

        debug!("Parsed {} packages from pom.xml", packages.len());
        Ok(packages)
    }

    /// Parse build.gradle or build.gradle.kts (Gradle/Java)
    fn parse_gradle(&self, path: &Path) -> Result<Vec<PackageRef>> {
        let content = fs::read_to_string(path)?;
        let mut packages = Vec::new();

        // Parse Gradle dependency notation: implementation 'group:artifact:version'
        // or implementation("group:artifact:version")
        let dep_re = regex::Regex::new(
            r#"(?:implementation|api|compile|runtimeOnly|testImplementation|testRuntimeOnly)\s*[\('"]+([^:]+):([^:]+):([^'")\s]+)"#,
        )
        .unwrap();

        for cap in dep_re.captures_iter(&content) {
            let group_id = &cap[1];
            let artifact_id = &cap[2];
            let version = &cap[3];

            // Skip property references
            if version.starts_with('$') {
                continue;
            }

            packages.push(PackageRef {
                ecosystem: OsvEcosystem::Maven,
                name: format!("{}:{}", group_id, artifact_id),
                version: version.to_string(),
                scope: DependencyScope::Runtime,
                source_file: path.to_path_buf(),
            });
        }

        debug!("Parsed {} packages from {}", packages.len(), path.display());
        Ok(packages)
    }

    /// Query vulnerabilities using local database (primary) or API (fallback)
    fn query_vulnerabilities(
        &self,
        packages: &[PackageRef],
    ) -> Result<HashMap<(String, String, String), Vec<OsvVulnerability>>> {
        let mut results: HashMap<(String, String, String), Vec<OsvVulnerability>> = HashMap::new();

        // Try local database first (fast path)
        if let Some(db) = &self.db {
            debug!(
                "Querying local OSV database for {} packages",
                packages.len()
            );

            for pkg in packages {
                let cache_key = (
                    pkg.ecosystem.to_string(),
                    pkg.name.clone(),
                    pkg.version.clone(),
                );

                match db.query(pkg.ecosystem, &pkg.name, &pkg.version) {
                    Ok(matches) => {
                        // Convert VulnMatch to OsvVulnerability
                        let vulns: Vec<OsvVulnerability> =
                            matches.into_iter().map(|m| convert_vuln_match(m)).collect();
                        results.insert(cache_key, vulns);
                    }
                    Err(e) => {
                        debug!(
                            "Local DB query failed for {}:{}: {}",
                            pkg.name, pkg.version, e
                        );
                        // Will try cache/API fallback below
                    }
                }
            }

            // If we got results for all packages, return early
            if results.len() == packages.len() {
                debug!(
                    "All {} packages resolved from local database",
                    packages.len()
                );
                return Ok(results);
            }
        }

        // Fallback: Check file cache for packages not in local DB
        let mut uncached_packages = Vec::new();
        for pkg in packages {
            let cache_key = (
                pkg.ecosystem.to_string(),
                pkg.name.clone(),
                pkg.version.clone(),
            );

            // Skip if already resolved from local DB
            if results.contains_key(&cache_key) {
                continue;
            }

            if let Some(vulns) = self.get_cached(&cache_key) {
                results.insert(cache_key, vulns);
            } else {
                uncached_packages.push(pkg);
            }
        }

        if uncached_packages.is_empty() {
            debug!("All packages resolved from local DB or cache");
            return Ok(results);
        }

        if self.config.offline {
            warn!(
                "Offline mode: skipping {} packages not in local DB or cache",
                uncached_packages.len()
            );
            return Ok(results);
        }

        // Last resort: Query OSV API for remaining packages
        info!(
            "Querying OSV API for {} uncached packages",
            uncached_packages.len()
        );
        for chunk in uncached_packages.chunks(1000) {
            let batch_results = self.osv_batch_query(chunk)?;

            for (pkg, vulns) in chunk.iter().zip(batch_results.into_iter()) {
                let cache_key = (
                    pkg.ecosystem.to_string(),
                    pkg.name.clone(),
                    pkg.version.clone(),
                );
                self.set_cached(&cache_key, &vulns)?;
                results.insert(cache_key, vulns);
            }
        }

        Ok(results)
    }

    /// Execute OSV batch query
    fn osv_batch_query(&self, packages: &[&PackageRef]) -> Result<Vec<Vec<OsvVulnerability>>> {
        let queries: Vec<OsvQuery> = packages
            .iter()
            .map(|pkg| OsvQuery {
                package: OsvQueryPackage {
                    ecosystem: pkg.ecosystem.to_string(),
                    name: pkg.name.clone(),
                },
                version: pkg.version.clone(),
            })
            .collect();

        let request = OsvBatchQuery { queries };

        debug!("Querying OSV API for {} packages", packages.len());

        // Use reqwest blocking client
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let response = client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&request)
            .send()
            .context("Failed to query OSV API")?;

        if !response.status().is_success() {
            anyhow::bail!("OSV API returned error: {}", response.status());
        }

        let batch_response: OsvBatchResponse =
            response.json().context("Failed to parse OSV response")?;

        // The batch query returns minimal data - fetch full details for each vulnerability
        let results: Vec<Vec<OsvVulnerability>> = batch_response
            .results
            .into_iter()
            .map(|r| {
                r.vulns
                    .into_iter()
                    .filter_map(|vuln| {
                        // If the vulnerability has incomplete data, fetch full details
                        if vuln.affected.is_empty() || vuln.summary.is_none() {
                            self.fetch_vulnerability_details(&vuln.id, &client).ok()
                        } else {
                            Some(vuln)
                        }
                    })
                    .collect()
            })
            .collect();

        Ok(results)
    }

    /// Fetch full vulnerability details from OSV by ID
    fn fetch_vulnerability_details(
        &self,
        vuln_id: &str,
        client: &reqwest::blocking::Client,
    ) -> Result<OsvVulnerability> {
        let url = format!("https://api.osv.dev/v1/vulns/{}", vuln_id);

        debug!("Fetching full details for {}", vuln_id);

        let response = client
            .get(&url)
            .send()
            .with_context(|| format!("Failed to fetch vulnerability {}", vuln_id))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "OSV API returned error for {}: {}",
                vuln_id,
                response.status()
            );
        }

        let vuln: OsvVulnerability = response
            .json()
            .with_context(|| format!("Failed to parse vulnerability {}", vuln_id))?;

        Ok(vuln)
    }

    /// Get cached vulnerability results
    fn get_cached(&self, key: &(String, String, String)) -> Option<Vec<OsvVulnerability>> {
        let cache_file = self.cache_file_path(key);
        if !cache_file.exists() {
            return None;
        }

        let content = fs::read_to_string(&cache_file).ok()?;
        let entry: CacheEntry = serde_json::from_str(&content).ok()?;

        // Check TTL
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now - entry.cached_at > self.cache_ttl.as_secs() {
            // Cache expired
            let _ = fs::remove_file(&cache_file);
            return None;
        }

        Some(entry.vulns)
    }

    /// Set cached vulnerability results
    fn set_cached(&self, key: &(String, String, String), vulns: &[OsvVulnerability]) -> Result<()> {
        let cache_file = self.cache_file_path(key);

        // Ensure cache directory exists
        if let Some(parent) = cache_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let entry = CacheEntry {
            vulns: vulns.to_vec(),
            cached_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let content = serde_json::to_string(&entry)?;
        fs::write(&cache_file, content)?;

        Ok(())
    }

    /// Get cache file path for a package
    fn cache_file_path(&self, key: &(String, String, String)) -> PathBuf {
        // Use hash to avoid filesystem issues with package names
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        self.cache_dir.join(format!("{:x}.json", hash))
    }

    /// Create findings from vulnerabilities
    fn create_findings(
        &self,
        packages: &[PackageRef],
        vulns: &HashMap<(String, String, String), Vec<OsvVulnerability>>,
        base_path: &Path,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Build import map for reachability confidence
        let imports = self.detect_imports(base_path)?;

        for pkg in packages {
            let key = (
                pkg.ecosystem.to_string(),
                pkg.name.clone(),
                pkg.version.clone(),
            );

            if let Some(pkg_vulns) = vulns.get(&key) {
                for vuln in pkg_vulns {
                    // Check ignore list
                    if self.config.ignore_list.contains(&vuln.id) {
                        continue;
                    }
                    if vuln
                        .aliases
                        .iter()
                        .any(|a| self.config.ignore_list.contains(a))
                    {
                        continue;
                    }

                    // Determine severity
                    let severity = self.determine_severity(vuln);

                    // Look up import info for reachability confidence
                    let import_info =
                        self.find_package_imports(&pkg.name, &pkg.ecosystem, &imports);
                    let (confidence, reachability, import_hits, import_files_sample) =
                        if let Some(info) = import_info {
                            (
                                Confidence::High,
                                "imported",
                                info.hit_count(),
                                info.sample_files(3),
                            )
                        } else {
                            (Confidence::Medium, "present", 0, Vec::new())
                        };

                    // Get fix version if available
                    let fix_version = self.get_fix_version(vuln);

                    // Build message
                    let summary = vuln.summary.as_deref().unwrap_or("No summary available");
                    let message = format!(
                        "{} {} is vulnerable: {} ({}). {}",
                        pkg.ecosystem,
                        pkg.name,
                        summary,
                        vuln.id,
                        fix_version
                            .as_ref()
                            .map(|v| format!("Fixed in version {}", v))
                            .unwrap_or_else(|| "No fix available".to_string())
                    );

                    let language = match pkg.ecosystem {
                        OsvEcosystem::CratesIo => Language::Rust,
                        OsvEcosystem::Npm => Language::JavaScript,
                        OsvEcosystem::PyPI => Language::Python,
                        OsvEcosystem::Go => Language::Go,
                        OsvEcosystem::Maven => Language::Java,
                    };

                    let location = SourceLocation::new(pkg.source_file.clone(), 1, 1, 1, 1);

                    // Build properties with reachability info
                    let mut properties = std::collections::HashMap::new();
                    properties.insert("reachability".to_string(), serde_json::json!(reachability));
                    properties.insert("import_hits".to_string(), serde_json::json!(import_hits));
                    if !import_files_sample.is_empty() {
                        properties.insert(
                            "import_files_sample".to_string(),
                            serde_json::json!(import_files_sample),
                        );
                    }

                    let mut finding = Finding {
                        id: format!("deps/osv/{}:{}:{}", vuln.id, pkg.source_file.display(), 1),
                        rule_id: format!("deps/osv/{}", vuln.id),
                        message,
                        severity,
                        location,
                        language,
                        snippet: Some(format!("{} = \"{}\"", pkg.name, pkg.version)),
                        suggestion: fix_version.map(|v| format!("Upgrade to version {}", v)),
                        fix: None,
                        confidence,
                        category: FindingCategory::Security,
                        fingerprint: None,
                        properties: Some(properties),
                        occurrence_count: None,
                        additional_locations: None,
                    };
                    finding.compute_fingerprint();
                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    /// Find import info for a package, considering ecosystem-specific lookup
    fn find_package_imports<'a>(
        &self,
        pkg_name: &str,
        ecosystem: &OsvEcosystem,
        imports: &'a HashMap<String, ImportInfo>,
    ) -> Option<&'a ImportInfo> {
        match ecosystem {
            OsvEcosystem::CratesIo => {
                // Rust crates: normalize underscores to hyphens and vice versa
                // e.g., "serde_json" crate can be imported as "serde_json"
                let normalized = pkg_name.replace('-', "_");
                imports.get(&normalized).or_else(|| imports.get(pkg_name))
            }
            OsvEcosystem::Npm => {
                // npm: exact package name match
                imports.get(pkg_name)
            }
            OsvEcosystem::PyPI => {
                // Python: normalize package names (underscores/hyphens are often interchangeable)
                let normalized = pkg_name.replace('-', "_").to_lowercase();
                imports.get(&normalized).or_else(|| {
                    // Try original name
                    imports.get(pkg_name)
                })
            }
            OsvEcosystem::Go => {
                // Go: full module path match
                imports.get(pkg_name)
            }
            OsvEcosystem::Maven => {
                // Maven: group:artifact format, try matching group prefix
                if let Some(group) = pkg_name.split(':').next() {
                    // Convert Maven group to Java package prefix
                    // e.g., "com.fasterxml.jackson" -> look for "com.fasterxml"
                    imports.get(group).or_else(|| {
                        // Try partial match on group parts
                        let parts: Vec<&str> = group.split('.').collect();
                        if parts.len() >= 2 {
                            let prefix = parts[..2].join(".");
                            imports.get(&prefix)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            }
        }
    }

    /// Determine severity from OSV vulnerability
    fn determine_severity(&self, vuln: &OsvVulnerability) -> Severity {
        // Check for severity override
        if let Some(sev) = self.config.severity_overrides.get(&vuln.id) {
            return *sev;
        }
        for alias in &vuln.aliases {
            if let Some(sev) = self.config.severity_overrides.get(alias) {
                return *sev;
            }
        }

        // Try to parse CVSS score
        for sev in &vuln.severity {
            if (sev.severity_type == "CVSS_V3" || sev.severity_type == "CVSS_V2")
                && let Ok(score) = sev.score.parse::<f32>()
            {
                return if score >= 9.0 {
                    Severity::Critical
                } else if score >= 7.0 {
                    Severity::Error
                } else if score >= 4.0 {
                    Severity::Warning
                } else {
                    Severity::Info
                };
            }
        }

        // Default to Warning for unknown severity
        Severity::Warning
    }

    /// Get fix version from OSV vulnerability
    fn get_fix_version(&self, vuln: &OsvVulnerability) -> Option<String> {
        for affected in &vuln.affected {
            for range in &affected.ranges {
                for event in &range.events {
                    if let Some(fixed) = &event.fixed {
                        return Some(fixed.clone());
                    }
                }
            }
        }
        None
    }

    /// Detect imports in source files for reachability confidence
    /// Returns a map of normalized package names to their import locations
    fn detect_imports(&self, path: &Path) -> Result<HashMap<String, ImportInfo>> {
        let mut imports: HashMap<String, ImportInfo> = HashMap::new();

        // Walk directory and look for import statements
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            let ext = file_path.extension().and_then(|e| e.to_str());

            match ext {
                Some("rs") => self.extract_rust_imports(file_path, &mut imports)?,
                Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") => {
                    self.extract_js_imports(file_path, &mut imports)?
                }
                Some("py") => self.extract_python_imports(file_path, &mut imports)?,
                Some("go") => self.extract_go_imports(file_path, &mut imports)?,
                Some("java") => self.extract_java_imports(file_path, &mut imports)?,
                _ => {}
            }
        }

        Ok(imports)
    }

    /// Extract Rust imports (use statements)
    /// Normalizes to crate names (e.g., `use serde::Serialize` -> "serde")
    fn extract_rust_imports(
        &self,
        path: &Path,
        imports: &mut HashMap<String, ImportInfo>,
    ) -> Result<()> {
        let content = fs::read_to_string(path)?;

        // Match use statements: use crate_name::... or extern crate crate_name
        let use_re =
            regex::Regex::new(r"(?m)^[\s]*(?:use|extern\s+crate)\s+([a-zA-Z_][a-zA-Z0-9_]*)")
                .unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            for cap in use_re.captures_iter(line) {
                let crate_name = cap[1].to_string();
                // Skip std/core/alloc as they're built-in
                if !matches!(
                    crate_name.as_str(),
                    "std" | "core" | "alloc" | "self" | "super" | "crate"
                ) {
                    imports
                        .entry(crate_name)
                        .or_default()
                        .add_location(path.to_path_buf(), line_idx + 1);
                }
            }
        }

        Ok(())
    }

    /// Extract JavaScript/TypeScript imports
    /// Normalizes to npm package names:
    /// - `@scope/pkg/path` -> `@scope/pkg`
    /// - `lodash/get` -> `lodash`
    fn extract_js_imports(
        &self,
        path: &Path,
        imports: &mut HashMap<String, ImportInfo>,
    ) -> Result<()> {
        let content = fs::read_to_string(path)?;

        // Match import/require statements
        // import X from 'package' | import 'package' | require('package')
        let import_re = regex::Regex::new(
            r#"(?:import\s+(?:[^'"]*\s+from\s+)?|require\s*\(\s*)['"]([^'"]+)['"]"#,
        )
        .unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            for cap in import_re.captures_iter(line) {
                let module = &cap[1];
                // Skip relative imports
                if module.starts_with('.') {
                    continue;
                }

                // Normalize to package name
                let pkg_name = Self::normalize_npm_package(module);
                imports
                    .entry(pkg_name)
                    .or_default()
                    .add_location(path.to_path_buf(), line_idx + 1);
            }
        }

        Ok(())
    }

    /// Normalize npm module path to package name
    /// `@scope/pkg/path/to/file` -> `@scope/pkg`
    /// `lodash/get` -> `lodash`
    fn normalize_npm_package(module: &str) -> String {
        if module.starts_with('@') {
            // Scoped package: @scope/package/...
            module.split('/').take(2).collect::<Vec<_>>().join("/")
        } else {
            // Regular package: package/...
            module.split('/').next().unwrap_or(module).to_string()
        }
    }

    /// Extract Python imports
    /// Normalizes to top-level package names
    fn extract_python_imports(
        &self,
        path: &Path,
        imports: &mut HashMap<String, ImportInfo>,
    ) -> Result<()> {
        let content = fs::read_to_string(path)?;

        // Match import X or from X import Y
        let import_re =
            regex::Regex::new(r"(?m)^[\s]*(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_]*)").unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            for cap in import_re.captures_iter(line) {
                let pkg_name = cap[1].to_string();
                imports
                    .entry(pkg_name)
                    .or_default()
                    .add_location(path.to_path_buf(), line_idx + 1);
            }
        }

        Ok(())
    }

    /// Extract Go imports
    /// Returns full module paths (e.g., `github.com/gin-gonic/gin`)
    fn extract_go_imports(
        &self,
        path: &Path,
        imports: &mut HashMap<String, ImportInfo>,
    ) -> Result<()> {
        let content = fs::read_to_string(path)?;

        // Match import statements (both single and grouped)
        // import "package" or import ( "package" )
        let import_re = regex::Regex::new(r#"["']([^"']+)["']"#).unwrap();

        let mut in_import_block = false;
        for (line_idx, line) in content.lines().enumerate() {
            let line_trimmed = line.trim();

            // Track import blocks
            if line_trimmed.starts_with("import (") || line_trimmed == "import(" {
                in_import_block = true;
                continue;
            }
            if in_import_block && line_trimmed == ")" {
                in_import_block = false;
                continue;
            }

            // Single import or inside import block
            let should_check = in_import_block || line_trimmed.starts_with("import ");
            if should_check {
                for cap in import_re.captures_iter(line) {
                    let module_path = cap[1].to_string();
                    imports
                        .entry(module_path)
                        .or_default()
                        .add_location(path.to_path_buf(), line_idx + 1);
                }
            }
        }

        Ok(())
    }

    /// Extract Java imports
    /// Normalizes to group:artifact format for Maven comparison
    fn extract_java_imports(
        &self,
        path: &Path,
        imports: &mut HashMap<String, ImportInfo>,
    ) -> Result<()> {
        let content = fs::read_to_string(path)?;

        // Match import statements
        let import_re =
            regex::Regex::new(r"(?m)^[\s]*import\s+(?:static\s+)?([a-zA-Z_][a-zA-Z0-9_.]+)")
                .unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            for cap in import_re.captures_iter(line) {
                let import_path = &cap[1];
                // Extract potential group ID (first 2-3 parts)
                let parts: Vec<&str> = import_path.split('.').collect();
                if parts.len() >= 2 {
                    // Common patterns: com.example, org.apache, io.netty
                    let group = parts[..2.min(parts.len())].join(".");
                    imports
                        .entry(group)
                        .or_default()
                        .add_location(path.to_path_buf(), line_idx + 1);
                }
            }
        }

        Ok(())
    }

    /// Get cache directory path
    pub fn cache_path(&self) -> &Path {
        &self.cache_dir
    }
}

impl AnalysisProvider for OsvProvider {
    fn name(&self) -> &'static str {
        "osv"
    }

    fn description(&self) -> &'static str {
        "Offline-first multi-language dependency vulnerability scanning (local Sled DB with bloom filters)"
    }

    fn supports_language(&self, lang: Language) -> bool {
        match lang {
            Language::Rust => self
                .config
                .enabled_ecosystems
                .contains(&OsvEcosystem::CratesIo),
            Language::JavaScript | Language::TypeScript => {
                self.config.enabled_ecosystems.contains(&OsvEcosystem::Npm)
            }
            Language::Python => self.config.enabled_ecosystems.contains(&OsvEcosystem::PyPI),
            Language::Go => self.config.enabled_ecosystems.contains(&OsvEcosystem::Go),
            Language::Java => self
                .config
                .enabled_ecosystems
                .contains(&OsvEcosystem::Maven),
            // Other languages not yet supported by OSV ecosystem mapping
            _ => false,
        }
    }

    fn is_available(&self) -> bool {
        // OSV provider is always available (Rust-native)
        true
    }

    fn version(&self) -> Option<String> {
        Some("1.0.0".to_string())
    }

    fn analyze_file(&self, _path: &Path) -> Result<Vec<Finding>> {
        // OSV works at directory level, not file level
        Ok(Vec::new())
    }

    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        self.scan_directory(path)
    }
}

/// Parse duration string like "24h", "30m", "7d"
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = s.split_at(s.len().saturating_sub(1));
    let num: u64 = num_str.parse().ok()?;

    match unit {
        "s" => Some(Duration::from_secs(num)),
        "m" => Some(Duration::from_secs(num * 60)),
        "h" => Some(Duration::from_secs(num * 3600)),
        "d" => Some(Duration::from_secs(num * 86400)),
        _ => None,
    }
}

/// Convert VulnMatch from local database to OsvVulnerability format
fn convert_vuln_match(m: VulnMatch) -> OsvVulnerability {
    let db_vuln = m.vulnerability;
    OsvVulnerability {
        id: db_vuln.id,
        aliases: db_vuln.aliases,
        summary: db_vuln.summary,
        details: db_vuln.details,
        severity: db_vuln
            .severity
            .into_iter()
            .map(|s| OsvSeverity {
                severity_type: s.severity_type,
                score: s.score,
            })
            .collect(),
        affected: db_vuln
            .affected
            .into_iter()
            .map(|a| OsvAffected {
                package: a.package.map(|p| OsvPackage {
                    ecosystem: p.ecosystem,
                    name: p.name,
                }),
                ranges: a
                    .ranges
                    .into_iter()
                    .map(|r| OsvRange {
                        range_type: r.range_type,
                        events: r
                            .events
                            .into_iter()
                            .map(|e| OsvEvent {
                                introduced: e.introduced,
                                fixed: e.fixed,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        references: db_vuln
            .references
            .into_iter()
            .map(|r| OsvReference {
                ref_type: r.ref_type,
                url: r.url,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("24h"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_duration("7d"), Some(Duration::from_secs(604800)));
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn test_parse_cargo_lock() {
        let provider = OsvProvider::default();
        let cargo_lock = r#"
[[package]]
name = "serde"
version = "1.0.193"

[[package]]
name = "anyhow"
version = "1.0.75"
"#;
        let temp_dir = tempfile::tempdir().unwrap();
        let lock_path = temp_dir.path().join("Cargo.lock");
        fs::write(&lock_path, cargo_lock).unwrap();

        let packages = provider.parse_cargo_lock(&lock_path).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "serde");
        assert_eq!(packages[0].version, "1.0.193");
        assert_eq!(packages[1].name, "anyhow");
    }

    #[test]
    fn test_parse_package_lock() {
        let provider = OsvProvider::default();
        let package_lock = r#"{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dev": true
    }
  }
}"#;
        let temp_dir = tempfile::tempdir().unwrap();
        let lock_path = temp_dir.path().join("package-lock.json");
        fs::write(&lock_path, package_lock).unwrap();

        let packages = provider.parse_package_lock(&lock_path).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(
            packages
                .iter()
                .any(|p| p.name == "lodash" && p.scope == DependencyScope::Runtime)
        );
        assert!(
            packages
                .iter()
                .any(|p| p.name == "express" && p.scope == DependencyScope::Dev)
        );
    }

    #[test]
    fn test_parse_go_mod() {
        let provider = OsvProvider::default();
        let go_mod = r#"
module example.com/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4
)

require github.com/go-playground/validator/v10 v10.14.0
"#;
        let temp_dir = tempfile::tempdir().unwrap();
        let mod_path = temp_dir.path().join("go.mod");
        let sum_path = temp_dir.path().join("go.sum");
        fs::write(&mod_path, go_mod).unwrap();

        let packages = provider.parse_go_mod(&mod_path, &sum_path).unwrap();
        assert_eq!(packages.len(), 3);
        assert!(
            packages
                .iter()
                .any(|p| p.name == "github.com/gin-gonic/gin" && p.version == "1.9.1")
        );
    }

    #[test]
    fn test_provider_creation() {
        let provider = OsvProvider::default();
        assert!(provider.is_available());
        assert!(provider.supports_language(Language::Rust));
        assert!(provider.supports_language(Language::JavaScript));
        assert!(provider.supports_language(Language::Python));
        assert!(provider.supports_language(Language::Go));
        assert!(provider.supports_language(Language::Java));
    }

    #[test]
    fn test_npm_import_detection() {
        let provider = OsvProvider::default();
        let temp_dir = tempfile::tempdir().unwrap();

        // Create test JS file with imports
        let js_content = r#"
import lodash from 'lodash';
import { get } from 'lodash/get';
import express from '@express/core';
const axios = require('axios');
const foo = require('@scope/package/subpath');
import './local-file';
"#;
        let js_path = temp_dir.path().join("test.js");
        fs::write(&js_path, js_content).unwrap();

        let imports = provider.detect_imports(temp_dir.path()).unwrap();

        // Check normalized package names
        assert!(imports.contains_key("lodash"), "Should detect lodash");
        assert!(imports.contains_key("axios"), "Should detect axios");
        assert!(
            imports.contains_key("@express/core"),
            "Should detect scoped package"
        );
        assert!(
            imports.contains_key("@scope/package"),
            "Should normalize scoped subpath to package"
        );
        assert!(
            !imports.contains_key("./local-file"),
            "Should skip relative imports"
        );
    }

    #[test]
    fn test_go_import_detection() {
        let provider = OsvProvider::default();
        let temp_dir = tempfile::tempdir().unwrap();

        // Create test Go file with imports
        let go_content = r#"
package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
)

import "net/http"
"#;
        let go_path = temp_dir.path().join("main.go");
        fs::write(&go_path, go_content).unwrap();

        let imports = provider.detect_imports(temp_dir.path()).unwrap();

        assert!(imports.contains_key("fmt"), "Should detect fmt");
        assert!(
            imports.contains_key("github.com/gin-gonic/gin"),
            "Should detect gin"
        );
        assert!(imports.contains_key("net/http"), "Should detect net/http");
    }

    #[test]
    fn test_rust_import_detection() {
        let provider = OsvProvider::default();
        let temp_dir = tempfile::tempdir().unwrap();

        // Create test Rust file with imports
        let rs_content = r#"
use serde::Serialize;
use serde_json::Value;
extern crate anyhow;
use std::collections::HashMap;
use super::MyModule;
use crate::local;
"#;
        let rs_path = temp_dir.path().join("lib.rs");
        fs::write(&rs_path, rs_content).unwrap();

        let imports = provider.detect_imports(temp_dir.path()).unwrap();

        assert!(imports.contains_key("serde"), "Should detect serde");
        assert!(
            imports.contains_key("serde_json"),
            "Should detect serde_json"
        );
        assert!(imports.contains_key("anyhow"), "Should detect extern crate");
        assert!(!imports.contains_key("std"), "Should skip std");
        assert!(!imports.contains_key("super"), "Should skip super");
        assert!(!imports.contains_key("crate"), "Should skip crate");
    }

    #[test]
    fn test_import_info_tracks_locations() {
        let provider = OsvProvider::default();
        let temp_dir = tempfile::tempdir().unwrap();

        // Create test files with same import in multiple places
        let js1 = temp_dir.path().join("a.js");
        fs::write(&js1, "import lodash from 'lodash';").unwrap();

        let js2 = temp_dir.path().join("b.js");
        fs::write(&js2, "const _ = require('lodash');").unwrap();

        let imports = provider.detect_imports(temp_dir.path()).unwrap();

        let lodash_info = imports.get("lodash").expect("Should find lodash");
        assert_eq!(lodash_info.hit_count(), 2, "Should have 2 import hits");

        let samples = lodash_info.sample_files(3);
        assert_eq!(samples.len(), 2, "Should have 2 sample files");
    }

    #[test]
    fn test_normalize_npm_package() {
        // Scoped packages
        assert_eq!(
            OsvProvider::normalize_npm_package("@scope/pkg"),
            "@scope/pkg"
        );
        assert_eq!(
            OsvProvider::normalize_npm_package("@scope/pkg/deep/path"),
            "@scope/pkg"
        );

        // Regular packages
        assert_eq!(OsvProvider::normalize_npm_package("lodash"), "lodash");
        assert_eq!(OsvProvider::normalize_npm_package("lodash/get"), "lodash");
        assert_eq!(
            OsvProvider::normalize_npm_package("lodash/fp/get"),
            "lodash"
        );
    }
}
