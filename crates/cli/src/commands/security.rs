//! Security command - comprehensive multi-language security audit
//!
//! Scans:
//! - Dependency vulnerabilities (Rust, JS/TS, Python, Go, Java)
//! - Docker images and base image vulnerabilities
//! - docker-compose.yml security misconfigurations
//! - Dockerfile security issues
//! - Code security patterns
//!
//! Shows CVE → Fix mappings for all vulnerabilities

use anyhow::Result;
use colored::Colorize;
use rma_analyzer::providers::{AnalysisProvider, OsvProvider, RustSecProvider};
use rma_common::{
    DEFAULT_EXAMPLE_IGNORE_PATHS, DEFAULT_TEST_IGNORE_PATHS, DEFAULT_VENDOR_IGNORE_PATHS, Finding,
    OsvEcosystem, OsvProviderConfig, RmaConfig, Severity,
};
use rma_parser::ParserEngine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::str::FromStr for FailSeverity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityArgs {
    pub path: PathBuf,
    pub format: OutputFormat,
    #[allow(dead_code)]
    pub severity: Severity,
    pub details: bool,
    pub fix: bool,
    pub offline: bool,
    pub skip_docker: bool,
    pub skip_deps: bool,
    pub skip_code: bool,
    /// Fail on vulnerabilities at or above this severity
    pub fail_on: FailSeverity,
    /// Include test files in code security scanning
    pub include_tests: bool,
}

impl Default for SecurityArgs {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            format: OutputFormat::Pretty,
            severity: Severity::Warning,
            details: false,
            fix: false,
            offline: false,
            skip_docker: false,
            skip_deps: false,
            skip_code: false,
            fail_on: FailSeverity::High, // Default: fail on critical or high
            include_tests: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Pretty,
    Json,
    Sarif,
    Markdown,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" | "text" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "markdown" | "md" => Ok(Self::Markdown),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

/// A vulnerability with full CVE details and fix information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// CVE ID (e.g., CVE-2024-1234) or advisory ID (RUSTSEC-2024-0001, GHSA-xxxx)
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: String,
    /// CVSS score if available
    pub cvss_score: Option<f32>,
    /// Affected package name
    pub package: String,
    /// Installed/affected version
    pub installed_version: String,
    /// Versions that fix this vulnerability
    pub fixed_versions: Vec<String>,
    /// Recommended fix action
    pub fix_command: Option<String>,
    /// Ecosystem (crates.io, npm, PyPI, Go, Maven, Docker)
    pub ecosystem: String,
    /// Source file where found (Cargo.lock, package-lock.json, Dockerfile, etc.)
    pub source_file: String,
    /// Related CVE IDs
    pub cve_ids: Vec<String>,
    /// Related GHSA IDs
    pub ghsa_ids: Vec<String>,
    /// Reference URLs
    pub references: Vec<String>,
    /// Published date
    pub published: Option<String>,
    /// Is this vulnerability in a direct or transitive dependency
    pub is_direct: bool,
}

/// Grouped vulnerability for display (deduplication)
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields reserved for future output formats
pub struct GroupedVulnerability {
    /// All advisory IDs (GHSA, RUSTSEC, CVE, etc.)
    pub ids: Vec<String>,
    /// Best title (longest/most descriptive)
    pub title: String,
    /// Best description
    pub description: String,
    /// Highest severity among grouped vulns
    pub severity: String,
    /// Package name
    pub package: String,
    /// Installed version
    pub installed_version: String,
    /// Fixed version (if any)
    pub fixed_version: Option<String>,
    /// Fix command
    pub fix_command: Option<String>,
    /// Ecosystem
    pub ecosystem: String,
    /// Source file
    pub source_file: String,
    /// All CVE IDs
    pub cve_ids: Vec<String>,
    /// All GHSA IDs
    pub ghsa_ids: Vec<String>,
    /// All references
    pub references: Vec<String>,
}

/// Docker-specific security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerFinding {
    pub file: String,
    pub line: usize,
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub fix: Option<String>,
}

/// Complete security audit report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub scan_time: String,
    pub project_path: String,
    pub summary: SecuritySummary,
    pub vulnerabilities: Vec<Vulnerability>,
    pub docker_findings: Vec<DockerFinding>,
    pub ecosystems: HashMap<String, EcosystemReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecuritySummary {
    pub total_vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub fixable: usize,
    pub docker_issues: usize,
    pub ecosystems_scanned: Vec<String>,
    pub lockfiles_found: Vec<String>,
    pub dockerfiles_found: Vec<String>,
    /// Number of unique packages affected (after dedup)
    pub unique_packages: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EcosystemReport {
    pub name: String,
    pub lockfile: String,
    pub total_deps: usize,
    pub vulnerable_deps: usize,
    pub vulnerabilities: Vec<String>, // IDs
}

pub fn run(args: SecurityArgs) -> Result<()> {
    let start = std::time::Instant::now();

    // Header
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║           🔒 RMA Security Audit                                   ║".cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════╝".cyan()
    );
    println!();

    let mut report = SecurityReport {
        scan_time: chrono::Utc::now().to_rfc3339(),
        project_path: args.path.display().to_string(),
        summary: SecuritySummary::default(),
        vulnerabilities: Vec::new(),
        docker_findings: Vec::new(),
        ecosystems: HashMap::new(),
    };

    // 1. Discover all lockfiles and Dockerfiles
    println!("{} Discovering project files...", "→".bright_blue());
    let discovery = discover_files(&args.path)?;

    report.summary.lockfiles_found = discovery
        .lockfiles
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    report.summary.dockerfiles_found = discovery
        .dockerfiles
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    println!(
        "  Found {} lockfiles, {} Dockerfiles",
        discovery.lockfiles.len().to_string().bright_white(),
        discovery.dockerfiles.len().to_string().bright_white()
    );
    println!();

    // 2. Scan dependencies
    if !args.skip_deps {
        println!("{} Scanning dependencies for CVEs...", "→".bright_blue());
        scan_all_dependencies(&args, &discovery, &mut report)?;
        println!();
    }

    // 3. Scan Docker files
    if !args.skip_docker && !discovery.dockerfiles.is_empty() {
        println!("{} Scanning Docker configurations...", "→".bright_blue());
        scan_docker_files(&args, &discovery, &mut report)?;
        println!();
    }

    // 4. Scan code for security issues
    if !args.skip_code {
        println!("{} Scanning code for security issues...", "→".bright_blue());
        scan_code_security(&args, &mut report)?;
        println!();
    }

    // Group/deduplicate vulnerabilities for display
    let grouped = deduplicate_vulnerabilities(&report.vulnerabilities);

    // Calculate summary from grouped (deduplicated) vulnerabilities
    let mut summary = SecuritySummary::default();
    for gv in &grouped {
        match gv.severity.as_str() {
            "critical" => summary.critical += 1,
            "high" => summary.high += 1,
            "medium" => summary.medium += 1,
            "low" => summary.low += 1,
            _ => {}
        }
        if gv.fixed_version.is_some() || gv.fix_command.is_some() {
            summary.fixable += 1;
        }
    }
    summary.total_vulnerabilities = grouped.len();
    summary.unique_packages = grouped
        .iter()
        .map(|g| (&g.ecosystem, &g.package))
        .collect::<HashSet<_>>()
        .len();
    summary.docker_issues = report.docker_findings.len();
    summary.ecosystems_scanned = report.ecosystems.keys().cloned().collect();
    summary.lockfiles_found = report.summary.lockfiles_found.clone();
    summary.dockerfiles_found = report.summary.dockerfiles_found.clone();
    report.summary = summary;

    let duration = start.elapsed();

    // Output
    match args.format {
        OutputFormat::Json => output_json(&report)?,
        OutputFormat::Sarif => output_sarif(&report)?,
        OutputFormat::Markdown => output_markdown(&report)?,
        OutputFormat::Pretty => output_pretty_grouped(&grouped, &report, &args, duration)?,
    }

    // Show fix commands if requested
    if args.fix {
        show_fix_commands_deduped(&grouped)?;
    }

    // Exit code based on fail_on policy
    let exit_code = determine_exit_code(&report.summary, args.fail_on);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Determine exit code based on fail_on policy
fn determine_exit_code(summary: &SecuritySummary, fail_on: FailSeverity) -> i32 {
    match fail_on {
        FailSeverity::None => 0,
        FailSeverity::Low => {
            if summary.critical > 0 || summary.high > 0 || summary.medium > 0 || summary.low > 0 {
                1
            } else {
                0
            }
        }
        FailSeverity::Medium => {
            if summary.critical > 0 || summary.high > 0 || summary.medium > 0 {
                1
            } else {
                0
            }
        }
        FailSeverity::High => {
            if summary.critical > 0 || summary.high > 0 {
                1
            } else {
                0
            }
        }
        FailSeverity::Critical => {
            if summary.critical > 0 {
                1
            } else {
                0
            }
        }
    }
}

/// Deduplicate vulnerabilities by grouping same package@version with same fix
pub fn deduplicate_vulnerabilities(vulns: &[Vulnerability]) -> Vec<GroupedVulnerability> {
    // Group by (ecosystem, package, installed_version, fixed_version)
    let mut groups: HashMap<(String, String, String, Option<String>), Vec<&Vulnerability>> =
        HashMap::new();

    for vuln in vulns {
        let fixed = vuln.fixed_versions.first().cloned();
        let key = (
            vuln.ecosystem.clone(),
            vuln.package.clone(),
            vuln.installed_version.clone(),
            fixed,
        );
        groups.entry(key).or_default().push(vuln);
    }

    let mut result: Vec<GroupedVulnerability> = groups
        .into_iter()
        .map(|(key, vulns)| {
            let (ecosystem, package, installed_version, fixed_version) = key;

            // Collect all IDs
            let ids: Vec<String> = vulns.iter().map(|v| v.id.clone()).collect();

            // Pick best title (prefer longer GHSA summaries)
            let title = vulns
                .iter()
                .filter(|v| v.id.starts_with("GHSA-") && v.title.len() > 20)
                .max_by_key(|v| v.title.len())
                .map(|v| v.title.clone())
                .unwrap_or_else(|| {
                    vulns
                        .iter()
                        .max_by_key(|v| v.title.len())
                        .map(|v| v.title.clone())
                        .unwrap_or_default()
                });

            // Pick best description
            let description = vulns
                .iter()
                .max_by_key(|v| v.description.len())
                .map(|v| v.description.clone())
                .unwrap_or_default();

            // Highest severity
            let severity = vulns
                .iter()
                .map(|v| severity_rank(&v.severity))
                .max()
                .map(rank_to_severity)
                .unwrap_or_else(|| "medium".to_string());

            // Collect all CVE/GHSA IDs
            let cve_ids: Vec<String> = vulns
                .iter()
                .flat_map(|v| v.cve_ids.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            let ghsa_ids: Vec<String> = vulns
                .iter()
                .flat_map(|v| v.ghsa_ids.iter().cloned())
                .chain(
                    vulns
                        .iter()
                        .filter(|v| v.id.starts_with("GHSA-"))
                        .map(|v| v.id.clone()),
                )
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            // Collect references
            let references: Vec<String> = vulns
                .iter()
                .flat_map(|v| v.references.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            let fix_command = vulns.first().and_then(|v| v.fix_command.clone());
            let source_file = vulns
                .first()
                .map(|v| v.source_file.clone())
                .unwrap_or_default();

            GroupedVulnerability {
                ids,
                title,
                description,
                severity,
                package,
                installed_version,
                fixed_version,
                fix_command,
                ecosystem,
                source_file,
                cve_ids,
                ghsa_ids,
                references,
            }
        })
        .collect();

    // Sort by severity (critical first), then by package name
    result.sort_by(|a, b| {
        let sev_cmp = severity_rank(&b.severity).cmp(&severity_rank(&a.severity));
        if sev_cmp != std::cmp::Ordering::Equal {
            return sev_cmp;
        }
        a.package.cmp(&b.package)
    });

    result
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn rank_to_severity(r: u8) -> String {
    match r {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "unknown",
    }
    .to_string()
}

/// Check if a path matches any of the default exclude patterns
fn matches_exclude_pattern(path: &Path, patterns: &[&str]) -> bool {
    let path_str = path.to_string_lossy();

    for pattern in patterns {
        // Simple glob matching for common patterns
        if pattern.starts_with("**/") && pattern.ends_with("/**") {
            // e.g., "**/tests/**"
            let inner = &pattern[3..pattern.len() - 3];
            if path_str.contains(&format!("/{}/", inner))
                || path_str.contains(&format!("\\{}\\", inner))
                || path_str.ends_with(&format!("/{}", inner))
            {
                return true;
            }
        } else if let Some(suffix) = pattern.strip_prefix("**/") {
            // e.g., "**/*.test.*"
            if suffix.contains('*') {
                // Handle wildcards like "*.test.*"
                let parts: Vec<&str> = suffix.split('*').collect();
                if parts.len() >= 2 {
                    let check = parts
                        .iter()
                        .all(|part| part.is_empty() || path_str.contains(part));
                    if check && !parts[0].is_empty() && path_str.contains(parts[0]) {
                        return true;
                    }
                }
            } else if path_str.ends_with(suffix) || path_str.contains(&format!("/{}", suffix)) {
                return true;
            }
        }

        // Direct contains check for patterns like "**/test/**"
        if pattern.contains("tests") && path_str.contains("tests") {
            return true;
        }
        if pattern.contains("test/") && path_str.contains("test/") {
            return true;
        }
        if pattern.contains("fixtures") && path_str.contains("fixtures") {
            return true;
        }
        if pattern.contains("__tests__") && path_str.contains("__tests__") {
            return true;
        }
        if pattern.contains(".test.") && path_str.contains(".test.") {
            return true;
        }
        if pattern.contains(".spec.") && path_str.contains(".spec.") {
            return true;
        }
        if pattern.contains("_test.") && path_str.contains("_test.") {
            return true;
        }
        if pattern.contains("testdata") && path_str.contains("testdata") {
            return true;
        }
    }

    false
}

struct ProjectDiscovery {
    lockfiles: Vec<PathBuf>,
    dockerfiles: Vec<PathBuf>,
    compose_files: Vec<PathBuf>,
}

fn discover_files(root: &Path) -> Result<ProjectDiscovery> {
    let mut discovery = ProjectDiscovery {
        lockfiles: Vec::new(),
        dockerfiles: Vec::new(),
        compose_files: Vec::new(),
    };

    // Known lockfile names
    let lockfile_names = [
        "Cargo.lock",        // Rust
        "package-lock.json", // npm
        "yarn.lock",         // Yarn
        "pnpm-lock.yaml",    // pnpm
        "go.sum",            // Go
        "go.mod",            // Go
        "requirements.txt",  // Python pip
        "Pipfile.lock",      // Python pipenv
        "poetry.lock",       // Python poetry
        "pom.xml",           // Maven
        "build.gradle",      // Gradle
        "build.gradle.kts",  // Gradle Kotlin
        "Gemfile.lock",      // Ruby
        "composer.lock",     // PHP
    ];

    let dockerfile_patterns = ["Dockerfile", "dockerfile", "Containerfile"];

    let compose_patterns = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ];

    // Walk directory
    for entry in walkdir::WalkDir::new(root)
        .max_depth(10)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Skip common non-project directories
            !matches!(
                name.as_ref(),
                "node_modules" | ".git" | "target" | "vendor" | ".venv" | "__pycache__"
            )
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Check lockfiles
        if lockfile_names.contains(&name.as_str()) {
            discovery.lockfiles.push(path.to_path_buf());
        }

        // Check Dockerfiles (including Dockerfile.prod, Dockerfile.dev, etc.)
        if dockerfile_patterns.iter().any(|p| name.starts_with(p)) || name.ends_with(".dockerfile")
        {
            discovery.dockerfiles.push(path.to_path_buf());
        }

        // Check compose files
        if compose_patterns.contains(&name.as_str()) {
            discovery.compose_files.push(path.to_path_buf());
        }
    }

    // Also add compose files to dockerfiles for scanning
    discovery
        .dockerfiles
        .extend(discovery.compose_files.clone());

    Ok(discovery)
}

fn scan_all_dependencies(
    args: &SecurityArgs,
    discovery: &ProjectDiscovery,
    report: &mut SecurityReport,
) -> Result<()> {
    // Use OSV as the universal backend for all ecosystems
    let osv_config = OsvProviderConfig {
        offline: args.offline,
        include_dev_deps: true,
        enabled_ecosystems: vec![
            OsvEcosystem::CratesIo,
            OsvEcosystem::Npm,
            OsvEcosystem::PyPI,
            OsvEcosystem::Go,
            OsvEcosystem::Maven,
        ],
        ..Default::default()
    };

    let osv_provider = OsvProvider::new(osv_config);

    // RustSec as a "booster" for Rust crates - provides better fix version info
    let rustsec_provider = RustSecProvider::new();
    let use_rustsec = rustsec_provider.is_available();

    // Group lockfiles by directory to batch scan
    let mut dirs_scanned: HashMap<PathBuf, bool> = HashMap::new();

    for lockfile in &discovery.lockfiles {
        let name = lockfile
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let ecosystem = match name.as_str() {
            "Cargo.lock" => "crates.io",
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => "npm",
            "go.sum" | "go.mod" => "Go",
            "requirements.txt" | "Pipfile.lock" | "poetry.lock" => "PyPI",
            "pom.xml" | "build.gradle" | "build.gradle.kts" => "Maven",
            "Gemfile.lock" => "RubyGems",
            "composer.lock" => "Packagist",
            _ => continue,
        };

        // Skip unsupported ecosystems for now
        if ecosystem == "RubyGems" || ecosystem == "Packagist" {
            println!(
                "  {} {} ({}) - skipped (not yet supported)",
                "•".dimmed(),
                lockfile.display(),
                ecosystem.yellow()
            );
            continue;
        }

        println!(
            "  {} {} ({})",
            "•".dimmed(),
            lockfile.display(),
            ecosystem.cyan()
        );

        // Get the directory containing the lockfile
        let dir = lockfile.parent().unwrap_or(Path::new("."));

        // Check if we've already scanned this directory
        if dirs_scanned.contains_key(dir) {
            println!("    {} Already scanned", "ℹ".blue());
            continue;
        }
        dirs_scanned.insert(dir.to_path_buf(), true);

        // Use OSV as the universal backend (aggregates RustSec, GHSA, PyPA, etc.)
        let findings = osv_provider.analyze_directory(dir)?;
        let mut vulns = convert_osv_findings_to_vulns(&findings, lockfile, ecosystem);

        // For Rust crates, optionally use RustSec as a booster if OSV is missing data
        if ecosystem == "crates.io"
            && use_rustsec
            && vulns.iter().any(|v| v.fixed_versions.is_empty())
        {
            // Try RustSec for vulnerabilities missing fix info
            if let Ok(rustsec_findings) = rustsec_provider.analyze_directory(dir) {
                let rustsec_vulns = convert_rustsec_findings_to_vulns(&rustsec_findings, lockfile);
                // Merge RustSec fix info into OSV results
                for vuln in &mut vulns {
                    if vuln.fixed_versions.is_empty()
                        && let Some(rs_vuln) =
                            rustsec_vulns.iter().find(|v| v.package == vuln.package)
                    {
                        vuln.fixed_versions = rs_vuln.fixed_versions.clone();
                    }
                }
            }
        }

        // Add to ecosystem report
        let eco_report = report
            .ecosystems
            .entry(ecosystem.to_string())
            .or_insert_with(|| EcosystemReport {
                name: ecosystem.to_string(),
                lockfile: lockfile.display().to_string(),
                ..Default::default()
            });

        for vuln in &vulns {
            eco_report.vulnerabilities.push(vuln.id.clone());
            eco_report.vulnerable_deps += 1;
        }

        if !vulns.is_empty() {
            println!("    {} {} vulnerabilities found", "⚠".yellow(), vulns.len());
        } else {
            println!("    {} No vulnerabilities", "✓".green());
        }

        report.vulnerabilities.extend(vulns);
    }

    Ok(())
}

/// Convert RustSec findings to our Vulnerability format (has better fix version info)
fn convert_rustsec_findings_to_vulns(findings: &[Finding], lockfile: &Path) -> Vec<Vulnerability> {
    findings
        .iter()
        .map(|f| {
            // RustSec format: "package vX.Y.Z: title (RUSTSEC-XXXX-XXXX)"
            let (pkg, ver) = parse_pkg_version(&f.message);
            let advisory_id = extract_id(&f.rule_id);

            // RustSec includes "Patched in: >= X.Y.Z" in suggestion
            let fixed_versions = extract_versions(&f.suggestion);

            // Extract title from message
            let title = if let Some(idx) = f.message.find(':') {
                f.message[idx + 1..]
                    .trim()
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string()
            } else {
                f.message.clone()
            };

            Vulnerability {
                id: advisory_id.clone(),
                title: if title.is_empty() {
                    format!("crates.io {} - {}", pkg, advisory_id)
                } else {
                    title
                },
                description: f.suggestion.clone().unwrap_or_default(),
                severity: severity_to_string(f.severity),
                cvss_score: None,
                package: pkg,
                installed_version: ver,
                fixed_versions,
                fix_command: Some("cargo update".to_string()),
                ecosystem: "crates.io".to_string(),
                source_file: lockfile.display().to_string(),
                cve_ids: extract_cves(&f.message),
                ghsa_ids: extract_ghsas(&f.message),
                references: extract_urls(&f.suggestion),
                published: None,
                is_direct: false,
            }
        })
        .collect()
}

/// Convert OSV findings to our Vulnerability format
fn convert_osv_findings_to_vulns(
    findings: &[Finding],
    lockfile: &Path,
    ecosystem: &str,
) -> Vec<Vulnerability> {
    findings
        .iter()
        .map(|f| {
            // Extract package name and version from snippet (format: "package = \"version\"")
            let (pkg, ver) = if let Some(ref snippet) = f.snippet {
                parse_pkg_from_snippet(snippet)
            } else {
                parse_pkg_version(&f.message)
            };

            let advisory_id = extract_id(&f.rule_id);

            // Extract fix version from suggestion
            let fixed_versions = extract_versions(&f.suggestion);

            // Extract summary from message (after "is vulnerable:")
            let title = if let Some(idx) = f.message.find("is vulnerable:") {
                let rest = &f.message[idx + 14..].trim();
                // Get up to the advisory ID
                if let Some(paren_idx) = rest.rfind('(') {
                    rest[..paren_idx].trim().to_string()
                } else {
                    rest.to_string()
                }
            } else {
                f.message.clone()
            };

            Vulnerability {
                id: advisory_id.clone(),
                title: if title.is_empty() || title == "No summary available" {
                    format!("{} {} - {}", ecosystem, pkg, advisory_id)
                } else {
                    title
                },
                description: f.suggestion.clone().unwrap_or_default(),
                severity: severity_to_string(f.severity),
                cvss_score: None,
                package: pkg,
                installed_version: ver,
                fixed_versions,
                fix_command: get_fix_command(ecosystem),
                ecosystem: ecosystem.to_string(),
                source_file: lockfile.display().to_string(),
                cve_ids: extract_cves(&f.message)
                    .into_iter()
                    .chain(extract_cves(&advisory_id))
                    .collect(),
                ghsa_ids: extract_ghsas(&f.message)
                    .into_iter()
                    .chain(extract_ghsas(&advisory_id))
                    .collect(),
                references: extract_urls(&f.suggestion),
                published: None,
                is_direct: false,
            }
        })
        .collect()
}

/// Parse package name and version from snippet (format: "package = \"version\"")
fn parse_pkg_from_snippet(snippet: &str) -> (String, String) {
    // Format: package_name = "version"
    if let Ok(re) = regex::Regex::new(r#"^([^\s=]+)\s*=\s*"([^"]+)"#)
        && let Some(caps) = re.captures(snippet)
    {
        return (
            caps.get(1).map_or("unknown", |m| m.as_str()).to_string(),
            caps.get(2).map_or("unknown", |m| m.as_str()).to_string(),
        );
    }
    ("unknown".to_string(), "unknown".to_string())
}

fn scan_docker_files(
    _args: &SecurityArgs,
    discovery: &ProjectDiscovery,
    report: &mut SecurityReport,
) -> Result<()> {
    for dockerfile in &discovery.dockerfiles {
        let content = fs::read_to_string(dockerfile)?;
        let name = dockerfile
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        println!("  {} {}", "•".dimmed(), dockerfile.display());

        let mut findings = Vec::new();

        // Check if it's a compose file
        if name.contains("compose") {
            findings.extend(scan_compose_file(dockerfile, &content)?);
        } else {
            findings.extend(scan_dockerfile(dockerfile, &content)?);
        }

        if !findings.is_empty() {
            println!("    {} {} security issues", "⚠".yellow(), findings.len());
        } else {
            println!("    {} No issues", "✓".green());
        }

        report.docker_findings.extend(findings);
    }

    Ok(())
}

fn scan_dockerfile(path: &Path, content: &str) -> Result<Vec<DockerFinding>> {
    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1;
        let line_lower = line.to_lowercase();
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        // Check for root user
        if trimmed.starts_with("USER") && trimmed.contains("root") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/root-user".to_string(),
                severity: "high".to_string(),
                message: "Container runs as root user".to_string(),
                fix: Some(
                    "Add 'USER nonroot' or 'USER 1000' after installing packages".to_string(),
                ),
            });
        }

        // Check for latest tag
        if (line_lower.starts_with("from ") && line_lower.contains(":latest"))
            || (line_lower.starts_with("from ") && !line.contains(':') && !line.contains(" AS "))
        {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/latest-tag".to_string(),
                severity: "medium".to_string(),
                message: "Using 'latest' or untagged image - pins to unpredictable version"
                    .to_string(),
                fix: Some("Use specific image tag like 'image:1.2.3' or digest".to_string()),
            });
        }

        // Check for ADD instead of COPY
        if trimmed.starts_with("ADD ") && !line.contains("http://") && !line.contains("https://") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/prefer-copy".to_string(),
                severity: "low".to_string(),
                message: "Use COPY instead of ADD for local files".to_string(),
                fix: Some("Replace 'ADD' with 'COPY' for local file copies".to_string()),
            });
        }

        // Check for curl/wget without verification
        if (line_lower.contains("curl ") || line_lower.contains("wget "))
            && (line_lower.contains("-k")
                || line_lower.contains("--insecure")
                || line_lower.contains("--no-check-certificate"))
        {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/insecure-download".to_string(),
                severity: "high".to_string(),
                message: "Downloading files without TLS verification".to_string(),
                fix: Some("Remove --insecure/-k/--no-check-certificate flags".to_string()),
            });
        }

        // Check for secrets in ENV
        if trimmed.starts_with("ENV ") || trimmed.starts_with("ARG ") {
            let secrets = [
                "password",
                "secret",
                "key",
                "token",
                "api_key",
                "apikey",
                "credential",
                "private",
            ];
            for secret in secrets {
                if line_lower.contains(secret) && line.contains('=') && !line.contains("${") {
                    findings.push(DockerFinding {
                        file: path.display().to_string(),
                        line: line_num,
                        rule: "docker/hardcoded-secret".to_string(),
                        severity: "critical".to_string(),
                        message: format!("Potential hardcoded {} in Dockerfile", secret),
                        fix: Some(
                            "Use build args or runtime environment variables instead".to_string(),
                        ),
                    });
                    break;
                }
            }
        }

        // Check for privileged operations
        if line_lower.contains("--privileged") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/privileged-mode".to_string(),
                severity: "critical".to_string(),
                message: "Container requests privileged mode".to_string(),
                fix: Some("Avoid --privileged; use specific capabilities instead".to_string()),
            });
        }

        // Check for sudo usage
        if line_lower.contains("sudo ") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/sudo-usage".to_string(),
                severity: "medium".to_string(),
                message: "Using sudo in Dockerfile (already running as root during build)"
                    .to_string(),
                fix: Some("Remove sudo from RUN commands".to_string()),
            });
        }

        // Check for apt-get without cleanup
        if line_lower.contains("apt-get install")
            && !line.contains("rm -rf /var/lib/apt")
            && !line.contains("&&")
        {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/apt-cache".to_string(),
                severity: "low".to_string(),
                message: "apt-get install without cache cleanup bloats image".to_string(),
                fix: Some("Add '&& rm -rf /var/lib/apt/lists/*' after apt-get install".to_string()),
            });
        }

        // Check for EXPOSE with all interfaces
        if trimmed.starts_with("EXPOSE") && content.contains("0.0.0.0") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "docker/expose-all".to_string(),
                severity: "medium".to_string(),
                message: "Service binds to all interfaces (0.0.0.0)".to_string(),
                fix: Some("Consider binding to specific interface or localhost".to_string()),
            });
        }
    }

    // Check for missing HEALTHCHECK (at file level)
    if !content.to_lowercase().contains("healthcheck") {
        findings.push(DockerFinding {
            file: path.display().to_string(),
            line: 1,
            rule: "docker/no-healthcheck".to_string(),
            severity: "low".to_string(),
            message: "Dockerfile has no HEALTHCHECK instruction".to_string(),
            fix: Some("Add HEALTHCHECK to enable container health monitoring".to_string()),
        });
    }

    // Check for missing USER instruction
    if !content.to_lowercase().contains("\nuser ") && !content.to_lowercase().starts_with("user ") {
        findings.push(DockerFinding {
            file: path.display().to_string(),
            line: 1,
            rule: "docker/no-user".to_string(),
            severity: "high".to_string(),
            message: "Dockerfile has no USER instruction - runs as root".to_string(),
            fix: Some("Add 'USER nonroot' or 'USER 1000:1000' before ENTRYPOINT/CMD".to_string()),
        });
    }

    Ok(findings)
}

fn scan_compose_file(path: &Path, content: &str) -> Result<Vec<DockerFinding>> {
    let mut findings = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1;
        let line_lower = line.to_lowercase();
        let trimmed = line.trim();

        // Check for privileged mode
        if trimmed.contains("privileged:") && line_lower.contains("true") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/privileged".to_string(),
                severity: "critical".to_string(),
                message: "Service runs in privileged mode".to_string(),
                fix: Some("Remove 'privileged: true' or use specific capabilities".to_string()),
            });
        }

        // Check for host network mode
        if trimmed.contains("network_mode:") && line_lower.contains("host") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/host-network".to_string(),
                severity: "high".to_string(),
                message: "Service uses host network mode".to_string(),
                fix: Some("Use bridge networking with explicit port mappings".to_string()),
            });
        }

        // Check for host PID mode
        if trimmed.contains("pid:") && line_lower.contains("host") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/host-pid".to_string(),
                severity: "critical".to_string(),
                message: "Service shares host PID namespace".to_string(),
                fix: Some("Remove 'pid: host' unless absolutely necessary".to_string()),
            });
        }

        // Check for sensitive volume mounts
        let sensitive_mounts = ["/etc", "/var/run/docker.sock", "/root", "/home"];
        for mount in sensitive_mounts {
            if line.contains(mount)
                && (trimmed.starts_with("- ") || trimmed.starts_with("volumes:"))
            {
                findings.push(DockerFinding {
                    file: path.display().to_string(),
                    line: line_num,
                    rule: "compose/sensitive-mount".to_string(),
                    severity: "high".to_string(),
                    message: format!("Mounting sensitive path: {}", mount),
                    fix: Some("Avoid mounting host system paths; use named volumes".to_string()),
                });
            }
        }

        // Check for hardcoded secrets
        let secrets = ["password:", "secret:", "api_key:", "token:", "credentials:"];
        for secret in secrets {
            if line_lower.contains(secret) && !line.contains("${") && !line.contains("_FILE") {
                findings.push(DockerFinding {
                    file: path.display().to_string(),
                    line: line_num,
                    rule: "compose/hardcoded-secret".to_string(),
                    severity: "critical".to_string(),
                    message: "Hardcoded secret in compose file".to_string(),
                    fix: Some("Use environment variables (${VAR}) or Docker secrets".to_string()),
                });
                break;
            }
        }

        // Check for cap_add
        if (trimmed.contains("cap_add:")
            || (line_lower.contains("- sys_admin")
                || line_lower.contains("- net_admin")
                || line_lower.contains("- all")))
            && (line_lower.contains("sys_admin") || line_lower.contains("all"))
        {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/dangerous-capability".to_string(),
                severity: "high".to_string(),
                message: "Adding dangerous Linux capability".to_string(),
                fix: Some("Use minimal capabilities required for functionality".to_string()),
            });
        }

        // Check for security_opt: no-new-privileges
        if trimmed.contains("no-new-privileges:") && line_lower.contains("false") {
            findings.push(DockerFinding {
                file: path.display().to_string(),
                line: line_num,
                rule: "compose/new-privileges".to_string(),
                severity: "medium".to_string(),
                message: "Container can gain new privileges".to_string(),
                fix: Some("Set 'no-new-privileges: true' or remove the line".to_string()),
            });
        }
    }

    Ok(findings)
}

fn scan_code_security(args: &SecurityArgs, report: &mut SecurityReport) -> Result<()> {
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = rma_analyzer::AnalyzerEngine::new(config);

    let (parsed_files, _stats) = parser.parse_directory(&args.path)?;

    let mut security_findings = 0;
    let mut files_scanned = 0;
    let mut files_excluded = 0;

    for parsed in &parsed_files {
        // Always exclude vendored/bundled/minified files (third-party code)
        if matches_exclude_pattern(&parsed.path, DEFAULT_VENDOR_IGNORE_PATHS) {
            files_excluded += 1;
            continue;
        }

        // Check if file should be excluded (default excludes for tests/fixtures)
        // Use the same comprehensive patterns as the scan command
        if !args.include_tests
            && (matches_exclude_pattern(&parsed.path, DEFAULT_TEST_IGNORE_PATHS)
                || matches_exclude_pattern(&parsed.path, DEFAULT_EXAMPLE_IGNORE_PATHS))
        {
            files_excluded += 1;
            continue;
        }

        files_scanned += 1;

        let analysis = match analyzer.analyze_file(parsed) {
            Ok(a) => a,
            Err(_) => continue,
        };

        for f in &analysis.findings {
            if !is_security_finding(f) {
                continue;
            }

            security_findings += 1;

            let file_path = analysis.path.clone();
            report.vulnerabilities.push(Vulnerability {
                id: f.rule_id.clone(),
                title: f.message.clone(),
                description: f.suggestion.clone().unwrap_or_default(),
                severity: severity_to_string(f.severity),
                cvss_score: None,
                package: file_path.clone(),
                installed_version: format!("line {}", f.location.start_line),
                fixed_versions: Vec::new(),
                fix_command: None,
                ecosystem: "source".to_string(),
                source_file: file_path,
                cve_ids: Vec::new(),
                ghsa_ids: Vec::new(),
                references: Vec::new(),
                published: None,
                is_direct: true,
            });
        }
    }

    if security_findings > 0 {
        println!(
            "  {} {} code security issues in {} files",
            "⚠".yellow(),
            security_findings,
            files_scanned
        );
    } else {
        println!(
            "  {} No code security issues in {} files",
            "✓".green(),
            files_scanned
        );
    }

    if files_excluded > 0 && !args.include_tests {
        println!(
            "  {} {} test/fixture files excluded (use --include-tests to scan)",
            "ℹ".dimmed(),
            files_excluded
        );
    }

    Ok(())
}

fn is_security_finding(f: &Finding) -> bool {
    use rma_common::FindingCategory;
    matches!(f.category, FindingCategory::Security)
        || f.rule_id.contains("security")
        || f.rule_id.contains("injection")
        || f.rule_id.contains("xss")
        || f.rule_id.contains("secret")
        || f.rule_id.contains("unsafe")
        || f.rule_id.contains("command")
        || f.rule_id.contains("sql")
        || f.rule_id.contains("path-traversal")
        || f.rule_id.contains("xxe")
        || f.rule_id.contains("deserialization")
        || f.rule_id.contains("crypto")
}

fn output_pretty_grouped(
    grouped: &[GroupedVulnerability],
    report: &SecurityReport,
    args: &SecurityArgs,
    duration: std::time::Duration,
) -> Result<()> {
    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════════════════".bright_white()
    );
    println!(
        "{}",
        "                    SECURITY AUDIT REPORT                    "
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "════════════════════════════════════════════════════════════".bright_white()
    );
    println!();

    // Summary box
    println!(
        "{}",
        "┌─────────────────────────────────────────────────────────────┐".dimmed()
    );
    println!(
        "│ {}                                              │",
        "SUMMARY".bright_white().bold()
    );
    println!(
        "{}",
        "├─────────────────────────────────────────────────────────────┤".dimmed()
    );
    println!(
        "│  Unique Vulnerabilities: {:>4}                              │",
        report
            .summary
            .total_vulnerabilities
            .to_string()
            .bright_white()
    );
    println!(
        "│  ├─ {} Critical: {:>3}                                      │",
        "●".red(),
        report.summary.critical
    );
    println!(
        "│  ├─ {} High:     {:>3}                                      │",
        "●".yellow(),
        report.summary.high
    );
    println!(
        "│  ├─ {} Medium:   {:>3}                                      │",
        "●".blue(),
        report.summary.medium
    );
    println!(
        "│  └─ {} Low:      {:>3}                                      │",
        "●".dimmed(),
        report.summary.low
    );
    println!("│                                                             │");
    println!(
        "│  Affected Packages: {:>4}                                  │",
        report.summary.unique_packages.to_string().bright_white()
    );
    println!(
        "│  Docker Issues:     {:>4}                                  │",
        report.summary.docker_issues.to_string().bright_white()
    );
    println!(
        "│  Fixable:           {:>4}                                  │",
        report.summary.fixable.to_string().green()
    );
    println!(
        "│  Scan Duration:   {:>5.2}s                                   │",
        duration.as_secs_f32()
    );
    println!(
        "{}",
        "└─────────────────────────────────────────────────────────────┘".dimmed()
    );
    println!();

    // Ecosystems breakdown
    if !report.ecosystems.is_empty() {
        println!("{}", "ECOSYSTEMS SCANNED".bright_white().bold());
        println!("{}", "─".repeat(60).dimmed());
        for (name, eco) in &report.ecosystems {
            let status = if eco.vulnerable_deps > 0 {
                format!("{} vulnerable", eco.vulnerable_deps)
                    .yellow()
                    .to_string()
            } else {
                "✓ secure".green().to_string()
            };
            println!(
                "  {:12} {} ({})",
                name.cyan(),
                eco.lockfile.dimmed(),
                status
            );
        }
        println!();
    }

    // Grouped vulnerabilities by severity
    if !grouped.is_empty() {
        println!("{}", "VULNERABILITIES (CVE → FIX)".bright_white().bold());
        println!("{}", "─".repeat(60).dimmed());
        println!();

        // Group by severity for display
        let mut by_severity: BTreeMap<&str, Vec<&GroupedVulnerability>> = BTreeMap::new();
        for gv in grouped {
            by_severity
                .entry(gv.severity.as_str())
                .or_default()
                .push(gv);
        }

        for severity in ["critical", "high", "medium", "low"] {
            if let Some(vulns) = by_severity.get(severity) {
                let label = match severity {
                    "critical" => "CRITICAL".red().bold(),
                    "high" => "HIGH".yellow().bold(),
                    "medium" => "MEDIUM".blue().bold(),
                    _ => "LOW".dimmed().bold(),
                };

                println!("  {} ({})", label, vulns.len());
                println!();

                for gv in vulns {
                    // Package and version
                    println!(
                        "    {} {}@{}",
                        "├─".dimmed(),
                        gv.package.cyan(),
                        gv.installed_version.dimmed()
                    );

                    // All advisory IDs
                    println!("    │  IDs: {}", gv.ids.join(", ").bright_white());

                    // CVEs if any
                    if !gv.cve_ids.is_empty() {
                        println!("    │  CVE: {}", gv.cve_ids.join(", ").yellow());
                    }

                    // Title
                    let title = if gv.title.len() > 50 {
                        format!("{}...", &gv.title[..47])
                    } else {
                        gv.title.clone()
                    };
                    println!("    │  {}", title);

                    // Fix version / command
                    if let Some(ref fix_ver) = gv.fixed_version {
                        println!("    │  {} Upgrade to: {}", "→".green(), fix_ver.green());
                        if let Some(ref cmd) = gv.fix_command {
                            println!("    │  {} Run: {}", "→".green(), cmd.bright_green());
                        }
                    } else if let Some(ref cmd) = gv.fix_command {
                        println!("    │  {} Run: {}", "→".yellow(), cmd.bright_green());
                    } else {
                        println!("    │  {} No fix available", "✗".red());
                    }

                    // References if showing details
                    if args.details && !gv.references.is_empty() {
                        println!("    │  Ref: {}", gv.references.first().unwrap().dimmed());
                    }

                    println!("    │");
                }
                println!();
            }
        }
    }

    // Docker findings
    if !report.docker_findings.is_empty() {
        println!("{}", "DOCKER SECURITY ISSUES".bright_white().bold());
        println!("{}", "─".repeat(60).dimmed());
        println!();

        for finding in &report.docker_findings {
            let severity = match finding.severity.as_str() {
                "critical" => "CRIT".red().bold(),
                "high" => "HIGH".yellow().bold(),
                "medium" => "MED ".blue(),
                _ => "LOW ".dimmed(),
            };

            println!(
                "  {} {} {}:{}",
                severity,
                finding.rule.bright_white(),
                finding.file.dimmed(),
                finding.line
            );
            println!("       {}", finding.message);
            if let Some(ref fix) = finding.fix {
                println!("       {} {}", "Fix:".green(), fix);
            }
            println!();
        }
    }

    // Footer
    println!("{}", "═".repeat(60).bright_white());
    if report.summary.critical > 0 || report.summary.high > 0 {
        println!(
            "{}",
            format!(
                "⚠️  {} critical/high severity issues require immediate attention",
                report.summary.critical + report.summary.high
            )
            .red()
            .bold()
        );
    } else if report.summary.total_vulnerabilities == 0 && report.summary.docker_issues == 0 {
        println!(
            "{}",
            "✅ Security audit passed - no vulnerabilities found!"
                .green()
                .bold()
        );
    } else {
        println!(
            "{}",
            format!(
                "ℹ️  {} lower-severity issues found",
                report.summary.total_vulnerabilities + report.summary.docker_issues
            )
            .blue()
        );
    }
    println!();

    Ok(())
}

fn output_json(report: &SecurityReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn output_sarif(report: &SecurityReport) -> Result<()> {
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rma-security",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/bumahkib7/rust-monorepo-analyzer",
                }
            },
            "results": report.vulnerabilities.iter().map(|v| {
                serde_json::json!({
                    "ruleId": v.id,
                    "level": match v.severity.as_str() {
                        "critical" | "high" => "error",
                        "medium" => "warning",
                        _ => "note"
                    },
                    "message": { "text": format!("{}: {}", v.package, v.title) },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": v.source_file }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });
    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}

fn output_markdown(report: &SecurityReport) -> Result<()> {
    println!("# Security Audit Report\n");
    println!("**Scan Time:** {}\n", report.scan_time);

    println!("## Summary\n");
    println!("| Metric | Count |");
    println!("|--------|-------|");
    println!(
        "| Total Vulnerabilities | {} |",
        report.summary.total_vulnerabilities
    );
    println!("| 🔴 Critical | {} |", report.summary.critical);
    println!("| 🟠 High | {} |", report.summary.high);
    println!("| 🟡 Medium | {} |", report.summary.medium);
    println!("| 🔵 Low | {} |", report.summary.low);
    println!("| Affected Packages | {} |", report.summary.unique_packages);
    println!("| Docker Issues | {} |", report.summary.docker_issues);
    println!("| Fixable | {} |", report.summary.fixable);
    println!();

    if !report.vulnerabilities.is_empty() {
        println!("## Vulnerabilities\n");
        println!("| Severity | Package | Version | CVE/ID | Fix Version |");
        println!("|----------|---------|---------|--------|-------------|");

        for v in &report.vulnerabilities {
            let sev = match v.severity.as_str() {
                "critical" => "🔴 Critical",
                "high" => "🟠 High",
                "medium" => "🟡 Medium",
                _ => "🔵 Low",
            };
            let cve = if !v.cve_ids.is_empty() {
                v.cve_ids.join(", ")
            } else {
                v.id.clone()
            };
            let fix = if !v.fixed_versions.is_empty() {
                v.fixed_versions.join(", ")
            } else {
                "N/A".to_string()
            };
            println!(
                "| {} | {} | {} | {} | {} |",
                sev, v.package, v.installed_version, cve, fix
            );
        }
        println!();
    }

    if !report.docker_findings.is_empty() {
        println!("## Docker Issues\n");
        for f in &report.docker_findings {
            println!("### {} ({}:{})\n", f.rule, f.file, f.line);
            println!("**Severity:** {}\n", f.severity);
            println!("{}\n", f.message);
            if let Some(ref fix) = f.fix {
                println!("**Fix:** {}\n", fix);
            }
        }
    }

    Ok(())
}

fn show_fix_commands_deduped(grouped: &[GroupedVulnerability]) -> Result<()> {
    println!();
    println!("{}", "RECOMMENDED FIX COMMANDS".bright_white().bold());
    println!("{}", "─".repeat(60).dimmed());
    println!();

    // Group vulnerabilities by ecosystem, deduplicate commands
    let mut by_eco: HashMap<String, BTreeSet<String>> = HashMap::new();

    for gv in grouped {
        if let Some(ref fix_ver) = gv.fixed_version {
            let entry = by_eco.entry(gv.ecosystem.clone()).or_default();

            // Generate specific update command based on ecosystem
            let cmd = match gv.ecosystem.as_str() {
                "crates.io" => format!("cargo update -p {} --precise {}", gv.package, fix_ver),
                "npm" => format!("npm install {}@{}", gv.package, fix_ver),
                "PyPI" => format!("pip install {}=={}", gv.package, fix_ver),
                "Go" => format!("go get {}@v{}", gv.package, fix_ver),
                "Maven" => format!(
                    "# Update {} to {} in pom.xml/build.gradle",
                    gv.package, fix_ver
                ),
                _ => continue,
            };
            entry.insert(cmd);
        }
    }

    if by_eco.contains_key("crates.io") {
        println!("  {} Rust (Cargo):", "📦".cyan());
        println!("    {}", "cargo update".bright_green());
        println!("    # Or update specific packages:");
        for cmd in by_eco.get("crates.io").unwrap().iter().take(5) {
            println!("    {}", cmd);
        }
        println!();
    }

    if by_eco.contains_key("npm") {
        println!("  {} npm:", "📦".cyan());
        println!("    {}", "npm audit fix".bright_green());
        println!("    # Or update specific packages:");
        for cmd in by_eco.get("npm").unwrap().iter().take(5) {
            println!("    {}", cmd);
        }
        println!();
    }

    if by_eco.contains_key("PyPI") {
        println!("  {} Python (pip):", "🐍".cyan());
        println!("    {}", "pip-audit --fix".bright_green());
        println!("    # Or update specific packages:");
        for cmd in by_eco.get("PyPI").unwrap().iter().take(5) {
            println!("    {}", cmd);
        }
        println!();
    }

    if by_eco.contains_key("Go") {
        println!("  {} Go:", "🐹".cyan());
        println!("    {}", "go get -u ./...".bright_green());
        println!("    {}", "go mod tidy".bright_green());
        for cmd in by_eco.get("Go").unwrap().iter().take(5) {
            println!("    {}", cmd);
        }
        println!();
    }

    if by_eco.contains_key("Maven") {
        println!("  {} Maven/Gradle:", "☕".cyan());
        println!("    {}", "mvn versions:use-latest-releases".bright_green());
        for cmd in by_eco.get("Maven").unwrap().iter().take(5) {
            println!("    {}", cmd);
        }
        println!();
    }

    Ok(())
}

// Helper functions
fn severity_to_string(s: Severity) -> String {
    match s {
        Severity::Critical => "critical",
        Severity::Error => "high",
        Severity::Warning => "medium",
        Severity::Info => "low",
    }
    .to_string()
}

fn parse_pkg_version(msg: &str) -> (String, String) {
    // Pattern 1: OSV format "ecosystem package_name is vulnerable"
    if let Ok(re) = regex::Regex::new(r"(?:crates\.io|npm|PyPI|Go|Maven)\s+(\S+)\s+is\s+vulnerable")
        && let Some(caps) = re.captures(msg)
    {
        let pkg_name = caps.get(1).map_or("unknown", |m| m.as_str()).to_string();
        if let Ok(ver_re) = regex::Regex::new(r"version\s+(\d+\.\d+\.\d+(?:-[\w.]+)?)")
            && let Some(ver_caps) = ver_re.captures(msg)
        {
            return (
                pkg_name,
                ver_caps
                    .get(1)
                    .map_or("unknown", |m| m.as_str())
                    .to_string(),
            );
        }
        return (pkg_name, "unknown".to_string());
    }

    // Pattern 2: RustSec format "package vX.Y.Z: title"
    if let Ok(re) = regex::Regex::new(r"^(\S+)\s+v(\d+\.\d+\.\d+(?:-[\w.]+)?)")
        && let Some(caps) = re.captures(msg)
    {
        return (
            caps.get(1).map_or("unknown", |m| m.as_str()).to_string(),
            caps.get(2).map_or("unknown", |m| m.as_str()).to_string(),
        );
    }

    // Pattern 3: Generic "package X.Y.Z" or "package@X.Y.Z"
    if let Ok(re) = regex::Regex::new(r"(\S+)[@\s]v?(\d+\.\d+\.\d+(?:-[\w.]+)?)")
        && let Some(caps) = re.captures(msg)
    {
        return (
            caps.get(1).map_or("unknown", |m| m.as_str()).to_string(),
            caps.get(2).map_or("unknown", |m| m.as_str()).to_string(),
        );
    }

    ("unknown".to_string(), "unknown".to_string())
}

fn extract_id(rule_id: &str) -> String {
    for prefix in ["RUSTSEC-", "GHSA-", "CVE-"] {
        if let Some(start) = rule_id.find(prefix) {
            let end = rule_id[start..]
                .find(|c: char| !c.is_alphanumeric() && c != '-')
                .map(|i| start + i)
                .unwrap_or(rule_id.len());
            return rule_id[start..end].to_string();
        }
    }
    rule_id.to_string()
}

fn extract_versions(text: &Option<String>) -> Vec<String> {
    let Some(t) = text else { return Vec::new() };
    let mut versions = Vec::new();

    // Pattern 1: "Patched in: >= X.Y.Z" (from RustSec)
    if let (Ok(re), Ok(ver_re)) = (
        regex::Regex::new(r"(?i)Patched in:\s*(.+?)(?:\n|$)"),
        regex::Regex::new(r">=?\s*(\d+\.\d+\.\d+(?:-[\w.]+)?)"),
    ) {
        for cap in re.captures_iter(t) {
            if let Some(m) = cap.get(1) {
                let patched_line = m.as_str();
                for ver_cap in ver_re.captures_iter(patched_line) {
                    if let Some(v) = ver_cap.get(1) {
                        let version = v.as_str().to_string();
                        if !versions.contains(&version) {
                            versions.push(version);
                        }
                    }
                }
            }
        }
    }

    // Pattern 2: "upgrade to version X.Y.Z" or "fixed in X.Y.Z"
    if let Ok(re) =
        regex::Regex::new(r"(?i)(?:upgrade to|fixed in|update to)\s*v?(\d+\.\d+\.\d+(?:-[\w.]+)?)")
    {
        for cap in re.captures_iter(t) {
            if let Some(m) = cap.get(1) {
                let v = m.as_str().to_string();
                if !versions.contains(&v) {
                    versions.push(v);
                }
            }
        }
    }

    // Pattern 3: "version >= X.Y.Z"
    if versions.is_empty()
        && let Ok(re) = regex::Regex::new(r">=\s*v?(\d+\.\d+\.\d+(?:-[\w.]+)?)")
    {
        for cap in re.captures_iter(t) {
            if let Some(m) = cap.get(1) {
                let v = m.as_str().to_string();
                if !versions.contains(&v) {
                    versions.push(v);
                }
            }
        }
    }

    // Pattern 4: Look for any semver at the end
    if versions.is_empty()
        && let Ok(re) = regex::Regex::new(r"(\d+\.\d+\.\d+(?:-[\w.]+)?)\s*$")
        && let Some(cap) = re.captures(t)
        && let Some(m) = cap.get(1)
    {
        versions.push(m.as_str().to_string());
    }

    versions
}

fn extract_cves(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"CVE-\d{4}-\d+").ok();
    re.map(|r| r.find_iter(text).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

fn extract_ghsas(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}").ok();
    re.map(|r| r.find_iter(text).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

fn extract_urls(text: &Option<String>) -> Vec<String> {
    let Some(t) = text else { return Vec::new() };
    let re = regex::Regex::new(r"https?://[^\s)>]+").ok();
    re.map(|r| r.find_iter(t).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

fn get_fix_command(ecosystem: &str) -> Option<String> {
    match ecosystem {
        "crates.io" => Some("cargo update".to_string()),
        "npm" => Some("npm audit fix".to_string()),
        "PyPI" => Some("pip install --upgrade <package>".to_string()),
        "Go" => Some("go get -u ./...".to_string()),
        "Maven" => Some("mvn versions:use-latest-releases".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicate_vulnerabilities() {
        let vulns = vec![
            Vulnerability {
                id: "GHSA-xxxx-xxxx-xxxx".to_string(),
                title: "GHSA title is longer and more descriptive".to_string(),
                description: "desc".to_string(),
                severity: "medium".to_string(),
                cvss_score: None,
                package: "gix-date".to_string(),
                installed_version: "0.10.7".to_string(),
                fixed_versions: vec!["0.12.0".to_string()],
                fix_command: Some("cargo update".to_string()),
                ecosystem: "crates.io".to_string(),
                source_file: "Cargo.lock".to_string(),
                cve_ids: vec![],
                ghsa_ids: vec!["GHSA-xxxx-xxxx-xxxx".to_string()],
                references: vec![],
                published: None,
                is_direct: false,
            },
            Vulnerability {
                id: "RUSTSEC-2025-0140".to_string(),
                title: "Non-utf8 String".to_string(),
                description: "desc2".to_string(),
                severity: "medium".to_string(),
                cvss_score: None,
                package: "gix-date".to_string(),
                installed_version: "0.10.7".to_string(),
                fixed_versions: vec!["0.12.0".to_string()],
                fix_command: Some("cargo update".to_string()),
                ecosystem: "crates.io".to_string(),
                source_file: "Cargo.lock".to_string(),
                cve_ids: vec![],
                ghsa_ids: vec![],
                references: vec![],
                published: None,
                is_direct: false,
            },
        ];

        let grouped = deduplicate_vulnerabilities(&vulns);

        // Should be deduplicated to 1 entry
        assert_eq!(grouped.len(), 1);

        // Should have both IDs
        assert_eq!(grouped[0].ids.len(), 2);
        assert!(grouped[0].ids.contains(&"GHSA-xxxx-xxxx-xxxx".to_string()));
        assert!(grouped[0].ids.contains(&"RUSTSEC-2025-0140".to_string()));

        // Should pick GHSA title (longer)
        assert!(grouped[0].title.contains("GHSA"));
    }

    #[test]
    fn test_matches_exclude_pattern() {
        // Test patterns should match test directories
        assert!(matches_exclude_pattern(
            Path::new("/project/src/tests/test_foo.rs"),
            DEFAULT_TEST_IGNORE_PATHS
        ));

        // Example patterns should match fixtures
        assert!(matches_exclude_pattern(
            Path::new("/project/fixtures/secrets.json"),
            DEFAULT_EXAMPLE_IGNORE_PATHS
        ));

        // Test patterns should match *.test.ts files
        assert!(matches_exclude_pattern(
            Path::new("/project/src/foo.test.ts"),
            DEFAULT_TEST_IGNORE_PATHS
        ));

        // Test patterns should match __tests__ directories
        assert!(matches_exclude_pattern(
            Path::new("/project/__tests__/auth.spec.js"),
            DEFAULT_TEST_IGNORE_PATHS
        ));

        // Should NOT match regular source files
        assert!(!matches_exclude_pattern(
            Path::new("/project/src/auth/login.rs"),
            DEFAULT_TEST_IGNORE_PATHS
        ));

        assert!(!matches_exclude_pattern(
            Path::new("/project/lib/security.py"),
            DEFAULT_TEST_IGNORE_PATHS
        ));
    }

    #[test]
    fn test_fail_on_severity() {
        let mut summary = SecuritySummary::default();

        // No vulnerabilities - always exit 0
        assert_eq!(determine_exit_code(&summary, FailSeverity::Critical), 0);
        assert_eq!(determine_exit_code(&summary, FailSeverity::High), 0);
        assert_eq!(determine_exit_code(&summary, FailSeverity::None), 0);

        // Only medium vulnerabilities
        summary.medium = 1;
        assert_eq!(determine_exit_code(&summary, FailSeverity::Critical), 0);
        assert_eq!(determine_exit_code(&summary, FailSeverity::High), 0);
        assert_eq!(determine_exit_code(&summary, FailSeverity::Medium), 1);
        assert_eq!(determine_exit_code(&summary, FailSeverity::Low), 1);
        assert_eq!(determine_exit_code(&summary, FailSeverity::None), 0);

        // Critical vulnerabilities
        summary.critical = 1;
        assert_eq!(determine_exit_code(&summary, FailSeverity::Critical), 1);
        assert_eq!(determine_exit_code(&summary, FailSeverity::High), 1);
        assert_eq!(determine_exit_code(&summary, FailSeverity::None), 0);
    }

    #[test]
    fn test_no_duplicate_fix_commands() {
        let grouped = vec![
            GroupedVulnerability {
                ids: vec!["GHSA-1".to_string(), "RUSTSEC-1".to_string()],
                title: "Vuln 1".to_string(),
                description: "".to_string(),
                severity: "medium".to_string(),
                package: "gix-date".to_string(),
                installed_version: "0.10.7".to_string(),
                fixed_version: Some("0.12.0".to_string()),
                fix_command: Some("cargo update".to_string()),
                ecosystem: "crates.io".to_string(),
                source_file: "Cargo.lock".to_string(),
                cve_ids: vec![],
                ghsa_ids: vec![],
                references: vec![],
            },
            GroupedVulnerability {
                ids: vec!["GHSA-2".to_string()],
                title: "Vuln 2".to_string(),
                description: "".to_string(),
                severity: "medium".to_string(),
                package: "gix-date".to_string(), // Same package, same fix version
                installed_version: "0.10.7".to_string(),
                fixed_version: Some("0.12.0".to_string()),
                fix_command: Some("cargo update".to_string()),
                ecosystem: "crates.io".to_string(),
                source_file: "Cargo.lock".to_string(),
                cve_ids: vec![],
                ghsa_ids: vec![],
                references: vec![],
            },
        ];

        // Collect fix commands - should be deduplicated
        let mut by_eco: HashMap<String, BTreeSet<String>> = HashMap::new();
        for gv in &grouped {
            if let Some(ref fix_ver) = gv.fixed_version {
                let cmd = format!("cargo update -p {} --precise {}", gv.package, fix_ver);
                by_eco.entry(gv.ecosystem.clone()).or_default().insert(cmd);
            }
        }

        // Should only have 1 command (deduplicated)
        assert_eq!(by_eco.get("crates.io").unwrap().len(), 1);
    }
}
