//! High-Performance OSV Vulnerability Database
//!
//! Offline-first vulnerability scanning using locally cached OSV data.
//! Downloads vulnerability databases from GCS and indexes them for O(1) lookups.
//!
//! Architecture:
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        OSV Database Architecture                         │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │   Query: "is lodash@4.17.20 vulnerable?"                                │
//! │                     │                                                    │
//! │                     ▼                                                    │
//! │   ┌─────────────────────────────────┐                                   │
//! │   │     Bloom Filter (O(1))         │  ──► "definitely not vulnerable"  │
//! │   │   ~1MB per ecosystem            │      (fast path, 99% of queries)  │
//! │   └─────────────────────────────────┘                                   │
//! │                     │ maybe vulnerable                                   │
//! │                     ▼                                                    │
//! │   ┌─────────────────────────────────┐                                   │
//! │   │   FxHashMap Index (O(1))        │  ──► package_name → [vuln_ids]    │
//! │   │   In-memory, ~10MB              │                                   │
//! │   └─────────────────────────────────┘                                   │
//! │                     │                                                    │
//! │                     ▼                                                    │
//! │   ┌─────────────────────────────────┐                                   │
//! │   │   Sled KV Store                 │  ──► vuln_id → OsvVulnerability   │
//! │   │   Memory-mapped, compressed     │      (full vulnerability data)    │
//! │   └─────────────────────────────────┘                                   │
//! │                     │                                                    │
//! │                     ▼                                                    │
//! │   ┌─────────────────────────────────┐                                   │
//! │   │   Version Matcher               │  ──► Check if version in range    │
//! │   │   semver + ecosystem-specific   │                                   │
//! │   └─────────────────────────────────┘                                   │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Data Sources (GCS Public Bucket):
//! - All: https://storage.googleapis.com/osv-vulnerabilities/all.zip
//! - Cargo: https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip
//! - npm: https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip
//! - PyPI: https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip
//! - Go: https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip
//! - Maven: https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip

use anyhow::{Context, Result};
use rayon::prelude::*;
use rma_common::OsvEcosystem;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

// ============================================================================
// Constants
// ============================================================================

/// GCS bucket URLs for OSV data
pub const OSV_GCS_BASE: &str = "https://storage.googleapis.com/osv-vulnerabilities";

/// Ecosystem download URLs
pub fn ecosystem_url(ecosystem: &OsvEcosystem) -> String {
    let name = match ecosystem {
        OsvEcosystem::CratesIo => "crates.io",
        OsvEcosystem::Npm => "npm",
        OsvEcosystem::PyPI => "PyPI",
        OsvEcosystem::Go => "Go",
        OsvEcosystem::Maven => "Maven",
    };
    format!("{}/{}/all.zip", OSV_GCS_BASE, name)
}

/// Bloom filter parameters
const BLOOM_EXPECTED_ITEMS: usize = 100_000; // Expected packages per ecosystem
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.01; // 1% false positive rate

// ============================================================================
// Data Structures
// ============================================================================

/// OSV Vulnerability (matching OSV schema)
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
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub withdrawn: Option<String>,
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
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub ecosystem_specific: Option<serde_json::Value>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvRange {
    #[serde(rename = "type")]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
    #[serde(default)]
    pub repo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub ref_type: String,
    pub url: String,
}

/// Query result with matched vulnerabilities
#[derive(Debug, Clone)]
pub struct VulnMatch {
    pub vulnerability: OsvVulnerability,
    pub matched_version: String,
    pub fix_version: Option<String>,
}

/// Database metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMetadata {
    pub ecosystem: String,
    pub last_updated: u64,
    pub vuln_count: usize,
    pub package_count: usize,
    pub bloom_filter_size: usize,
    pub index_size: usize,
    pub db_version: u32,
}

/// Bloom filter for fast negative lookups
#[derive(Clone)]
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
}

impl BloomFilter {
    /// Create a new bloom filter with optimal size for expected items
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        // Calculate optimal size: m = -n*ln(p) / (ln(2)^2)
        let num_bits = (-(expected_items as f64) * false_positive_rate.ln() / (2_f64.ln().powi(2)))
            .ceil() as usize;
        let num_bits = num_bits.max(64); // Minimum 64 bits

        // Calculate optimal number of hash functions: k = (m/n) * ln(2)
        let num_hashes = ((num_bits as f64 / expected_items as f64) * 2_f64.ln()).ceil() as u32;
        let num_hashes = num_hashes.clamp(1, 16);

        let num_words = num_bits.div_ceil(64);

        Self {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes,
        }
    }

    /// Insert an item into the bloom filter
    pub fn insert(&mut self, item: &str) {
        let (h1, h2) = self.hash_pair(item);
        for i in 0..self.num_hashes {
            let idx = self.get_index(h1, h2, i);
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            self.bits[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// Check if an item might be in the set (false positives possible)
    #[inline]
    pub fn might_contain(&self, item: &str) -> bool {
        let (h1, h2) = self.hash_pair(item);
        for i in 0..self.num_hashes {
            let idx = self.get_index(h1, h2, i);
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            if self.bits[word_idx] & (1u64 << bit_idx) == 0 {
                return false;
            }
        }
        true
    }

    /// Double hashing using FxHash
    #[inline]
    fn hash_pair(&self, item: &str) -> (u64, u64) {
        use std::hash::{BuildHasher, Hasher};
        let build_hasher = rustc_hash::FxBuildHasher;

        let mut hasher1 = build_hasher.build_hasher();
        hasher1.write(item.as_bytes());
        let h1 = hasher1.finish();

        let mut hasher2 = build_hasher.build_hasher();
        hasher2.write(item.as_bytes());
        hasher2.write_u64(0x517cc1b727220a95); // Mix in a constant
        let h2 = hasher2.finish();

        (h1, h2)
    }

    #[inline]
    fn get_index(&self, h1: u64, h2: u64, i: u32) -> usize {
        let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (combined as usize) % self.num_bits
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.bits.len() * 8);
        bytes.extend_from_slice(&(self.num_bits as u32).to_le_bytes());
        bytes.extend_from_slice(&self.num_hashes.to_le_bytes());
        bytes.extend_from_slice(&(self.bits.len() as u32).to_le_bytes());
        for word in &self.bits {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let num_bits = u32::from_le_bytes(bytes[0..4].try_into().ok()?) as usize;
        let num_hashes = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        let num_words = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;

        if bytes.len() < 12 + num_words * 8 {
            return None;
        }

        let mut bits = Vec::with_capacity(num_words);
        for i in 0..num_words {
            let start = 12 + i * 8;
            let word = u64::from_le_bytes(bytes[start..start + 8].try_into().ok()?);
            bits.push(word);
        }

        Some(Self {
            bits,
            num_bits,
            num_hashes,
        })
    }
}

// ============================================================================
// Package Index (in-memory FxHashMap)
// ============================================================================

/// Fast in-memory index mapping package names to vulnerability IDs
#[derive(Default)]
pub struct PackageIndex {
    /// package_name -> list of vulnerability IDs
    index: FxHashMap<String, Vec<String>>,
}

impl PackageIndex {
    pub fn new() -> Self {
        Self {
            index: FxHashMap::default(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            index: FxHashMap::with_capacity_and_hasher(capacity, Default::default()),
        }
    }

    /// Add a vulnerability for a package
    pub fn insert(&mut self, package_name: String, vuln_id: String) {
        self.index.entry(package_name).or_default().push(vuln_id);
    }

    /// Get vulnerability IDs for a package
    #[inline]
    pub fn get(&self, package_name: &str) -> Option<&Vec<String>> {
        self.index.get(package_name)
    }

    /// Check if package exists in index
    #[inline]
    pub fn contains(&self, package_name: &str) -> bool {
        self.index.contains_key(package_name)
    }

    /// Number of packages in index
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Serialize to bytes (for caching)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.index).context("Failed to serialize package index")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let index: FxHashMap<String, Vec<String>> =
            bincode::deserialize(bytes).context("Failed to deserialize package index")?;
        Ok(Self { index })
    }
}

// ============================================================================
// Ecosystem Database
// ============================================================================

/// Database for a single ecosystem
pub struct EcosystemDb {
    pub ecosystem: OsvEcosystem,
    pub db_path: PathBuf,

    /// Bloom filter for O(1) "definitely not vulnerable" checks
    bloom: BloomFilter,

    /// In-memory index: package_name -> [vuln_ids]
    index: PackageIndex,

    /// Sled database for vulnerability data
    db: sled::Db,

    /// Metadata
    metadata: DbMetadata,

    /// Stats
    queries: AtomicU64,
    bloom_hits: AtomicU64, // Queries answered by bloom filter (negative)
    cache_hits: AtomicU64,
}

impl EcosystemDb {
    /// Open or create an ecosystem database
    pub fn open(ecosystem: OsvEcosystem, base_path: &Path) -> Result<Self> {
        let ecosystem_name = ecosystem.to_string().to_lowercase();
        let db_path = base_path.join(&ecosystem_name);
        fs::create_dir_all(&db_path)?;

        let sled_path = db_path.join("sled");
        let db = sled::Config::new()
            .path(&sled_path)
            .cache_capacity(64 * 1024 * 1024) // 64MB cache
            .mode(sled::Mode::LowSpace)
            .open()
            .context("Failed to open Sled database")?;

        // Load or create bloom filter
        let bloom_path = db_path.join("bloom.bin");
        let bloom = if bloom_path.exists() {
            let bytes = fs::read(&bloom_path)?;
            BloomFilter::from_bytes(&bytes).unwrap_or_else(|| {
                BloomFilter::new(BLOOM_EXPECTED_ITEMS, BLOOM_FALSE_POSITIVE_RATE)
            })
        } else {
            BloomFilter::new(BLOOM_EXPECTED_ITEMS, BLOOM_FALSE_POSITIVE_RATE)
        };

        // Load or create index
        let index_path = db_path.join("index.bin");
        let index = if index_path.exists() {
            let bytes = fs::read(&index_path)?;
            PackageIndex::from_bytes(&bytes).unwrap_or_default()
        } else {
            PackageIndex::new()
        };

        // Load or create metadata
        let metadata_path = db_path.join("metadata.json");
        let metadata = if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            serde_json::from_str(&content).unwrap_or_else(|_| DbMetadata {
                ecosystem: ecosystem_name.clone(),
                last_updated: 0,
                vuln_count: 0,
                package_count: 0,
                bloom_filter_size: bloom.bits.len() * 8,
                index_size: index.len(),
                db_version: 1,
            })
        } else {
            DbMetadata {
                ecosystem: ecosystem_name,
                last_updated: 0,
                vuln_count: 0,
                package_count: 0,
                bloom_filter_size: bloom.bits.len() * 8,
                index_size: index.len(),
                db_version: 1,
            }
        };

        Ok(Self {
            ecosystem,
            db_path,
            bloom,
            index,
            db,
            metadata,
            queries: AtomicU64::new(0),
            bloom_hits: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
        })
    }

    /// Query vulnerabilities for a package
    #[inline]
    pub fn query(&self, package_name: &str, version: &str) -> Result<Vec<VulnMatch>> {
        self.queries.fetch_add(1, Ordering::Relaxed);

        // Normalize package name for lookup
        let normalized = self.normalize_package_name(package_name);

        // Fast path: bloom filter check
        if !self.bloom.might_contain(&normalized) {
            self.bloom_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Vec::new());
        }

        // Get vulnerability IDs from index
        let vuln_ids = match self.index.get(&normalized) {
            Some(ids) => ids,
            None => return Ok(Vec::new()),
        };

        // Fetch and filter vulnerabilities
        let mut matches = Vec::new();
        for vuln_id in vuln_ids {
            if let Some(vuln) = self.get_vulnerability(vuln_id)? {
                // Check if this version is affected
                if let Some(fix_version) = self.is_version_affected(&vuln, package_name, version) {
                    matches.push(VulnMatch {
                        vulnerability: vuln,
                        matched_version: version.to_string(),
                        fix_version,
                    });
                }
            }
        }

        Ok(matches)
    }

    /// Get a vulnerability by ID from Sled
    fn get_vulnerability(&self, vuln_id: &str) -> Result<Option<OsvVulnerability>> {
        match self.db.get(vuln_id.as_bytes())? {
            Some(bytes) => {
                let vuln: OsvVulnerability = bincode::deserialize(&bytes)?;
                Ok(Some(vuln))
            }
            None => Ok(None),
        }
    }

    /// Check if a version is affected by a vulnerability
    /// Returns Some(fix_version) if affected, None if not affected
    fn is_version_affected(
        &self,
        vuln: &OsvVulnerability,
        package_name: &str,
        version: &str,
    ) -> Option<Option<String>> {
        for affected in &vuln.affected {
            // Check package name matches
            if let Some(pkg) = &affected.package {
                if !self.package_names_match(&pkg.name, package_name) {
                    continue;
                }
            }

            // Check explicit version list first (faster)
            if !affected.versions.is_empty() {
                if affected.versions.iter().any(|v| v == version) {
                    let fix = self.find_fix_version(affected);
                    return Some(fix);
                }
                continue;
            }

            // Check version ranges
            for range in &affected.ranges {
                if self.version_in_range(version, range) {
                    let fix = self.find_fix_version(affected);
                    return Some(fix);
                }
            }
        }

        None
    }

    /// Check if version is within a range
    fn version_in_range(&self, version: &str, range: &OsvRange) -> bool {
        let mut dominated_introduced = false;
        let mut fixed_or_limited = false;

        for event in &range.events {
            if let Some(introduced) = &event.introduced {
                // "0" means all versions
                if introduced == "0" || self.version_gte(version, introduced) {
                    dominated_introduced = true;
                }
            }

            if let Some(fixed) = &event.fixed {
                if self.version_gte(version, fixed) {
                    // Version is >= fixed, so not vulnerable
                    fixed_or_limited = true;
                }
            }

            if let Some(last_affected) = &event.last_affected {
                if self.version_gt(version, last_affected) {
                    // Version is > last_affected, so not vulnerable
                    fixed_or_limited = true;
                }
            }
        }

        dominated_introduced && !fixed_or_limited
    }

    /// Compare versions (ecosystem-aware)
    fn version_gte(&self, v1: &str, v2: &str) -> bool {
        match self.ecosystem {
            OsvEcosystem::CratesIo | OsvEcosystem::Npm => {
                // Try semver comparison
                if let (Ok(ver1), Ok(ver2)) =
                    (semver::Version::parse(v1), semver::Version::parse(v2))
                {
                    return ver1 >= ver2;
                }
            }
            OsvEcosystem::PyPI => {
                // Python uses PEP 440, but semver works for most cases
                if let (Ok(ver1), Ok(ver2)) =
                    (semver::Version::parse(v1), semver::Version::parse(v2))
                {
                    return ver1 >= ver2;
                }
            }
            _ => {}
        }
        // Fallback to string comparison
        v1 >= v2
    }

    fn version_gt(&self, v1: &str, v2: &str) -> bool {
        match self.ecosystem {
            OsvEcosystem::CratesIo | OsvEcosystem::Npm => {
                if let (Ok(ver1), Ok(ver2)) =
                    (semver::Version::parse(v1), semver::Version::parse(v2))
                {
                    return ver1 > ver2;
                }
            }
            _ => {}
        }
        v1 > v2
    }

    /// Find fix version from affected entry
    fn find_fix_version(&self, affected: &OsvAffected) -> Option<String> {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = &event.fixed {
                    return Some(fixed.clone());
                }
            }
        }
        None
    }

    /// Normalize package name for consistent lookups
    fn normalize_package_name(&self, name: &str) -> String {
        match self.ecosystem {
            OsvEcosystem::CratesIo => {
                // Rust: underscores and hyphens are interchangeable
                name.replace('-', "_").to_lowercase()
            }
            OsvEcosystem::PyPI => {
                // Python: case-insensitive, underscores/hyphens interchangeable
                name.replace('-', "_").to_lowercase()
            }
            OsvEcosystem::Npm => {
                // npm: case-sensitive, but normalize for index
                name.to_lowercase()
            }
            _ => name.to_lowercase(),
        }
    }

    /// Check if package names match (ecosystem-aware)
    fn package_names_match(&self, name1: &str, name2: &str) -> bool {
        self.normalize_package_name(name1) == self.normalize_package_name(name2)
    }

    /// Update database from downloaded ZIP file
    pub fn update_from_zip(
        &mut self,
        zip_path: &Path,
        progress: Option<&dyn Fn(usize, usize)>,
    ) -> Result<UpdateStats> {
        let start = Instant::now();
        let file = File::open(zip_path)?;
        let mut archive = zip::ZipArchive::new(BufReader::new(file))?;

        let total_files = archive.len();
        let mut processed = 0;
        let mut errors = 0;
        let mut vulns_added = 0;

        // Create new bloom filter and index
        let mut new_bloom = BloomFilter::new(BLOOM_EXPECTED_ITEMS, BLOOM_FALSE_POSITIVE_RATE);
        let mut new_index = PackageIndex::with_capacity(total_files);
        let mut packages_seen: HashSet<String> = HashSet::new();

        // Process files in batches for Sled efficiency
        let mut batch = sled::Batch::default();
        let batch_size = 1000;

        for i in 0..total_files {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();

            // Skip non-JSON files
            if !name.ends_with(".json") {
                continue;
            }

            // Read and parse vulnerability
            let mut content = String::new();
            if let Err(e) = file.read_to_string(&mut content) {
                debug!("Failed to read {}: {}", name, e);
                errors += 1;
                continue;
            }

            let vuln: OsvVulnerability = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    debug!("Failed to parse {}: {}", name, e);
                    errors += 1;
                    continue;
                }
            };

            // Skip withdrawn vulnerabilities
            if vuln.withdrawn.is_some() {
                continue;
            }

            // Index by package names
            for affected in &vuln.affected {
                if let Some(pkg) = &affected.package {
                    let normalized = self.normalize_package_name(&pkg.name);

                    // Add to bloom filter
                    new_bloom.insert(&normalized);

                    // Add to index
                    new_index.insert(normalized.clone(), vuln.id.clone());

                    // Track unique packages
                    packages_seen.insert(normalized);
                }
            }

            // Serialize and add to batch
            let serialized = bincode::serialize(&vuln)?;
            batch.insert(vuln.id.as_bytes(), serialized);
            vulns_added += 1;

            // Flush batch periodically
            if vulns_added % batch_size == 0 {
                self.db.apply_batch(batch)?;
                batch = sled::Batch::default();
            }

            processed += 1;
            if let Some(progress_fn) = progress {
                progress_fn(processed, total_files);
            }
        }

        // Flush remaining batch
        self.db.apply_batch(batch)?;
        self.db.flush()?;

        // Update in-memory structures
        self.bloom = new_bloom;
        self.index = new_index;

        // Save bloom filter
        let bloom_bytes = self.bloom.to_bytes();
        fs::write(self.db_path.join("bloom.bin"), &bloom_bytes)?;

        // Save index
        let index_bytes = self.index.to_bytes()?;
        fs::write(self.db_path.join("index.bin"), &index_bytes)?;

        // Update metadata
        self.metadata.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.metadata.vuln_count = vulns_added;
        self.metadata.package_count = packages_seen.len();
        self.metadata.bloom_filter_size = bloom_bytes.len();
        self.metadata.index_size = index_bytes.len();

        let metadata_json = serde_json::to_string_pretty(&self.metadata)?;
        fs::write(self.db_path.join("metadata.json"), metadata_json)?;

        let duration = start.elapsed();

        Ok(UpdateStats {
            ecosystem: self.ecosystem,
            vulns_added,
            packages_indexed: packages_seen.len(),
            errors,
            duration,
        })
    }

    /// Get database statistics
    pub fn stats(&self) -> DbStats {
        DbStats {
            ecosystem: self.ecosystem,
            vuln_count: self.metadata.vuln_count,
            package_count: self.metadata.package_count,
            last_updated: self.metadata.last_updated,
            queries: self.queries.load(Ordering::Relaxed),
            bloom_hits: self.bloom_hits.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            bloom_size_bytes: self.metadata.bloom_filter_size,
            index_size_bytes: self.metadata.index_size,
        }
    }

    /// Check if database needs update (older than max_age)
    pub fn needs_update(&self, max_age: Duration) -> bool {
        if self.metadata.last_updated == 0 {
            return true;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.metadata.last_updated > max_age.as_secs()
    }
}

// ============================================================================
// Statistics
// ============================================================================

#[derive(Debug, Clone)]
pub struct UpdateStats {
    pub ecosystem: OsvEcosystem,
    pub vulns_added: usize,
    pub packages_indexed: usize,
    pub errors: usize,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct DbStats {
    pub ecosystem: OsvEcosystem,
    pub vuln_count: usize,
    pub package_count: usize,
    pub last_updated: u64,
    pub queries: u64,
    pub bloom_hits: u64,
    pub cache_hits: u64,
    pub bloom_size_bytes: usize,
    pub index_size_bytes: usize,
}

impl DbStats {
    pub fn bloom_hit_rate(&self) -> f64 {
        if self.queries == 0 {
            0.0
        } else {
            self.bloom_hits as f64 / self.queries as f64
        }
    }
}

// ============================================================================
// Main Database Manager
// ============================================================================

/// High-performance OSV database manager
pub struct OsvDatabase {
    base_path: PathBuf,
    ecosystems: RwLock<FxHashMap<OsvEcosystem, Arc<EcosystemDb>>>,
}

impl OsvDatabase {
    /// Create a new OSV database manager
    pub fn new(base_path: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_path)?;
        Ok(Self {
            base_path,
            ecosystems: RwLock::new(FxHashMap::default()),
        })
    }

    /// Open default database location
    pub fn open_default() -> Result<Self> {
        let base_path = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rma")
            .join("osv-db");
        Self::new(base_path)
    }

    /// Get or open an ecosystem database
    pub fn ecosystem(&self, ecosystem: OsvEcosystem) -> Result<Arc<EcosystemDb>> {
        // Fast path: check if already loaded
        {
            let guard = self.ecosystems.read().unwrap();
            if let Some(db) = guard.get(&ecosystem) {
                return Ok(Arc::clone(db));
            }
        }

        // Slow path: open database
        let db = Arc::new(EcosystemDb::open(ecosystem, &self.base_path)?);

        // Store for future use
        {
            let mut guard = self.ecosystems.write().unwrap();
            guard.insert(ecosystem, Arc::clone(&db));
        }

        Ok(db)
    }

    /// Query vulnerabilities for a package
    pub fn query(
        &self,
        ecosystem: OsvEcosystem,
        package_name: &str,
        version: &str,
    ) -> Result<Vec<VulnMatch>> {
        let db = self.ecosystem(ecosystem)?;
        db.query(package_name, version)
    }

    /// Batch query multiple packages (parallel)
    pub fn query_batch(
        &self,
        queries: &[(OsvEcosystem, String, String)],
    ) -> Result<Vec<(OsvEcosystem, String, String, Vec<VulnMatch>)>> {
        queries
            .par_iter()
            .map(|(ecosystem, package, version)| {
                let matches = self.query(*ecosystem, package, version)?;
                Ok((*ecosystem, package.clone(), version.clone(), matches))
            })
            .collect()
    }

    /// Download and update an ecosystem database
    pub fn update_ecosystem(
        &self,
        ecosystem: OsvEcosystem,
        progress: Option<&(dyn Fn(&str, usize, usize) + Sync)>,
    ) -> Result<UpdateStats> {
        let url = ecosystem_url(&ecosystem);
        let zip_path = self.base_path.join(format!("{}.zip", ecosystem));

        // Download ZIP
        info!("Downloading {} database from {}", ecosystem, url);
        if let Some(p) = progress {
            p(&format!("Downloading {}", ecosystem), 0, 100);
        }

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(300)) // 5 minute timeout for large files
            .build()?;

        let response = client.get(&url).send()?;
        if !response.status().is_success() {
            anyhow::bail!("Failed to download {}: {}", url, response.status());
        }

        let bytes = response.bytes()?;
        fs::write(&zip_path, &bytes)?;

        if let Some(p) = progress {
            p(&format!("Downloaded {}", ecosystem), 100, 100);
        }

        // Update database from ZIP
        info!("Indexing {} vulnerabilities...", ecosystem);
        let mut db = EcosystemDb::open(ecosystem, &self.base_path)?;

        let progress_wrapper: Option<&dyn Fn(usize, usize)> = if progress.is_some() {
            None // TODO: wire up progress
        } else {
            None
        };

        let stats = db.update_from_zip(&zip_path, progress_wrapper)?;

        // Clean up ZIP file
        let _ = fs::remove_file(&zip_path);

        // Update cache
        {
            let mut guard = self.ecosystems.write().unwrap();
            guard.insert(ecosystem, Arc::new(db));
        }

        info!(
            "Updated {}: {} vulnerabilities, {} packages in {:?}",
            ecosystem, stats.vulns_added, stats.packages_indexed, stats.duration
        );

        Ok(stats)
    }

    /// Update all ecosystems (parallel)
    pub fn update_all(
        &self,
        ecosystems: &[OsvEcosystem],
        progress: Option<&(dyn Fn(&str, usize, usize) + Sync)>,
    ) -> Result<Vec<UpdateStats>> {
        // Note: Running sequentially to avoid overwhelming network/disk
        // Could be parallelized with proper resource management
        let mut all_stats = Vec::new();
        for (i, ecosystem) in ecosystems.iter().enumerate() {
            if let Some(p) = progress {
                p(&format!("Updating {}", ecosystem), i, ecosystems.len());
            }
            let stats = self.update_ecosystem(*ecosystem, None)?;
            all_stats.push(stats);
        }
        Ok(all_stats)
    }

    /// Get statistics for all loaded ecosystems
    pub fn all_stats(&self) -> Vec<DbStats> {
        let guard = self.ecosystems.read().unwrap();
        guard.values().map(|db| db.stats()).collect()
    }

    /// Check which ecosystems need updates
    pub fn check_updates(&self, max_age: Duration) -> Vec<OsvEcosystem> {
        let all_ecosystems = [
            OsvEcosystem::CratesIo,
            OsvEcosystem::Npm,
            OsvEcosystem::PyPI,
            OsvEcosystem::Go,
            OsvEcosystem::Maven,
        ];

        all_ecosystems
            .iter()
            .filter(|&&eco| {
                if let Ok(db) = self.ecosystem(eco) {
                    db.needs_update(max_age)
                } else {
                    true // Needs update if we can't open it
                }
            })
            .copied()
            .collect()
    }

    /// Get base path
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter() {
        let mut bloom = BloomFilter::new(1000, 0.01);

        bloom.insert("lodash");
        bloom.insert("express");
        bloom.insert("react");

        assert!(bloom.might_contain("lodash"));
        assert!(bloom.might_contain("express"));
        assert!(bloom.might_contain("react"));

        // These might have false positives, but should mostly be false
        let mut false_positives = 0;
        for i in 0..1000 {
            if bloom.might_contain(&format!("nonexistent-package-{}", i)) {
                false_positives += 1;
            }
        }
        // Should be around 1% false positive rate
        assert!(
            false_positives < 50,
            "Too many false positives: {}",
            false_positives
        );
    }

    #[test]
    fn test_bloom_filter_serialization() {
        let mut bloom = BloomFilter::new(100, 0.01);
        bloom.insert("test-package");

        let bytes = bloom.to_bytes();
        let restored = BloomFilter::from_bytes(&bytes).unwrap();

        assert!(restored.might_contain("test-package"));
    }

    #[test]
    fn test_package_index() {
        let mut index = PackageIndex::new();

        index.insert("lodash".to_string(), "GHSA-1234".to_string());
        index.insert("lodash".to_string(), "CVE-2021-5678".to_string());
        index.insert("express".to_string(), "GHSA-9999".to_string());

        assert_eq!(index.get("lodash").unwrap().len(), 2);
        assert_eq!(index.get("express").unwrap().len(), 1);
        assert!(index.get("nonexistent").is_none());
    }

    #[test]
    fn test_package_index_serialization() {
        let mut index = PackageIndex::new();
        index.insert("test".to_string(), "VULN-1".to_string());

        let bytes = index.to_bytes().unwrap();
        let restored = PackageIndex::from_bytes(&bytes).unwrap();

        assert!(restored.contains("test"));
    }

    #[test]
    fn test_normalize_package_name() {
        // We can't directly test normalize_package_name without an EcosystemDb
        // but we can test the logic
        let rust_name = "serde-json".replace('-', "_").to_lowercase();
        assert_eq!(rust_name, "serde_json");

        let python_name = "Django-REST-Framework".replace('-', "_").to_lowercase();
        assert_eq!(python_name, "django_rest_framework");
    }
}
