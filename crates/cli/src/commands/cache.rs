//! Cache command - manage RMA cache (OSV vulnerability data, etc.)
//!
//! The cache system includes:
//! - **OSV Local Database**: Full vulnerability database downloaded from GCS (recommended)
//! - **API Response Cache**: Individual package vulnerability lookups (fallback)
//!
//! Use `rma cache update` to download the OSV database for offline scanning.

use crate::CacheAction;
use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_analyzer::providers::{OsvDatabase, osv_db};
use rma_common::OsvEcosystem;
use std::fs;
use std::path::PathBuf;

/// Get the default OSV cache directory
pub fn get_osv_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .map(|d| d.join("rma").join("osv"))
        .unwrap_or_else(|| PathBuf::from(".rma/cache/osv"))
}

/// Get cache statistics
pub struct CacheStats {
    pub path: PathBuf,
    pub exists: bool,
    pub entry_count: usize,
    pub total_size_bytes: u64,
}

impl CacheStats {
    pub fn gather(cache_dir: &PathBuf) -> Self {
        if !cache_dir.exists() {
            return Self {
                path: cache_dir.clone(),
                exists: false,
                entry_count: 0,
                total_size_bytes: 0,
            };
        }

        let mut entry_count = 0;
        let mut total_size = 0u64;

        if let Ok(entries) = fs::read_dir(cache_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().extension().is_some_and(|ext| ext == "json") {
                    entry_count += 1;
                    if let Ok(meta) = entry.metadata() {
                        total_size += meta.len();
                    }
                }
            }
        }

        Self {
            path: cache_dir.clone(),
            exists: true,
            entry_count,
            total_size_bytes: total_size,
        }
    }

    pub fn format_size(&self) -> String {
        let bytes = self.total_size_bytes;
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

pub fn run(action: CacheAction) -> Result<()> {
    match action {
        CacheAction::Status => show_status(),
        CacheAction::Update { ecosystems, force } => update_database(ecosystems, force),
        CacheAction::Clear { force } => clear_cache(force),
    }
}

fn show_status() -> Result<()> {
    println!();
    println!("{}", "📦 RMA Cache Status".cyan().bold());
    println!("{}", Theme::separator(60));

    // OSV Local Database (primary - high performance)
    println!();
    println!(
        "  {}",
        "OSV Local Database (Recommended)".bright_white().bold()
    );

    let db_path = get_osv_db_dir();
    if let Ok(db) = OsvDatabase::new(db_path.clone()) {
        println!(
            "    {} {}",
            "Path:".dimmed(),
            db.base_path().display().to_string().cyan()
        );

        let ecosystems = [
            OsvEcosystem::CratesIo,
            OsvEcosystem::Npm,
            OsvEcosystem::PyPI,
            OsvEcosystem::Go,
            OsvEcosystem::Maven,
        ];

        let mut total_vulns = 0;
        let mut total_packages = 0;

        for eco in &ecosystems {
            if let Ok(eco_db) = db.ecosystem(*eco) {
                let stats = eco_db.stats();
                total_vulns += stats.vuln_count;
                total_packages += stats.package_count;

                let age = if stats.last_updated > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let age_secs = now.saturating_sub(stats.last_updated);
                    format_duration_ago(age_secs)
                } else {
                    "never".to_string()
                };

                let _status_color = if stats.vuln_count > 0 {
                    "ready".green()
                } else {
                    "empty".yellow()
                };

                println!(
                    "    {} {:12} {:>6} vulns, {:>6} packages, updated {}",
                    Theme::bullet(),
                    format!("{}:", eco).bright_white(),
                    stats.vuln_count.to_string().cyan(),
                    stats.package_count.to_string().dimmed(),
                    age.dimmed()
                );
            } else {
                println!(
                    "    {} {:12} {}",
                    Theme::bullet(),
                    format!("{}:", eco).bright_white(),
                    "not downloaded".yellow()
                );
            }
        }

        if total_vulns > 0 {
            println!();
            println!(
                "    {} {} vulnerabilities across {} packages",
                "Total:".bright_white(),
                total_vulns.to_string().cyan().bold(),
                total_packages.to_string().bright_white()
            );
            println!(
                "    {} Bloom filter: O(1) negative lookups, ~1% false positive rate",
                Theme::info_mark()
            );
        }
    } else {
        println!(
            "    {} {}",
            "Path:".dimmed(),
            db_path.display().to_string().cyan()
        );
        println!("    {} {}", "Status:".dimmed(), "not initialized".yellow());
        println!(
            "    {} Run {} to download vulnerability databases",
            Theme::info_mark(),
            "rma cache update".cyan()
        );
    }

    // API Response Cache (fallback)
    println!();
    println!(
        "  {}",
        "API Response Cache (Fallback)".bright_white().bold()
    );
    let osv_cache_dir = get_osv_cache_dir();
    let osv_stats = CacheStats::gather(&osv_cache_dir);

    println!(
        "    {} {}",
        "Path:".dimmed(),
        osv_stats.path.display().to_string().cyan()
    );

    if osv_stats.exists && osv_stats.entry_count > 0 {
        println!(
            "    {} {} entries, {}",
            "Cached:".dimmed(),
            osv_stats.entry_count.to_string().bright_white(),
            osv_stats.format_size().dimmed()
        );
        println!("    {} {}", "TTL:".dimmed(), "24h".bright_white());
    } else {
        println!("    {} {}", "Status:".dimmed(), "empty".dimmed());
    }

    // Local project cache
    let local_cache = PathBuf::from(".rma/cache/osv");
    if local_cache.exists() {
        let local_stats = CacheStats::gather(&local_cache);
        if local_stats.entry_count > 0 {
            println!();
            println!("  {}", "Local Project Cache".bright_white().bold());
            println!(
                "    {} {} entries, {}",
                "Cached:".dimmed(),
                local_stats.entry_count.to_string().bright_white(),
                local_stats.format_size().dimmed()
            );
        }
    }

    println!();
    println!("{}", Theme::separator(60));
    println!(
        "  {} {} - Download OSV databases for offline scanning",
        Theme::info_mark(),
        "rma cache update".cyan()
    );
    println!(
        "  {} {} - Remove all cached data",
        Theme::info_mark(),
        "rma cache clear".cyan()
    );
    println!();

    Ok(())
}

/// Update OSV vulnerability databases
fn update_database(ecosystems: Option<Vec<String>>, _force: bool) -> Result<()> {
    println!();
    println!(
        "{}",
        "📥 Updating OSV Vulnerability Databases".cyan().bold()
    );
    println!("{}", Theme::separator(60));

    // Parse ecosystems or use defaults
    let ecosystems_to_update: Vec<OsvEcosystem> = if let Some(eco_strs) = ecosystems {
        eco_strs
            .iter()
            .filter_map(|s| match s.to_lowercase().as_str() {
                "cargo" | "crates.io" | "crates" | "rust" => Some(OsvEcosystem::CratesIo),
                "npm" | "node" | "js" | "javascript" => Some(OsvEcosystem::Npm),
                "pypi" | "python" | "pip" => Some(OsvEcosystem::PyPI),
                "go" | "golang" => Some(OsvEcosystem::Go),
                "maven" | "java" | "gradle" => Some(OsvEcosystem::Maven),
                _ => {
                    eprintln!("{} Unknown ecosystem: {}", Theme::warning_mark(), s);
                    None
                }
            })
            .collect()
    } else {
        vec![
            OsvEcosystem::CratesIo,
            OsvEcosystem::Npm,
            OsvEcosystem::PyPI,
            OsvEcosystem::Go,
            OsvEcosystem::Maven,
        ]
    };

    if ecosystems_to_update.is_empty() {
        anyhow::bail!("No valid ecosystems specified");
    }

    // Open or create database
    let db_path = get_osv_db_dir();
    let db = OsvDatabase::new(db_path)?;

    println!();
    println!("  Ecosystems to update:");
    for eco in &ecosystems_to_update {
        let url = osv_db::ecosystem_url(eco);
        println!(
            "    {} {} ({})",
            Theme::bullet(),
            eco.to_string().cyan(),
            url.dimmed()
        );
    }
    println!();

    // Update each ecosystem
    let mut total_vulns = 0;
    let mut total_packages = 0;

    for (i, eco) in ecosystems_to_update.iter().enumerate() {
        print!(
            "  [{}/{}] Updating {}... ",
            i + 1,
            ecosystems_to_update.len(),
            eco.to_string().cyan()
        );
        std::io::Write::flush(&mut std::io::stdout())?;

        match db.update_ecosystem(*eco, None) {
            Ok(stats) => {
                println!(
                    "{} {} vulns, {} packages in {:.1}s",
                    "done".green(),
                    stats.vulns_added.to_string().cyan(),
                    stats.packages_indexed.to_string().dimmed(),
                    stats.duration.as_secs_f64()
                );
                total_vulns += stats.vulns_added;
                total_packages += stats.packages_indexed;
            }
            Err(e) => {
                println!("{} {}", "failed".red(), e.to_string().dimmed());
            }
        }
    }

    println!();
    println!("{}", Theme::separator(60));
    println!(
        "  {} Downloaded {} vulnerabilities across {} packages",
        Theme::success_mark(),
        total_vulns.to_string().cyan().bold(),
        total_packages.to_string().bright_white()
    );
    println!(
        "  {} Queries now use O(1) bloom filter + local Sled database",
        Theme::info_mark()
    );
    println!();

    Ok(())
}

/// Get OSV database directory
fn get_osv_db_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rma")
        .join("osv-db")
}

/// Format seconds ago as human-readable string
fn format_duration_ago(secs: u64) -> String {
    if secs < 60 {
        "just now".to_string()
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn clear_cache(force: bool) -> Result<()> {
    let osv_cache_dir = get_osv_cache_dir();
    let local_cache_dir = PathBuf::from(".rma/cache/osv");

    let mut paths_to_clear = Vec::new();

    if osv_cache_dir.exists() {
        paths_to_clear.push(osv_cache_dir.clone());
    }
    if local_cache_dir.exists() {
        paths_to_clear.push(local_cache_dir.clone());
    }

    if paths_to_clear.is_empty() {
        println!("{} No cache directories found to clear", Theme::info_mark());
        return Ok(());
    }

    // Show what will be deleted
    println!();
    println!("{}", "Cache directories to clear:".bright_white().bold());
    for path in &paths_to_clear {
        let stats = CacheStats::gather(path);
        println!(
            "  {} {} ({} entries, {})",
            Theme::bullet(),
            path.display(),
            stats.entry_count,
            stats.format_size()
        );
    }
    println!();

    // Confirm unless force
    if !force {
        print!("Are you sure you want to delete these cache files? [y/N] ");
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("{} Aborted", Theme::info_mark());
            return Ok(());
        }
    }

    // Clear cache
    let mut total_deleted = 0;
    for path in &paths_to_clear {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().extension().is_some_and(|ext| ext == "json")
                    && fs::remove_file(entry.path()).is_ok()
                {
                    total_deleted += 1;
                }
            }
        }
    }

    println!(
        "{} Cleared {} cache entries",
        Theme::success_mark(),
        total_deleted.to_string().green()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        let stats = CacheStats {
            path: PathBuf::from("/tmp"),
            exists: true,
            entry_count: 10,
            total_size_bytes: 512,
        };
        assert_eq!(stats.format_size(), "512 B");

        let stats = CacheStats {
            path: PathBuf::from("/tmp"),
            exists: true,
            entry_count: 10,
            total_size_bytes: 2048,
        };
        assert_eq!(stats.format_size(), "2.0 KB");

        let stats = CacheStats {
            path: PathBuf::from("/tmp"),
            exists: true,
            entry_count: 10,
            total_size_bytes: 1048576,
        };
        assert_eq!(stats.format_size(), "1.0 MB");
    }

    #[test]
    fn test_cache_stats_nonexistent() {
        let stats = CacheStats::gather(&PathBuf::from("/nonexistent/path/12345"));
        assert!(!stats.exists);
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }
}
