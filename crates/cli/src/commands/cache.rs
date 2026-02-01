//! Cache command - manage RMA cache (OSV vulnerability data, etc.)

use crate::CacheAction;
use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
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
        CacheAction::Clear { force } => clear_cache(force),
    }
}

fn show_status() -> Result<()> {
    println!();
    println!("{}", "📦 RMA Cache Status".cyan().bold());
    println!("{}", Theme::separator(50));

    // OSV Cache
    let osv_cache_dir = get_osv_cache_dir();
    let osv_stats = CacheStats::gather(&osv_cache_dir);

    println!();
    println!("  {}", "OSV Vulnerability Cache".bright_white().bold());
    println!(
        "    {} {}",
        "Path:".dimmed(),
        osv_stats.path.display().to_string().cyan()
    );

    if osv_stats.exists {
        println!("    {} {}", "Status:".dimmed(), "present".green());
        println!(
            "    {} {}",
            "Entries:".dimmed(),
            osv_stats.entry_count.to_string().bright_white()
        );
        println!(
            "    {} {}",
            "Size:".dimmed(),
            osv_stats.format_size().bright_white()
        );
        println!("    {} {}", "Default TTL:".dimmed(), "24h".bright_white());
    } else {
        println!("    {} {}", "Status:".dimmed(), "not created yet".yellow());
    }

    // Local project cache
    let local_cache = PathBuf::from(".rma/cache/osv");
    if local_cache.exists() {
        let local_stats = CacheStats::gather(&local_cache);
        println!();
        println!("  {}", "Local Project Cache".bright_white().bold());
        println!(
            "    {} {}",
            "Path:".dimmed(),
            local_stats.path.display().to_string().cyan()
        );
        println!(
            "    {} {}",
            "Entries:".dimmed(),
            local_stats.entry_count.to_string().bright_white()
        );
        println!(
            "    {} {}",
            "Size:".dimmed(),
            local_stats.format_size().bright_white()
        );
    }

    println!();
    println!("{}", Theme::separator(50));
    println!(
        "  {} Use {} to remove cache files",
        Theme::info_mark(),
        "rma cache clear".cyan()
    );
    println!();

    Ok(())
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
