//! Plugin loading utilities

use crate::{Plugin, PluginError, PluginMetadata};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Default plugin directories
pub fn default_plugin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Project-local plugins
    dirs.push(PathBuf::from(".rma/plugins"));

    // User plugins
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join(".config/rma/plugins"));
    }

    // System plugins
    #[cfg(unix)]
    dirs.push(PathBuf::from("/usr/share/rma/plugins"));

    dirs
}

/// Discover all WASM plugins in the given directories
pub fn discover_plugins(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut plugins = Vec::new();

    for dir in dirs {
        if !dir.exists() {
            debug!("Plugin directory {:?} does not exist", dir);
            continue;
        }

        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                        info!("Discovered plugin: {:?}", path);
                        plugins.push(path);
                    }
                }
            }
            Err(e) => {
                debug!("Failed to read plugin directory {:?}: {}", dir, e);
            }
        }
    }

    plugins
}

/// Validate a WASM plugin file
pub fn validate_plugin(path: &Path) -> Result<(), PluginError> {
    // Check file exists
    if !path.exists() {
        return Err(PluginError::NotFound(path.display().to_string()));
    }

    // Check extension
    if path.extension().map(|e| e != "wasm").unwrap_or(true) {
        return Err(PluginError::LoadError("File must have .wasm extension".into()));
    }

    // Check file size (max 10MB)
    let metadata = std::fs::metadata(path)
        .map_err(|e| PluginError::LoadError(format!("Failed to read metadata: {}", e)))?;

    if metadata.len() > 10 * 1024 * 1024 {
        return Err(PluginError::LoadError("Plugin file exceeds 10MB limit".into()));
    }

    // Basic WASM magic number check
    let mut file = std::fs::File::open(path)
        .map_err(|e| PluginError::LoadError(format!("Failed to open file: {}", e)))?;

    let mut magic = [0u8; 4];
    use std::io::Read;
    file.read_exact(&mut magic)
        .map_err(|e| PluginError::LoadError(format!("Failed to read file: {}", e)))?;

    if magic != [0x00, 0x61, 0x73, 0x6D] {
        return Err(PluginError::LoadError("Invalid WASM magic number".into()));
    }

    Ok(())
}

/// Plugin manifest file structure
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: Option<String>,
    pub wasm_file: String,
    pub languages: Vec<String>,
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
}

/// Load plugin manifest from JSON file
pub fn load_manifest(path: &Path) -> Result<PluginManifest, PluginError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| PluginError::LoadError(format!("Failed to read manifest: {}", e)))?;

    serde_json::from_str(&content)
        .map_err(|e| PluginError::LoadError(format!("Invalid manifest JSON: {}", e)))
}
