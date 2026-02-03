//! WASM Plugin System for RMA
//!
//! This crate provides a WebAssembly-based plugin system that allows users
//! to write custom analysis rules in any language that compiles to WASM.
//!
//! # Plugin Interface
//!
//! Plugins implement a simple interface:
//! - `analyze(source: &str, language: &str) -> Vec<Finding>`
//!
//! # Example Plugin (Rust compiled to WASM)
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "C" fn analyze(source_ptr: *const u8, source_len: usize) -> *mut Finding {
//!     // ... analysis logic
//! }
//! ```

pub mod host;
pub mod loader;
pub mod registry;

use anyhow::Result;
use rma_common::{Finding, Language};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur in the plugin system
#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Failed to load plugin: {0}")]
    LoadError(String),

    #[error("Plugin execution failed: {0}")]
    ExecutionError(String),

    #[error("Invalid plugin interface: {0}")]
    InterfaceError(String),

    #[error("Plugin not found: {0}")]
    NotFound(String),

    #[error("WASM error: {0}")]
    WasmError(#[from] anyhow::Error),
}

/// Metadata about a loaded plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: Option<String>,
    pub languages: Vec<Language>,
    pub rules: Vec<String>,
}

/// A loaded WASM plugin
pub struct Plugin {
    pub metadata: PluginMetadata,
    instance: wasmtime::Instance,
    store: wasmtime::Store<host::HostState>,
}

impl Plugin {
    /// Run the plugin's analysis on the given source code
    pub fn analyze(&mut self, source: &str, language: Language) -> Result<Vec<Finding>> {
        host::call_analyze(&mut self.store, &self.instance, source, language)
    }
}

/// Input data passed to plugin analysis functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInput {
    pub source: String,
    pub file_path: String,
    pub language: String,
}

/// Output from plugin analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOutput {
    pub findings: Vec<PluginFinding>,
}

/// A finding reported by a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    pub rule_id: String,
    pub message: String,
    pub severity: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub snippet: Option<String>,
    pub suggestion: Option<String>,
}

impl From<PluginFinding> for Finding {
    fn from(pf: PluginFinding) -> Self {
        let mut finding = Finding {
            id: format!(
                "plugin-{}-{}-{}",
                pf.rule_id, pf.start_line, pf.start_column
            ),
            rule_id: pf.rule_id,
            message: pf.message,
            severity: match pf.severity.to_lowercase().as_str() {
                "critical" => rma_common::Severity::Critical,
                "error" => rma_common::Severity::Error,
                "warning" => rma_common::Severity::Warning,
                _ => rma_common::Severity::Info,
            },
            location: rma_common::SourceLocation::new(
                std::path::PathBuf::new(),
                pf.start_line,
                pf.start_column,
                pf.end_line,
                pf.end_column,
            ),
            language: Language::Unknown,
            snippet: pf.snippet,
            suggestion: pf.suggestion,
            fix: None,
            confidence: rma_common::Confidence::Medium,
            category: rma_common::FindingCategory::Quality,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        };
        finding.compute_fingerprint();
        finding
    }
}

/// The main plugin manager
pub struct PluginManager {
    registry: registry::PluginRegistry,
    engine: wasmtime::Engine,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new() -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.async_support(false);

        let engine = wasmtime::Engine::new(&config)?;

        Ok(Self {
            registry: registry::PluginRegistry::new(),
            engine,
        })
    }

    /// Load a plugin from a WASM file
    pub fn load_plugin(&mut self, path: &Path) -> Result<String, PluginError> {
        info!("Loading plugin from {:?}", path);

        let wasm_bytes = std::fs::read(path)
            .map_err(|e| PluginError::LoadError(format!("Failed to read file: {}", e)))?;

        let module = wasmtime::Module::new(&self.engine, &wasm_bytes)
            .map_err(|e| PluginError::LoadError(format!("Failed to compile WASM: {}", e)))?;

        let mut store = wasmtime::Store::new(&self.engine, host::HostState::new());

        // Create linker with host functions
        let linker = host::create_linker(&self.engine)?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| PluginError::LoadError(format!("Failed to instantiate: {}", e)))?;

        // Get plugin metadata
        let metadata = host::get_plugin_metadata(&mut store, &instance)?;
        let plugin_name = metadata.name.clone();

        let plugin = Plugin {
            metadata,
            instance,
            store,
        };

        self.registry.register(plugin)?;

        Ok(plugin_name)
    }

    /// Load all plugins from a directory
    pub fn load_plugins_from_dir(&mut self, dir: &Path) -> Result<Vec<String>> {
        let mut loaded = Vec::new();

        if !dir.exists() {
            debug!("Plugin directory {:?} does not exist", dir);
            return Ok(loaded);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                match self.load_plugin(&path) {
                    Ok(name) => {
                        info!("Loaded plugin: {}", name);
                        loaded.push(name);
                    }
                    Err(e) => {
                        warn!("Failed to load plugin {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(loaded)
    }

    /// Run all applicable plugins on the given source
    pub fn analyze(&mut self, source: &str, language: Language) -> Result<Vec<Finding>> {
        self.registry.analyze_all(source, language)
    }

    /// List all loaded plugins
    pub fn list_plugins(&self) -> Vec<&PluginMetadata> {
        self.registry.list()
    }

    /// Unload a plugin by name
    pub fn unload_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        self.registry.unregister(name)
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new().expect("Failed to create plugin manager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_manager_creation() {
        let manager = PluginManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_plugin_finding_conversion() {
        let pf = PluginFinding {
            rule_id: "test-rule".to_string(),
            message: "Test message".to_string(),
            severity: "warning".to_string(),
            start_line: 10,
            start_column: 5,
            end_line: 10,
            end_column: 15,
            snippet: Some("test code".to_string()),
            suggestion: None,
        };

        let finding: Finding = pf.into();
        assert_eq!(finding.rule_id, "test-rule");
        assert_eq!(finding.severity, rma_common::Severity::Warning);
    }
}
