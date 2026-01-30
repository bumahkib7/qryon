//! Plugin registry for managing loaded plugins

use crate::{host, Plugin, PluginError, PluginMetadata};
use anyhow::Result;
use rma_common::{Finding, Language};
use std::collections::HashMap;
use tracing::{debug, info};

/// Registry of loaded plugins
pub struct PluginRegistry {
    plugins: HashMap<String, Plugin>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a new plugin
    pub fn register(&mut self, plugin: Plugin) -> Result<(), PluginError> {
        let name = plugin.metadata.name.clone();

        if self.plugins.contains_key(&name) {
            return Err(PluginError::LoadError(format!(
                "Plugin '{}' is already registered",
                name
            )));
        }

        info!("Registered plugin: {} v{}", name, plugin.metadata.version);
        self.plugins.insert(name, plugin);
        Ok(())
    }

    /// Unregister a plugin by name
    pub fn unregister(&mut self, name: &str) -> Result<(), PluginError> {
        if self.plugins.remove(name).is_some() {
            info!("Unregistered plugin: {}", name);
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    /// Get a plugin by name
    pub fn get(&self, name: &str) -> Option<&Plugin> {
        self.plugins.get(name)
    }

    /// Get a mutable reference to a plugin
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Plugin> {
        self.plugins.get_mut(name)
    }

    /// List all registered plugins
    pub fn list(&self) -> Vec<&PluginMetadata> {
        self.plugins.values().map(|p| &p.metadata).collect()
    }

    /// Get plugins that support a given language
    pub fn plugins_for_language(&self, language: Language) -> Vec<&str> {
        self.plugins
            .iter()
            .filter(|(_, p)| p.metadata.languages.contains(&language) || p.metadata.languages.is_empty())
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Run all applicable plugins on source code
    pub fn analyze_all(&mut self, source: &str, language: Language) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        // Get names of applicable plugins
        let plugin_names: Vec<String> = self
            .plugins
            .iter()
            .filter(|(_, p)| {
                p.metadata.languages.contains(&language) || p.metadata.languages.is_empty()
            })
            .map(|(name, _)| name.clone())
            .collect();

        // Run each plugin
        for name in plugin_names {
            if let Some(plugin) = self.plugins.get_mut(&name) {
                debug!("Running plugin: {}", name);
                match plugin.analyze(source, language) {
                    Ok(findings) => {
                        debug!("Plugin {} returned {} findings", name, findings.len());
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        tracing::warn!("Plugin {} failed: {}", name, e);
                    }
                }
            }
        }

        Ok(all_findings)
    }

    /// Get count of registered plugins
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// Check if a plugin is registered
    pub fn contains(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.count(), 0);
    }
}
