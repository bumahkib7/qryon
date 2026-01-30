//! Sled-based key-value store for metadata and caching

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;

/// A simple key-value store backed by sled
pub struct MetadataStore {
    db: sled::Db,
}

impl MetadataStore {
    /// Open or create a metadata store
    pub fn open(path: &Path) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Store a value
    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        self.db.insert(key, bytes)?;
        self.db.flush()?;
        Ok(())
    }

    /// Retrieve a value
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        match self.db.get(key)? {
            Some(bytes) => {
                let value = serde_json::from_slice(&bytes)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Remove a key
    pub fn remove(&self, key: &str) -> Result<()> {
        self.db.remove(key)?;
        Ok(())
    }

    /// Check if a key exists
    pub fn contains(&self, key: &str) -> Result<bool> {
        Ok(self.db.contains_key(key)?)
    }

    /// Get file hash for incremental checking
    pub fn get_file_hash(&self, path: &str) -> Result<Option<String>> {
        self.get(&format!("hash:{}", path))
    }

    /// Store file hash
    pub fn set_file_hash(&self, path: &str, hash: &str) -> Result<()> {
        self.set(&format!("hash:{}", path), &hash.to_string())
    }

    /// Clear all data
    pub fn clear(&self) -> Result<()> {
        self.db.clear()?;
        Ok(())
    }
}

/// Compute a simple hash of file contents for change detection
pub fn compute_file_hash(content: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_metadata_store() {
        let temp = TempDir::new().unwrap();
        let store = MetadataStore::open(temp.path()).unwrap();

        store.set("key1", &"value1".to_string()).unwrap();
        let value: Option<String> = store.get("key1").unwrap();
        assert_eq!(value, Some("value1".to_string()));

        store.remove("key1").unwrap();
        let value: Option<String> = store.get("key1").unwrap();
        assert_eq!(value, None);
    }

    #[test]
    fn test_file_hash() {
        let hash1 = compute_file_hash("hello world");
        let hash2 = compute_file_hash("hello world");
        let hash3 = compute_file_hash("different content");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
