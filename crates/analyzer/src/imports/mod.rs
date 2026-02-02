//! Import/Module Resolution
//!
//! This module parses import statements and resolves which file a symbol comes from.
//! Maps `import { sanitize } from './utils'` → `src/utils.js` exports `sanitize`.
//!
//! # Supported Languages
//! - JavaScript/TypeScript: ES6 imports, CommonJS require
//! - Python: from...import, import
//! - Rust: use statements
//! - Go: import statements
//! - Java: import statements

pub mod go;
pub mod java;
pub mod javascript;
pub mod python;
pub mod rust_lang;

use rma_common::Language;
use std::path::{Path, PathBuf};

/// A resolved import: maps an imported symbol to its source file and exported name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedImport {
    /// The local name used in this file (e.g., "sanitize", "express")
    pub local_name: String,
    /// The source file this import comes from (absolute path)
    pub source_file: PathBuf,
    /// The exported name in the source file (may differ from local_name due to aliasing)
    pub exported_name: String,
    /// Whether this is a default import, named import, or namespace import
    pub kind: ImportKind,
    /// The raw import specifier (e.g., "./utils", "express", "@/lib/auth")
    pub specifier: String,
    /// Line number of the import statement
    pub line: usize,
}

/// Type of import
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportKind {
    /// import foo from './bar' (JS default) / from bar import Foo (Python)
    Default,
    /// import { foo } from './bar' (JS named) / from bar import foo (Python)
    Named,
    /// import * as foo from './bar' (JS namespace) / import bar (Python)
    Namespace,
    /// require('./bar') (CommonJS)
    CommonJS,
    /// use crate::bar::foo (Rust)
    Use,
    /// import "bar" (Go)
    GoImport,
    /// import bar.Foo (Java)
    JavaImport,
}

/// An exported symbol from a file
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Export {
    /// Name of the exported symbol
    pub name: String,
    /// Is this the default export?
    pub is_default: bool,
    /// AST node ID of the export declaration
    pub node_id: usize,
    /// Line number
    pub line: usize,
    /// What kind of thing is exported (function, class, variable, type)
    pub kind: ExportKind,
}

/// Kind of exported symbol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportKind {
    Function,
    Class,
    Variable,
    Type,
    Module,
    Unknown,
}

/// Per-file import/export information
#[derive(Debug, Clone, Default)]
pub struct FileImports {
    /// All imports in this file
    pub imports: Vec<ResolvedImport>,
    /// All exports from this file
    pub exports: Vec<Export>,
    /// Unresolved imports (external packages, missing files)
    pub unresolved: Vec<UnresolvedImport>,
}

/// An import that could not be resolved to a local file
#[derive(Debug, Clone)]
pub struct UnresolvedImport {
    /// The import specifier
    pub specifier: String,
    /// The local name used
    pub local_name: String,
    /// Line number
    pub line: usize,
    /// Reason for being unresolved
    pub reason: UnresolvedReason,
}

/// Reason an import couldn't be resolved
#[derive(Debug, Clone)]
pub enum UnresolvedReason {
    /// External package (node_modules, pip package, crate, etc.)
    ExternalPackage,
    /// File not found on disk
    FileNotFound,
    /// Ambiguous resolution (multiple candidates)
    Ambiguous(Vec<PathBuf>),
    /// Unsupported import pattern
    Unsupported,
}

/// Extract imports and exports from a parsed file.
pub fn extract_file_imports(
    tree: &tree_sitter::Tree,
    source: &[u8],
    file_path: &Path,
    language: Language,
    project_root: &Path,
) -> FileImports {
    match language {
        Language::JavaScript | Language::TypeScript => {
            javascript::extract_imports(tree, source, file_path, project_root)
        }
        Language::Python => python::extract_imports(tree, source, file_path, project_root),
        Language::Rust => rust_lang::extract_imports(tree, source, file_path, project_root),
        Language::Go => go::extract_imports(tree, source, file_path, project_root),
        Language::Java => java::extract_imports(tree, source, file_path, project_root),
        _ => FileImports::default(),
    }
}

/// Try to resolve a relative import specifier to an absolute path
pub fn resolve_relative_import(
    specifier: &str,
    from_file: &Path,
    _project_root: &Path,
    extensions: &[&str],
) -> Option<PathBuf> {
    if !specifier.starts_with("./") && !specifier.starts_with("../") {
        return None;
    }

    let from_dir = from_file.parent()?;
    let base_path = from_dir.join(specifier);

    // Try exact path first
    if base_path.exists() && base_path.is_file() {
        return Some(base_path.canonicalize().unwrap_or(base_path));
    }

    // Try with extensions
    for ext in extensions {
        let with_ext = base_path.with_extension(ext.trim_start_matches('.'));
        if with_ext.exists() && with_ext.is_file() {
            return Some(with_ext.canonicalize().unwrap_or(with_ext));
        }
    }

    // Try index files
    if base_path.is_dir() {
        for ext in extensions {
            let index = base_path.join(format!("index.{}", ext.trim_start_matches('.')));
            if index.exists() {
                return Some(index.canonicalize().unwrap_or(index));
            }
        }
    }

    None
}

/// Check if an import specifier refers to an external package
pub fn is_external_package(specifier: &str) -> bool {
    // Relative imports are not external
    if specifier.starts_with("./") || specifier.starts_with("../") {
        return false;
    }

    // Absolute paths are not external
    if specifier.starts_with('/') {
        return false;
    }

    // Path aliases (like @/) might be internal
    if specifier.starts_with('@') {
        // @org/package is external, @/ or @alias/ might be internal
        let parts: Vec<&str> = specifier.splitn(2, '/').collect();
        if parts.len() == 2 && !parts[0].contains('/') && parts[0].len() > 1 {
            // This looks like @org/package, which is external
            return true;
        }
        // Could be a path alias - treat as potentially internal
        return false;
    }

    // Everything else (bare specifiers) is external
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_external_package() {
        assert!(is_external_package("express"));
        assert!(is_external_package("lodash"));
        assert!(is_external_package("@types/node"));
        assert!(is_external_package("@org/package"));

        assert!(!is_external_package("./utils"));
        assert!(!is_external_package("../lib/helper"));
        assert!(!is_external_package("/absolute/path"));
    }

    #[test]
    fn test_import_kind_equality() {
        assert_eq!(ImportKind::Default, ImportKind::Default);
        assert_ne!(ImportKind::Default, ImportKind::Named);
    }
}
