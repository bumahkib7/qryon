//! Go import resolution
//!
//! Handles:
//! - import "package/path"
//! - import alias "package/path"
//! - import . "package/path" (dot import)
//! - import _ "package/path" (side-effect import)
//! - import ( ... ) (grouped imports)

use super::{
    Export, ExportKind, FileImports, ImportKind, ResolvedImport, UnresolvedImport, UnresolvedReason,
};
use std::path::{Path, PathBuf};

/// Extract imports and exports from a Go file
pub fn extract_imports(
    tree: &tree_sitter::Tree,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
) -> FileImports {
    let mut file_imports = FileImports::default();
    let root = tree.root_node();

    extract_imports_recursive(root, source, file_path, project_root, &mut file_imports);

    file_imports
}

fn extract_imports_recursive(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    match node.kind() {
        "import_declaration" => {
            extract_import_declaration(node, source, file_path, project_root, file_imports);
        }
        "function_declaration" => {
            extract_function_export(node, source, file_imports);
        }
        "method_declaration" => {
            extract_method_export(node, source, file_imports);
        }
        "type_declaration" => {
            extract_type_export(node, source, file_imports);
        }
        "var_declaration" | "const_declaration" => {
            extract_var_export(node, source, file_imports);
        }
        _ => {}
    }

    // Recurse into children (but not into function bodies)
    if !matches!(node.kind(), "function_declaration" | "method_declaration") {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_imports_recursive(child, source, file_path, project_root, file_imports);
        }
    }
}

/// Extract imports from an import declaration
fn extract_import_declaration(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "import_spec" => {
                extract_import_spec(child, source, file_path, project_root, file_imports);
            }
            "import_spec_list" => {
                // Grouped imports
                let mut list_cursor = child.walk();
                for spec in child.children(&mut list_cursor) {
                    if spec.kind() == "import_spec" {
                        extract_import_spec(spec, source, file_path, project_root, file_imports);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Extract a single import spec
fn extract_import_spec(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let line = node.start_position().row + 1;

    // Get the package path
    let path_node = node.child_by_field_name("path");
    let package_path = match path_node {
        Some(p) => {
            let text = p.utf8_text(source).unwrap_or("");
            text.trim_matches('"').to_string()
        }
        None => return,
    };

    // Get the alias if present
    let name_node = node.child_by_field_name("name");
    let (local_name, kind) = match name_node {
        Some(n) => {
            let alias = n.utf8_text(source).unwrap_or("");
            match alias {
                "." => ("*".to_string(), ImportKind::Namespace), // dot import
                "_" => ("_".to_string(), ImportKind::GoImport),  // side-effect import
                _ => (alias.to_string(), ImportKind::GoImport),
            }
        }
        None => {
            // Default name is last path component
            let default_name = package_path
                .rsplit('/')
                .next()
                .unwrap_or(&package_path)
                .to_string();
            (default_name, ImportKind::GoImport)
        }
    };

    // Try to resolve the import
    let resolved = resolve_go_import(&package_path, file_path, project_root);

    if let Some(source_file) = resolved {
        file_imports.imports.push(ResolvedImport {
            local_name,
            source_file,
            exported_name: package_path.clone(),
            kind,
            specifier: package_path,
            line,
        });
    } else {
        let reason = if is_go_stdlib(&package_path) || is_external_go_package(&package_path) {
            UnresolvedReason::ExternalPackage
        } else {
            UnresolvedReason::FileNotFound
        };

        file_imports.unresolved.push(UnresolvedImport {
            specifier: package_path,
            local_name,
            line,
            reason,
        });
    }
}

/// Try to resolve a Go import path
fn resolve_go_import(import_path: &str, file_path: &Path, project_root: &Path) -> Option<PathBuf> {
    // Check if it's a relative import
    if import_path.starts_with("./") || import_path.starts_with("../") {
        let from_dir = file_path.parent()?;
        let target_dir = from_dir.join(import_path);
        if target_dir.is_dir() {
            // Return first .go file in directory (package directory)
            return find_go_file_in_dir(&target_dir);
        }
        return None;
    }

    // Try to resolve from project root
    // Look for go.mod to find module path
    let module_path = find_go_module_path(project_root);

    if let Some(mod_path) = module_path
        && import_path.starts_with(&mod_path)
    {
        // Internal package
        let relative = import_path.strip_prefix(&mod_path)?;
        let relative = relative.trim_start_matches('/');
        let target_dir = project_root.join(relative);
        if target_dir.is_dir() {
            return find_go_file_in_dir(&target_dir);
        }
    }

    None
}

/// Find the first .go file in a directory
fn find_go_file_in_dir(dir: &Path) -> Option<PathBuf> {
    if !dir.is_dir() {
        return None;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "go") {
                // Skip test files
                if !path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("_test.go"))
                {
                    return Some(path.canonicalize().unwrap_or(path));
                }
            }
        }
    }

    None
}

/// Find the Go module path from go.mod
fn find_go_module_path(project_root: &Path) -> Option<String> {
    let go_mod = project_root.join("go.mod");
    if !go_mod.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&go_mod).ok()?;
    for line in content.lines() {
        if line.starts_with("module ") {
            return Some(line.strip_prefix("module ")?.trim().to_string());
        }
    }

    None
}

/// Check if a path is a Go standard library package
fn is_go_stdlib(path: &str) -> bool {
    let stdlib_prefixes = [
        "archive/",
        "bufio",
        "bytes",
        "compress/",
        "container/",
        "context",
        "crypto/",
        "database/",
        "debug/",
        "embed",
        "encoding/",
        "errors",
        "expvar",
        "flag",
        "fmt",
        "go/",
        "hash/",
        "html/",
        "image/",
        "index/",
        "io",
        "log",
        "maps",
        "math/",
        "mime/",
        "net/",
        "os",
        "path",
        "plugin",
        "reflect",
        "regexp",
        "runtime",
        "slices",
        "sort",
        "strconv",
        "strings",
        "sync",
        "syscall",
        "testing",
        "text/",
        "time",
        "unicode",
        "unsafe",
    ];

    // Simple packages without /
    let simple_stdlib = [
        "bufio", "bytes", "context", "embed", "errors", "expvar", "flag", "fmt", "io", "log",
        "maps", "os", "path", "plugin", "reflect", "regexp", "runtime", "slices", "sort",
        "strconv", "strings", "sync", "syscall", "testing", "time", "unicode", "unsafe",
    ];

    if simple_stdlib.contains(&path) {
        return true;
    }

    stdlib_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Check if a path is an external Go package (not stdlib, not local)
fn is_external_go_package(path: &str) -> bool {
    // External packages typically have a domain in the path
    path.contains('.') || path.contains("github.com") || path.contains("golang.org")
}

/// Extract function export (Go exports are uppercase)
fn extract_function_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        // Go exports start with uppercase
        if name.chars().next().is_some_and(|c| c.is_uppercase()) {
            file_imports.exports.push(Export {
                name: name.to_string(),
                is_default: false,
                node_id: node.id(),
                line: node.start_position().row + 1,
                kind: ExportKind::Function,
            });
        }
    }
}

/// Extract method export
fn extract_method_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
        && name.chars().next().is_some_and(|c| c.is_uppercase())
    {
        file_imports.exports.push(Export {
            name: name.to_string(),
            is_default: false,
            node_id: node.id(),
            line: node.start_position().row + 1,
            kind: ExportKind::Function,
        });
    }
}

/// Extract type export
fn extract_type_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_spec"
            && let Some(name_node) = child.child_by_field_name("name")
            && let Ok(name) = name_node.utf8_text(source)
            && name.chars().next().is_some_and(|c| c.is_uppercase())
        {
            file_imports.exports.push(Export {
                name: name.to_string(),
                is_default: false,
                node_id: child.id(),
                line: child.start_position().row + 1,
                kind: ExportKind::Type,
            });
        }
    }
}

/// Extract var/const export
fn extract_var_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if (child.kind() == "var_spec" || child.kind() == "const_spec")
            && let Some(name_node) = child.child_by_field_name("name")
            && let Ok(name) = name_node.utf8_text(source)
            && name.chars().next().is_some_and(|c| c.is_uppercase())
        {
            file_imports.exports.push(Export {
                name: name.to_string(),
                is_default: false,
                node_id: child.id(),
                line: child.start_position().row + 1,
                kind: ExportKind::Variable,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_go(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn test_simple_import() {
        let code = r#"
package main

import "fmt"
"#;
        let tree = parse_go(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/main.go"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 1);
        assert_eq!(imports.unresolved[0].specifier, "fmt");
        assert_eq!(imports.unresolved[0].local_name, "fmt");
    }

    #[test]
    fn test_aliased_import() {
        let code = r#"
package main

import f "fmt"
"#;
        let tree = parse_go(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/main.go"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 1);
        assert_eq!(imports.unresolved[0].local_name, "f");
    }

    #[test]
    fn test_grouped_imports() {
        let code = r#"
package main

import (
    "fmt"
    "os"
)
"#;
        let tree = parse_go(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/main.go"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 2);
    }

    #[test]
    fn test_exported_function() {
        let code = r#"
package main

func PublicFunc() {}
func privateFunc() {}
"#;
        let tree = parse_go(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/main.go"),
            Path::new("/project"),
        );

        assert_eq!(imports.exports.len(), 1);
        assert_eq!(imports.exports[0].name, "PublicFunc");
    }

    #[test]
    fn test_exported_type() {
        let code = r#"
package main

type PublicStruct struct {
    Field string
}

type privateStruct struct {}
"#;
        let tree = parse_go(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/main.go"),
            Path::new("/project"),
        );

        assert_eq!(imports.exports.len(), 1);
        assert_eq!(imports.exports[0].name, "PublicStruct");
    }

    #[test]
    fn test_is_go_stdlib() {
        assert!(is_go_stdlib("fmt"));
        assert!(is_go_stdlib("os"));
        assert!(is_go_stdlib("net/http"));
        assert!(is_go_stdlib("crypto/sha256"));
        assert!(!is_go_stdlib("github.com/user/repo"));
    }
}
