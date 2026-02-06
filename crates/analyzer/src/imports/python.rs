//! Python import resolution
//!
//! Handles:
//! - from module import name, name2
//! - from module import name as alias
//! - import module
//! - import module as alias
//! - from . import relative
//! - from ..parent import something

use super::{
    Export, ExportKind, FileImports, ImportKind, ResolvedImport, UnresolvedImport,
    UnresolvedReason, is_external_package,
};
use std::path::{Path, PathBuf};

/// Python file extensions to try when resolving imports
const PY_EXTENSIONS: &[&str] = &["py", "pyi"];

/// Extract imports and exports from a Python file
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
        "import_statement" => {
            extract_import_statement(node, source, file_path, project_root, file_imports);
        }
        "import_from_statement" => {
            extract_from_import(node, source, file_path, project_root, file_imports);
        }
        "function_definition" => {
            // Check if this is a module-level function (potential export)
            if is_module_level(node) {
                extract_function_export(node, source, file_imports);
            }
        }
        "class_definition" => {
            if is_module_level(node) {
                extract_class_export(node, source, file_imports);
            }
        }
        "assignment" => {
            // Module-level assignments are exports
            if is_module_level(node) {
                extract_variable_export(node, source, file_imports);
            }
        }
        _ => {}
    }

    // Recurse into children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_imports_recursive(child, source, file_path, project_root, file_imports);
    }
}

/// Check if a node is at module level (not nested in function/class)
fn is_module_level(node: tree_sitter::Node) -> bool {
    let mut parent = node.parent();
    while let Some(p) = parent {
        match p.kind() {
            "function_definition" | "class_definition" => return false,
            "module" => return true,
            _ => parent = p.parent(),
        }
    }
    true
}

/// Extract `import module` or `import module as alias`
fn extract_import_statement(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let line = node.start_position().row + 1;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                if let Ok(module_name) = child.utf8_text(source) {
                    add_python_import(
                        file_imports,
                        module_name,
                        module_name,
                        module_name,
                        line,
                        ImportKind::Namespace,
                        file_path,
                        project_root,
                    );
                }
            }
            "aliased_import" => {
                let name_node = child.child_by_field_name("name");
                let alias_node = child.child_by_field_name("alias");

                if let Some(name) = name_node
                    && let Ok(module_name) = name.utf8_text(source)
                {
                    let local_name = alias_node
                        .and_then(|a| a.utf8_text(source).ok())
                        .unwrap_or(module_name);

                    add_python_import(
                        file_imports,
                        local_name,
                        module_name,
                        module_name,
                        line,
                        ImportKind::Namespace,
                        file_path,
                        project_root,
                    );
                }
            }
            _ => {}
        }
    }
}

/// Extract `from module import name` statements
fn extract_from_import(
    node: tree_sitter::Node,
    source: &[u8],
    file_path: &Path,
    project_root: &Path,
    file_imports: &mut FileImports,
) {
    let line = node.start_position().row + 1;

    // Get the module name
    let module_node = node.child_by_field_name("module_name");
    let module_name = module_node
        .and_then(|n| n.utf8_text(source).ok())
        .unwrap_or("");

    // Check for relative import dots
    let mut relative_level = 0;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "relative_import" {
            let text = child.utf8_text(source).unwrap_or("");
            relative_level = text.chars().filter(|c| *c == '.').count();
        }
    }

    let full_specifier = if relative_level > 0 {
        let dots: String = ".".repeat(relative_level);
        if module_name.is_empty() {
            dots
        } else {
            format!("{}{}", dots, module_name)
        }
    } else {
        module_name.to_string()
    };

    // Get the imported names
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "dotted_name" | "identifier" => {
                // Skip if this is the module name
                if Some(child) == module_node {
                    continue;
                }
                if let Ok(name) = child.utf8_text(source) {
                    add_python_import(
                        file_imports,
                        name,
                        name,
                        &full_specifier,
                        line,
                        ImportKind::Named,
                        file_path,
                        project_root,
                    );
                }
            }
            "aliased_import" => {
                let name_node = child.child_by_field_name("name");
                let alias_node = child.child_by_field_name("alias");

                if let Some(name) = name_node
                    && let Ok(exported_name) = name.utf8_text(source)
                {
                    let local_name = alias_node
                        .and_then(|a| a.utf8_text(source).ok())
                        .unwrap_or(exported_name);

                    add_python_import(
                        file_imports,
                        local_name,
                        exported_name,
                        &full_specifier,
                        line,
                        ImportKind::Named,
                        file_path,
                        project_root,
                    );
                }
            }
            "wildcard_import" => {
                // from module import *
                add_python_import(
                    file_imports,
                    "*",
                    "*",
                    &full_specifier,
                    line,
                    ImportKind::Namespace,
                    file_path,
                    project_root,
                );
            }
            _ => {}
        }
    }
}

/// Add a Python import, resolving it if possible
#[allow(clippy::too_many_arguments)]
fn add_python_import(
    file_imports: &mut FileImports,
    local_name: &str,
    exported_name: &str,
    specifier: &str,
    line: usize,
    kind: ImportKind,
    file_path: &Path,
    project_root: &Path,
) {
    // Try to resolve the import
    let resolved = resolve_python_import(specifier, file_path, project_root);

    if let Some(path) = resolved {
        file_imports.imports.push(ResolvedImport {
            local_name: local_name.to_string(),
            source_file: path,
            exported_name: exported_name.to_string(),
            kind,
            specifier: specifier.to_string(),
            line,
        });
    } else {
        let reason = if is_external_package(specifier)
            || is_python_stdlib(specifier)
            || !specifier.starts_with('.')
        {
            UnresolvedReason::ExternalPackage
        } else {
            UnresolvedReason::FileNotFound
        };

        file_imports.unresolved.push(UnresolvedImport {
            specifier: specifier.to_string(),
            local_name: local_name.to_string(),
            line,
            reason,
        });
    }
}

/// Try to resolve a Python import to a file path
fn resolve_python_import(
    specifier: &str,
    from_file: &Path,
    project_root: &Path,
) -> Option<PathBuf> {
    // Handle relative imports
    if specifier.starts_with('.') {
        let from_dir = from_file.parent()?;
        let dots = specifier.chars().take_while(|c| *c == '.').count();
        let module_part = &specifier[dots..];

        // Go up directories based on dots
        let mut base_dir = from_dir.to_path_buf();
        for _ in 1..dots {
            base_dir = base_dir.parent()?.to_path_buf();
        }

        // Convert module path to file path
        let module_path = module_part.replace('.', "/");
        let base_path = if module_path.is_empty() {
            base_dir
        } else {
            base_dir.join(&module_path)
        };

        return try_python_file_resolution(&base_path);
    }

    // Absolute imports - try from project root
    let module_path = specifier.replace('.', "/");
    let base_path = project_root.join(&module_path);

    try_python_file_resolution(&base_path)
}

/// Try to resolve a path to a Python file
fn try_python_file_resolution(base_path: &Path) -> Option<PathBuf> {
    // Try exact path first
    if base_path.exists() && base_path.is_file() {
        return Some(
            base_path
                .canonicalize()
                .unwrap_or_else(|_| base_path.to_path_buf()),
        );
    }

    // Try with extensions
    for ext in PY_EXTENSIONS {
        let with_ext = base_path.with_extension(ext);
        if with_ext.exists() && with_ext.is_file() {
            return Some(with_ext.canonicalize().unwrap_or(with_ext));
        }
    }

    // Try as package (__init__.py)
    if base_path.is_dir() {
        for ext in PY_EXTENSIONS {
            let init_file = base_path.join(format!("__init__.{}", ext));
            if init_file.exists() {
                return Some(init_file.canonicalize().unwrap_or(init_file));
            }
        }
    }

    None
}

/// Check if a module is part of Python standard library
fn is_python_stdlib(module: &str) -> bool {
    let stdlib_modules = [
        "os",
        "sys",
        "re",
        "json",
        "math",
        "random",
        "datetime",
        "time",
        "collections",
        "itertools",
        "functools",
        "typing",
        "pathlib",
        "subprocess",
        "threading",
        "multiprocessing",
        "asyncio",
        "socket",
        "http",
        "urllib",
        "email",
        "html",
        "xml",
        "logging",
        "unittest",
        "argparse",
        "configparser",
        "io",
        "shelve",
        "sqlite3",
        "csv",
        "hashlib",
        "hmac",
        "secrets",
        "base64",
        "binascii",
        "struct",
        "codecs",
        "abc",
        "contextlib",
        "copy",
        "dataclasses",
        "enum",
        "graphlib",
        "operator",
        "pprint",
        "reprlib",
        "string",
        "textwrap",
        "unicodedata",
        "warnings",
        "weakref",
        "types",
        "inspect",
        "dis",
        "traceback",
        "gc",
        "atexit",
        "builtins",
        "importlib",
        "pkgutil",
        "platform",
        "tempfile",
        "shutil",
        "glob",
        "fnmatch",
        "linecache",
        "uuid",
        "heapq",
        "bisect",
        "array",
        "queue",
        "signal",
    ];

    let first_part = module.split('.').next().unwrap_or(module);
    stdlib_modules.contains(&first_part)
}

/// Extract function export
fn extract_function_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        // Skip private functions (start with _)
        if !name.starts_with('_') || name.starts_with("__") && name.ends_with("__") {
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

/// Extract class export
fn extract_class_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    if let Some(name_node) = node.child_by_field_name("name")
        && let Ok(name) = name_node.utf8_text(source)
    {
        // Skip private classes
        if !name.starts_with('_') {
            file_imports.exports.push(Export {
                name: name.to_string(),
                is_default: false,
                node_id: node.id(),
                line: node.start_position().row + 1,
                kind: ExportKind::Class,
            });
        }
    }
}

/// Extract variable export (module-level assignment)
fn extract_variable_export(node: tree_sitter::Node, source: &[u8], file_imports: &mut FileImports) {
    // Get the left side of assignment
    if let Some(left) = node.child_by_field_name("left")
        && left.kind() == "identifier"
        && let Ok(name) = left.utf8_text(source)
    {
        // Skip private variables and dunder names
        if !name.starts_with('_') {
            // Check for __all__ which defines explicit exports
            file_imports.exports.push(Export {
                name: name.to_string(),
                is_default: false,
                node_id: node.id(),
                line: node.start_position().row + 1,
                kind: ExportKind::Variable,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_python(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn test_import_statement() {
        let code = "import os";
        let tree = parse_python(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/main.py"),
            Path::new("/project"),
        );

        assert_eq!(imports.unresolved.len(), 1);
        assert_eq!(imports.unresolved[0].local_name, "os");
    }

    #[test]
    fn test_from_import() {
        let code = "from typing import List, Dict";
        let tree = parse_python(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/main.py"),
            Path::new("/project"),
        );

        // Both should be unresolved (stdlib)
        assert!(!imports.unresolved.is_empty());
    }

    #[test]
    fn test_function_export() {
        let code = r#"
def public_function():
    pass

def _private_function():
    pass
"#;
        let tree = parse_python(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/utils.py"),
            Path::new("/project"),
        );

        // Only public function should be exported
        assert_eq!(imports.exports.len(), 1);
        assert_eq!(imports.exports[0].name, "public_function");
    }

    #[test]
    fn test_class_export() {
        let code = r#"
class MyClass:
    pass

class _PrivateClass:
    pass
"#;
        let tree = parse_python(code);
        let imports = extract_imports(
            &tree,
            code.as_bytes(),
            Path::new("/project/src/models.py"),
            Path::new("/project"),
        );

        assert_eq!(imports.exports.len(), 1);
        assert_eq!(imports.exports[0].name, "MyClass");
    }

    #[test]
    fn test_is_python_stdlib() {
        assert!(is_python_stdlib("os"));
        assert!(is_python_stdlib("sys"));
        assert!(is_python_stdlib("typing"));
        assert!(is_python_stdlib("collections.abc"));
        assert!(!is_python_stdlib("requests"));
        assert!(!is_python_stdlib("django"));
    }
}
