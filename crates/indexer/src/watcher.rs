//! File system watcher for incremental updates
//!
//! Provides file watching functionality with intelligent filtering:
//! - Only watches source files (.js, .ts, .py, .rs, .go, .java, etc.)
//! - Ignores common non-source directories (node_modules, target, .git, etc.)
//! - Supports debounced event coalescing for rapid file saves

use anyhow::Result;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use tracing::{debug, info};

/// Supported source file extensions for watch mode
pub const SOURCE_EXTENSIONS: &[&str] = &[
    "rs",   // Rust
    "js",   // JavaScript
    "jsx",  // JavaScript (React)
    "ts",   // TypeScript
    "tsx",  // TypeScript (React)
    "py",   // Python
    "go",   // Go
    "java", // Java
];

/// Directories that should always be ignored during watch
pub const IGNORED_DIRECTORIES: &[&str] = &[
    "node_modules",
    "target",
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    "vendor",
    "venv",
    ".venv",
    "coverage",
    ".nyc_output",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
];

/// File system event
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub path: std::path::PathBuf,
    pub kind: FileEventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEventKind {
    Created,
    Modified,
    Deleted,
}

/// Check if a file path points to a supported source file
///
/// Returns true if the file has a recognized source code extension
/// (e.g., .rs, .js, .ts, .py, .go, .java)
///
/// # Examples
///
/// ```
/// use rma_indexer::watcher::is_source_file;
/// use std::path::Path;
///
/// assert!(is_source_file(Path::new("main.rs")));
/// assert!(is_source_file(Path::new("app.tsx")));
/// assert!(!is_source_file(Path::new("README.md")));
/// assert!(!is_source_file(Path::new("package.json")));
/// ```
pub fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| SOURCE_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

/// Check if a path should be ignored during watch mode
///
/// Returns true if the path contains any ignored directory component
/// (e.g., node_modules, target, .git, __pycache__)
///
/// # Examples
///
/// ```
/// use rma_indexer::watcher::is_ignored_path;
/// use std::path::Path;
///
/// assert!(is_ignored_path(Path::new("project/node_modules/lodash/index.js")));
/// assert!(is_ignored_path(Path::new("crate/target/debug/main")));
/// assert!(is_ignored_path(Path::new(".git/config")));
/// assert!(!is_ignored_path(Path::new("src/main.rs")));
/// ```
pub fn is_ignored_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Check if any component of the path is an ignored directory
    for component in path.components() {
        if let std::path::Component::Normal(name) = component
            && let Some(name_str) = name.to_str()
        {
            // Check exact matches with ignored directories
            if IGNORED_DIRECTORIES.contains(&name_str) {
                return true;
            }
            // Also ignore hidden directories (starting with .)
            if name_str.starts_with('.') && name_str.len() > 1 {
                return true;
            }
        }
    }

    // Also check common patterns in path string for cross-platform support
    let patterns = [
        "/node_modules/",
        "/target/",
        "/__pycache__/",
        "/.git/",
        "/dist/",
        "/build/",
        "/vendor/",
        "/venv/",
    ];

    for pattern in patterns {
        if path_str.contains(pattern) {
            return true;
        }
    }

    false
}

/// Start watching a directory for changes
pub fn watch_directory(path: &Path) -> Result<(RecommendedWatcher, mpsc::Receiver<FileEvent>)> {
    let (tx, rx) = mpsc::channel();

    let watcher_tx = tx.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                for path in event.paths {
                    let kind = match event.kind {
                        notify::EventKind::Create(_) => FileEventKind::Created,
                        notify::EventKind::Modify(_) => FileEventKind::Modified,
                        notify::EventKind::Remove(_) => FileEventKind::Deleted,
                        _ => continue,
                    };

                    debug!("File event: {:?} {:?}", kind, path);

                    let _ = watcher_tx.send(FileEvent { path, kind });
                }
            }
        },
        Config::default(),
    )?;

    watcher.watch(path, RecursiveMode::Recursive)?;
    info!("Started watching {:?}", path);

    Ok((watcher, rx))
}

/// Filter events to only include supported source files that are not in ignored paths
pub fn filter_source_events(events: Vec<FileEvent>) -> Vec<FileEvent> {
    events
        .into_iter()
        .filter(|e| is_source_file(&e.path) && !is_ignored_path(&e.path))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // =========================================================================
    // is_source_file() tests
    // =========================================================================

    #[test]
    fn test_is_source_file_rust() {
        assert!(is_source_file(Path::new("main.rs")));
        assert!(is_source_file(Path::new("src/lib.rs")));
        assert!(is_source_file(Path::new("/absolute/path/to/file.rs")));
    }

    #[test]
    fn test_is_source_file_javascript() {
        assert!(is_source_file(Path::new("index.js")));
        assert!(is_source_file(Path::new("component.jsx")));
        // Note: .mjs is NOT in our supported list (it's ES module syntax)
        assert!(!is_source_file(Path::new("app.mjs")));
    }

    #[test]
    fn test_is_source_file_typescript() {
        assert!(is_source_file(Path::new("index.ts")));
        assert!(is_source_file(Path::new("component.tsx")));
        assert!(is_source_file(Path::new("src/utils/helper.ts")));
    }

    #[test]
    fn test_is_source_file_python() {
        assert!(is_source_file(Path::new("main.py")));
        assert!(is_source_file(Path::new("tests/test_main.py")));
    }

    #[test]
    fn test_is_source_file_go() {
        assert!(is_source_file(Path::new("main.go")));
        assert!(is_source_file(Path::new("pkg/server/server.go")));
    }

    #[test]
    fn test_is_source_file_java() {
        assert!(is_source_file(Path::new("Main.java")));
        assert!(is_source_file(Path::new("src/main/java/App.java")));
    }

    #[test]
    fn test_is_source_file_non_source() {
        assert!(!is_source_file(Path::new("README.md")));
        assert!(!is_source_file(Path::new("package.json")));
        assert!(!is_source_file(Path::new("Cargo.toml")));
        assert!(!is_source_file(Path::new(".gitignore")));
        assert!(!is_source_file(Path::new("image.png")));
        assert!(!is_source_file(Path::new("style.css")));
        assert!(!is_source_file(Path::new("config.yaml")));
        assert!(!is_source_file(Path::new("data.xml")));
    }

    #[test]
    fn test_is_source_file_no_extension() {
        assert!(!is_source_file(Path::new("Makefile")));
        assert!(!is_source_file(Path::new("Dockerfile")));
        assert!(!is_source_file(Path::new("LICENSE")));
    }

    #[test]
    fn test_is_source_file_case_insensitive() {
        // Extensions should be case-insensitive
        assert!(is_source_file(Path::new("main.RS")));
        assert!(is_source_file(Path::new("app.Js")));
        assert!(is_source_file(Path::new("module.PY")));
    }

    // =========================================================================
    // is_ignored_path() tests
    // =========================================================================

    #[test]
    fn test_is_ignored_path_node_modules() {
        assert!(is_ignored_path(Path::new("node_modules/lodash/index.js")));
        assert!(is_ignored_path(Path::new(
            "project/node_modules/express/lib/router.js"
        )));
        assert!(is_ignored_path(Path::new(
            "/absolute/path/node_modules/pkg/file.ts"
        )));
    }

    #[test]
    fn test_is_ignored_path_rust_target() {
        assert!(is_ignored_path(Path::new("target/debug/deps/main.rs")));
        assert!(is_ignored_path(Path::new("target/release/build/lib.rs")));
        assert!(is_ignored_path(Path::new("crate/target/doc/index.html")));
    }

    #[test]
    fn test_is_ignored_path_python_cache() {
        assert!(is_ignored_path(Path::new(
            "__pycache__/module.cpython-39.pyc"
        )));
        assert!(is_ignored_path(Path::new("src/__pycache__/utils.py")));
        assert!(is_ignored_path(Path::new(".pytest_cache/v/cache/file")));
        assert!(is_ignored_path(Path::new(
            ".mypy_cache/3.9/module.meta.json"
        )));
    }

    #[test]
    fn test_is_ignored_path_git() {
        assert!(is_ignored_path(Path::new(".git/config")));
        assert!(is_ignored_path(Path::new(".git/objects/pack/file")));
        assert!(is_ignored_path(Path::new("project/.git/HEAD")));
    }

    #[test]
    fn test_is_ignored_path_build_directories() {
        assert!(is_ignored_path(Path::new("dist/bundle.js")));
        assert!(is_ignored_path(Path::new("build/output/main.js")));
        assert!(is_ignored_path(Path::new("out/compiled/app.js")));
    }

    #[test]
    fn test_is_ignored_path_virtual_envs() {
        assert!(is_ignored_path(Path::new("venv/lib/python3.9/site.py")));
        // .venv is caught by hidden directory check (starts with .)
        assert!(is_ignored_path(Path::new(".venv/bin/activate")));
        // Note: "env" is intentionally NOT ignored - it's too common a name
        // Users should name their virtualenvs "venv" or ".venv"
        assert!(!is_ignored_path(Path::new("env/lib/python/module.py")));
    }

    #[test]
    fn test_is_ignored_path_vendor() {
        assert!(is_ignored_path(Path::new("vendor/github.com/pkg/file.go")));
        assert!(is_ignored_path(Path::new("project/vendor/deps/lib.go")));
    }

    #[test]
    fn test_is_ignored_path_hidden_directories() {
        assert!(is_ignored_path(Path::new(".hidden/file.rs")));
        assert!(is_ignored_path(Path::new(".cache/data")));
        assert!(is_ignored_path(Path::new("project/.idea/config.xml")));
        assert!(is_ignored_path(Path::new(".vscode/settings.json")));
    }

    #[test]
    fn test_is_ignored_path_not_ignored() {
        assert!(!is_ignored_path(Path::new("src/main.rs")));
        assert!(!is_ignored_path(Path::new("lib/utils.js")));
        assert!(!is_ignored_path(Path::new("tests/test_main.py")));
        assert!(!is_ignored_path(Path::new("pkg/server/main.go")));
        assert!(!is_ignored_path(Path::new(
            "src/main/java/com/example/App.java"
        )));
    }

    #[test]
    fn test_is_ignored_path_similar_names() {
        // These should NOT be ignored - they're similar but not exact matches
        assert!(!is_ignored_path(Path::new("src/target_config.rs")));
        assert!(!is_ignored_path(Path::new("lib/node_modules_utils.js")));
        assert!(!is_ignored_path(Path::new("my_vendor_code/lib.go")));
    }

    // =========================================================================
    // filter_source_events() tests
    // =========================================================================

    #[test]
    fn test_filter_source_events_basic() {
        let events = vec![
            FileEvent {
                path: PathBuf::from("test.rs"),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: PathBuf::from("test.txt"),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: PathBuf::from("test.py"),
                kind: FileEventKind::Created,
            },
        ];

        let filtered = filter_source_events(events);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|e| e.path == PathBuf::from("test.rs")));
        assert!(filtered.iter().any(|e| e.path == PathBuf::from("test.py")));
    }

    #[test]
    fn test_filter_source_events_ignores_node_modules() {
        let events = vec![
            FileEvent {
                path: PathBuf::from("src/main.js"),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: PathBuf::from("node_modules/lodash/index.js"),
                kind: FileEventKind::Modified,
            },
        ];

        let filtered = filter_source_events(events);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, PathBuf::from("src/main.js"));
    }

    #[test]
    fn test_filter_source_events_ignores_target() {
        let events = vec![
            FileEvent {
                path: PathBuf::from("src/lib.rs"),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: PathBuf::from("target/debug/deps/lib.rs"),
                kind: FileEventKind::Modified,
            },
        ];

        let filtered = filter_source_events(events);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, PathBuf::from("src/lib.rs"));
    }

    #[test]
    fn test_filter_source_events_preserves_event_kind() {
        let events = vec![
            FileEvent {
                path: PathBuf::from("created.rs"),
                kind: FileEventKind::Created,
            },
            FileEvent {
                path: PathBuf::from("modified.rs"),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: PathBuf::from("deleted.rs"),
                kind: FileEventKind::Deleted,
            },
        ];

        let filtered = filter_source_events(events);
        assert_eq!(filtered.len(), 3);
        assert!(filtered.iter().any(|e| e.kind == FileEventKind::Created));
        assert!(filtered.iter().any(|e| e.kind == FileEventKind::Modified));
        assert!(filtered.iter().any(|e| e.kind == FileEventKind::Deleted));
    }

    #[test]
    fn test_filter_source_events_empty_input() {
        let events: Vec<FileEvent> = vec![];
        let filtered = filter_source_events(events);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_source_events_all_filtered() {
        let events = vec![
            FileEvent {
                path: PathBuf::from("README.md"),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: PathBuf::from("node_modules/pkg/index.js"),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: PathBuf::from("Cargo.toml"),
                kind: FileEventKind::Modified,
            },
        ];

        let filtered = filter_source_events(events);
        assert!(filtered.is_empty());
    }
}
