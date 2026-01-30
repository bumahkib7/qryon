//! File system watcher for incremental updates

use anyhow::Result;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use tracing::{debug, info};

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

/// Start watching a directory for changes
pub fn watch_directory(
    path: &Path,
) -> Result<(RecommendedWatcher, mpsc::Receiver<FileEvent>)> {
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

                    let _ = watcher_tx.send(FileEvent {
                        path,
                        kind,
                    });
                }
            }
        },
        Config::default(),
    )?;

    watcher.watch(path, RecursiveMode::Recursive)?;
    info!("Started watching {:?}", path);

    Ok((watcher, rx))
}

/// Filter events to only include supported source files
pub fn filter_source_events(events: Vec<FileEvent>) -> Vec<FileEvent> {
    let extensions = ["rs", "js", "ts", "tsx", "py", "go", "java"];

    events
        .into_iter()
        .filter(|e| {
            e.path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| extensions.contains(&ext))
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_source_events() {
        let events = vec![
            FileEvent {
                path: "test.rs".into(),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: "test.txt".into(),
                kind: FileEventKind::Modified,
            },
            FileEvent {
                path: "test.py".into(),
                kind: FileEventKind::Created,
            },
        ];

        let filtered = filter_source_events(events);
        assert_eq!(filtered.len(), 2);
    }
}
