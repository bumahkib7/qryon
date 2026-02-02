//! Interactive TUI (Terminal User Interface) for RMA findings viewer
//!
//! Provides an interactive terminal interface for browsing and filtering scan results
//! using ratatui and crossterm.

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use rma_analyzer::AnalysisSummary;
use rma_common::{Finding, Severity};
use std::io;

/// Statistics about the scan results
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub total_findings: usize,
    pub critical_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub files_analyzed: usize,
    pub total_loc: usize,
}

impl From<&AnalysisSummary> for ScanStats {
    fn from(summary: &AnalysisSummary) -> Self {
        Self {
            total_findings: summary.total_findings,
            critical_count: summary.critical_count,
            error_count: summary.error_count,
            warning_count: summary.warning_count,
            info_count: summary.info_count,
            files_analyzed: summary.files_analyzed,
            total_loc: summary.total_loc,
        }
    }
}

/// Active panel in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePanel {
    List,
    Detail,
    Filter,
    Help,
}

/// Input mode for the application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Search,
}

/// The main TUI application state
pub struct TuiApp {
    /// All findings from the scan
    findings: Vec<Finding>,
    /// Indices into findings that match current filters
    filtered_findings: Vec<usize>,
    /// Currently selected index in filtered_findings
    selected: usize,
    /// Scroll offset for the list view (reserved for virtual scrolling)
    #[allow(dead_code)]
    scroll_offset: usize,
    /// Severity filter (None = show all)
    filter_severity: Option<Severity>,
    /// Rule ID filter
    filter_rule: Option<String>,
    /// File path filter
    filter_file: Option<String>,
    /// Current search query
    search_query: String,
    /// Whether detail view is expanded
    show_detail: bool,
    /// Scan statistics
    stats: ScanStats,
    /// Currently active panel
    active_panel: ActivePanel,
    /// Input mode
    input_mode: InputMode,
    /// Whether to quit the application
    should_quit: bool,
    /// List state for ratatui
    list_state: ListState,
}

impl TuiApp {
    /// Create a new TUI application with the given findings
    pub fn new(findings: Vec<Finding>, stats: ScanStats) -> Self {
        let filtered_findings: Vec<usize> = (0..findings.len()).collect();
        let mut list_state = ListState::default();
        if !filtered_findings.is_empty() {
            list_state.select(Some(0));
        }

        Self {
            findings,
            filtered_findings,
            selected: 0,
            scroll_offset: 0,
            filter_severity: None,
            filter_rule: None,
            filter_file: None,
            search_query: String::new(),
            show_detail: false,
            stats,
            active_panel: ActivePanel::List,
            input_mode: InputMode::Normal,
            should_quit: false,
            list_state,
        }
    }

    /// Apply all filters and update filtered_findings
    fn apply_filters(&mut self) {
        self.filtered_findings = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                // Severity filter
                if let Some(ref sev) = self.filter_severity {
                    if f.severity != *sev {
                        return false;
                    }
                }

                // Rule filter
                if let Some(ref rule) = self.filter_rule {
                    if !f.rule_id.contains(rule) {
                        return false;
                    }
                }

                // File filter
                if let Some(ref file) = self.filter_file {
                    let path = f.location.file.to_string_lossy();
                    if !path.contains(file) {
                        return false;
                    }
                }

                // Search query
                if !self.search_query.is_empty() {
                    let query = self.search_query.to_lowercase();
                    let matches = f.message.to_lowercase().contains(&query)
                        || f.rule_id.to_lowercase().contains(&query)
                        || f.location
                            .file
                            .to_string_lossy()
                            .to_lowercase()
                            .contains(&query)
                        || f.snippet
                            .as_ref()
                            .map(|s| s.to_lowercase().contains(&query))
                            .unwrap_or(false);
                    if !matches {
                        return false;
                    }
                }

                true
            })
            .map(|(i, _)| i)
            .collect();

        // Reset selection if out of bounds
        if self.selected >= self.filtered_findings.len() {
            self.selected = self.filtered_findings.len().saturating_sub(1);
        }

        // Update list state
        if !self.filtered_findings.is_empty() {
            self.list_state.select(Some(self.selected));
        } else {
            self.list_state.select(None);
        }
    }

    /// Cycle severity filter: None -> Critical -> Error -> Warning -> Info -> None
    fn cycle_severity_filter(&mut self) {
        self.filter_severity = match self.filter_severity {
            None => Some(Severity::Critical),
            Some(Severity::Critical) => Some(Severity::Error),
            Some(Severity::Error) => Some(Severity::Warning),
            Some(Severity::Warning) => Some(Severity::Info),
            Some(Severity::Info) => None,
        };
        self.apply_filters();
    }

    /// Move selection up
    fn select_previous(&mut self) {
        if !self.filtered_findings.is_empty() {
            self.selected = self.selected.saturating_sub(1);
            self.list_state.select(Some(self.selected));
        }
    }

    /// Move selection down
    fn select_next(&mut self) {
        if !self.filtered_findings.is_empty() {
            self.selected = (self.selected + 1).min(self.filtered_findings.len() - 1);
            self.list_state.select(Some(self.selected));
        }
    }

    /// Page up
    fn page_up(&mut self) {
        if !self.filtered_findings.is_empty() {
            self.selected = self.selected.saturating_sub(10);
            self.list_state.select(Some(self.selected));
        }
    }

    /// Page down
    fn page_down(&mut self) {
        if !self.filtered_findings.is_empty() {
            self.selected = (self.selected + 10).min(self.filtered_findings.len() - 1);
            self.list_state.select(Some(self.selected));
        }
    }

    /// Jump to start
    fn select_first(&mut self) {
        if !self.filtered_findings.is_empty() {
            self.selected = 0;
            self.list_state.select(Some(0));
        }
    }

    /// Jump to end
    fn select_last(&mut self) {
        if !self.filtered_findings.is_empty() {
            self.selected = self.filtered_findings.len() - 1;
            self.list_state.select(Some(self.selected));
        }
    }

    /// Get the currently selected finding
    fn selected_finding(&self) -> Option<&Finding> {
        self.filtered_findings
            .get(self.selected)
            .and_then(|&idx| self.findings.get(idx))
    }

    /// Handle keyboard events
    fn handle_key_event(&mut self, key: event::KeyEvent) {
        match self.input_mode {
            InputMode::Normal => self.handle_normal_mode(key),
            InputMode::Search => self.handle_search_mode(key),
        }
    }

    /// Handle keys in normal mode
    fn handle_normal_mode(&mut self, key: event::KeyEvent) {
        match self.active_panel {
            ActivePanel::Help => {
                // Any key closes help
                self.active_panel = ActivePanel::List;
            }
            _ => match key.code {
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Char('?') => self.active_panel = ActivePanel::Help,
                KeyCode::Char('j') | KeyCode::Down => self.select_next(),
                KeyCode::Char('k') | KeyCode::Up => self.select_previous(),
                KeyCode::Char('g') => self.select_first(),
                KeyCode::Char('G') => self.select_last(),
                KeyCode::PageUp => self.page_up(),
                KeyCode::PageDown => self.page_down(),
                KeyCode::Home => self.select_first(),
                KeyCode::End => self.select_last(),
                KeyCode::Enter => self.show_detail = !self.show_detail,
                KeyCode::Char('s') => self.cycle_severity_filter(),
                KeyCode::Char('/') => {
                    self.input_mode = InputMode::Search;
                    self.search_query.clear();
                }
                KeyCode::Char('f') => {
                    self.active_panel = if self.active_panel == ActivePanel::Filter {
                        ActivePanel::List
                    } else {
                        ActivePanel::Filter
                    };
                }
                KeyCode::Tab => {
                    self.active_panel = match self.active_panel {
                        ActivePanel::List => {
                            if self.show_detail {
                                ActivePanel::Detail
                            } else {
                                ActivePanel::List
                            }
                        }
                        ActivePanel::Detail => ActivePanel::List,
                        ActivePanel::Filter => ActivePanel::List,
                        ActivePanel::Help => ActivePanel::List,
                    };
                }
                KeyCode::Esc => {
                    if self.active_panel != ActivePanel::List {
                        self.active_panel = ActivePanel::List;
                    } else if !self.search_query.is_empty() {
                        self.search_query.clear();
                        self.apply_filters();
                    } else if self.filter_severity.is_some()
                        || self.filter_rule.is_some()
                        || self.filter_file.is_some()
                    {
                        // Clear all filters
                        self.filter_severity = None;
                        self.filter_rule = None;
                        self.filter_file = None;
                        self.apply_filters();
                    }
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.should_quit = true;
                }
                KeyCode::Char('r') => {
                    // Clear rule filter
                    self.filter_rule = None;
                    self.apply_filters();
                }
                KeyCode::Char('p') => {
                    // Clear file/path filter
                    self.filter_file = None;
                    self.apply_filters();
                }
                _ => {}
            },
        }
    }

    /// Handle keys in search mode
    fn handle_search_mode(&mut self, key: event::KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
                self.apply_filters();
            }
            KeyCode::Char(c) => {
                self.search_query.push(c);
                self.apply_filters();
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.apply_filters();
            }
            _ => {}
        }
    }

    /// Render the UI
    fn render(&mut self, frame: &mut Frame) {
        let size = frame.area();

        // Main layout: header, filter bar, content, status bar
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(3), // Filter bar
                Constraint::Min(10),   // Content
                Constraint::Length(1), // Status bar
            ])
            .split(size);

        self.render_header(frame, chunks[0]);
        self.render_filter_bar(frame, chunks[1]);
        self.render_content(frame, chunks[2]);
        self.render_status_bar(frame, chunks[3]);

        // Render help overlay if active
        if self.active_panel == ActivePanel::Help {
            self.render_help_overlay(frame, size);
        }
    }

    /// Render the header with stats
    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let stats_text = format!(
            " RMA Scan Results - {} findings ({} critical, {} errors, {} warnings, {} info) | {} files, {} LOC",
            self.stats.total_findings,
            self.stats.critical_count,
            self.stats.error_count,
            self.stats.warning_count,
            self.stats.info_count,
            self.stats.files_analyzed,
            self.stats.total_loc,
        );

        let header = Paragraph::new(stats_text)
            .style(Style::default().fg(Color::Cyan))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" RMA Interactive Viewer ")
                    .title_style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
            );

        frame.render_widget(header, area);
    }

    /// Render the filter bar
    fn render_filter_bar(&self, frame: &mut Frame, area: Rect) {
        let severity_text = match self.filter_severity {
            None => "All".to_string(),
            Some(Severity::Critical) => "Critical".to_string(),
            Some(Severity::Error) => "Error".to_string(),
            Some(Severity::Warning) => "Warning".to_string(),
            Some(Severity::Info) => "Info".to_string(),
        };

        let search_display = if self.input_mode == InputMode::Search {
            format!("{}|", self.search_query)
        } else if self.search_query.is_empty() {
            "_".to_string()
        } else {
            self.search_query.clone()
        };

        let filter_text = Line::from(vec![
            Span::raw(" ["),
            Span::styled("s", Style::default().fg(Color::Yellow)),
            Span::raw("] Severity: "),
            Span::styled(
                severity_text,
                Style::default()
                    .fg(match self.filter_severity {
                        None => Color::Green,
                        Some(Severity::Critical) => Color::Red,
                        Some(Severity::Error) => Color::LightRed,
                        Some(Severity::Warning) => Color::Yellow,
                        Some(Severity::Info) => Color::Blue,
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  ["),
            Span::styled("/", Style::default().fg(Color::Yellow)),
            Span::raw("] Search: "),
            Span::styled(
                search_display,
                if self.input_mode == InputMode::Search {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                },
            ),
            Span::raw(format!(
                "  | Showing {} of {} findings",
                self.filtered_findings.len(),
                self.findings.len()
            )),
        ]);

        let filter_bar =
            Paragraph::new(filter_text).block(Block::default().borders(Borders::ALL).border_style(
                if self.active_panel == ActivePanel::Filter {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ));

        frame.render_widget(filter_bar, area);
    }

    /// Render the main content area
    fn render_content(&mut self, frame: &mut Frame, area: Rect) {
        if self.show_detail {
            // Split into list and detail
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(area);

            self.render_list(frame, chunks[0]);
            self.render_detail(frame, chunks[1]);
        } else {
            // Split into list and preview
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(5), Constraint::Length(6)])
                .split(area);

            self.render_list(frame, chunks[0]);
            self.render_preview(frame, chunks[1]);
        }
    }

    /// Render the findings list
    fn render_list(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .filtered_findings
            .iter()
            .map(|&idx| {
                let finding = &self.findings[idx];
                let severity_style = match finding.severity {
                    Severity::Critical => {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    }
                    Severity::Error => Style::default().fg(Color::LightRed),
                    Severity::Warning => Style::default().fg(Color::Yellow),
                    Severity::Info => Style::default().fg(Color::Blue),
                };

                let file_path = finding.location.file.to_string_lossy();
                // Truncate file path if too long
                let file_display = if file_path.len() > 30 {
                    format!("...{}", &file_path[file_path.len() - 27..])
                } else {
                    file_path.to_string()
                };

                let severity_str = match finding.severity {
                    Severity::Critical => "CRIT",
                    Severity::Error => "ERR ",
                    Severity::Warning => "WARN",
                    Severity::Info => "INFO",
                };

                let line = Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        format!("{:<30}", file_display),
                        Style::default().fg(Color::White),
                    ),
                    Span::raw(":"),
                    Span::styled(
                        format!("{:<5}", finding.location.start_line),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(" | "),
                    Span::styled(
                        format!("{:<25}", truncate_str(&finding.rule_id, 25)),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(" | "),
                    Span::styled(severity_str, severity_style),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(
                        " Findings ({}-{} of {}) ",
                        if self.filtered_findings.is_empty() {
                            0
                        } else {
                            self.selected + 1
                        },
                        self.filtered_findings.len().min(self.selected + 20),
                        self.filtered_findings.len()
                    ))
                    .border_style(if self.active_panel == ActivePanel::List {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    }),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    /// Render the preview panel (when detail is collapsed)
    fn render_preview(&self, frame: &mut Frame, area: Rect) {
        let content = if let Some(finding) = self.selected_finding() {
            let mut lines = vec![Line::from(vec![
                Span::styled("Message: ", Style::default().fg(Color::Yellow)),
                Span::raw(&finding.message),
            ])];

            if let Some(ref suggestion) = finding.suggestion {
                lines.push(Line::from(vec![
                    Span::styled("Suggestion: ", Style::default().fg(Color::Green)),
                    Span::raw(suggestion),
                ]));
            }

            if let Some(ref snippet) = finding.snippet {
                let truncated = truncate_str(snippet.trim(), 100);
                lines.push(Line::from(vec![
                    Span::styled("Code: ", Style::default().fg(Color::Cyan)),
                    Span::styled(truncated, Style::default().fg(Color::DarkGray)),
                ]));
            }

            Text::from(lines)
        } else {
            Text::raw("No finding selected")
        };

        let preview = Paragraph::new(content).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Preview (Enter to expand) ")
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        frame.render_widget(preview, area);
    }

    /// Render the detail panel (when expanded)
    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let content = if let Some(finding) = self.selected_finding() {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(
                        "Rule: ",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&finding.rule_id, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("File: ", Style::default().fg(Color::Yellow)),
                    Span::raw(finding.location.file.to_string_lossy()),
                ]),
                Line::from(vec![
                    Span::styled("Location: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!(
                        "Line {}, Column {}",
                        finding.location.start_line, finding.location.start_column
                    )),
                ]),
                Line::from(vec![
                    Span::styled("Severity: ", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        format!("{:?}", finding.severity),
                        match finding.severity {
                            Severity::Critical => {
                                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                            }
                            Severity::Error => Style::default().fg(Color::LightRed),
                            Severity::Warning => Style::default().fg(Color::Yellow),
                            Severity::Info => Style::default().fg(Color::Blue),
                        },
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Category: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("{:?}", finding.category)),
                ]),
                Line::from(vec![
                    Span::styled("Confidence: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("{:?}", finding.confidence)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "Message:",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(finding.message.clone()),
            ];

            if let Some(ref suggestion) = finding.suggestion {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Suggestion:",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(suggestion.clone()));
            }

            if let Some(ref snippet) = finding.snippet {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Code Snippet:",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
                for line in snippet.lines().take(10) {
                    lines.push(Line::from(Span::styled(
                        format!("  {}", line),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }

            if let Some(ref fix) = finding.fix {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "Suggested Fix:",
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(fix.description.clone()));
                lines.push(Line::from(Span::styled(
                    format!("  Replace with: {}", fix.replacement),
                    Style::default().fg(Color::Green),
                )));
            }

            Text::from(lines)
        } else {
            Text::raw("No finding selected")
        };

        let detail = Paragraph::new(content).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Detail View (Enter to collapse) ")
                .border_style(if self.active_panel == ActivePanel::Detail {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );

        frame.render_widget(detail, area);
    }

    /// Render the status bar
    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let help_text = match self.input_mode {
            InputMode::Search => " Type to search | Enter/Esc: finish search",
            InputMode::Normal => {
                " j/k: navigate | Enter: detail | s: severity | /: search | ?: help | q: quit"
            }
        };

        let status = Paragraph::new(help_text).style(Style::default().fg(Color::DarkGray));

        frame.render_widget(status, area);
    }

    /// Render the help overlay
    fn render_help_overlay(&self, frame: &mut Frame, area: Rect) {
        let help_text = vec![
            Line::from(Span::styled(
                "Keyboard Shortcuts",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  j / Down    ", Style::default().fg(Color::Yellow)),
                Span::raw("Move down"),
            ]),
            Line::from(vec![
                Span::styled("  k / Up      ", Style::default().fg(Color::Yellow)),
                Span::raw("Move up"),
            ]),
            Line::from(vec![
                Span::styled("  g           ", Style::default().fg(Color::Yellow)),
                Span::raw("Jump to first"),
            ]),
            Line::from(vec![
                Span::styled("  G           ", Style::default().fg(Color::Yellow)),
                Span::raw("Jump to last"),
            ]),
            Line::from(vec![
                Span::styled("  PgUp/PgDn   ", Style::default().fg(Color::Yellow)),
                Span::raw("Page up/down"),
            ]),
            Line::from(vec![
                Span::styled("  Enter       ", Style::default().fg(Color::Yellow)),
                Span::raw("Toggle detail view"),
            ]),
            Line::from(vec![
                Span::styled("  Tab         ", Style::default().fg(Color::Yellow)),
                Span::raw("Switch panels"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  s           ", Style::default().fg(Color::Yellow)),
                Span::raw("Cycle severity filter"),
            ]),
            Line::from(vec![
                Span::styled("  /           ", Style::default().fg(Color::Yellow)),
                Span::raw("Search findings"),
            ]),
            Line::from(vec![
                Span::styled("  r           ", Style::default().fg(Color::Yellow)),
                Span::raw("Clear rule filter"),
            ]),
            Line::from(vec![
                Span::styled("  p           ", Style::default().fg(Color::Yellow)),
                Span::raw("Clear file filter"),
            ]),
            Line::from(vec![
                Span::styled("  Esc         ", Style::default().fg(Color::Yellow)),
                Span::raw("Clear filters / Close panel"),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  ?           ", Style::default().fg(Color::Yellow)),
                Span::raw("Show this help"),
            ]),
            Line::from(vec![
                Span::styled("  q           ", Style::default().fg(Color::Yellow)),
                Span::raw("Quit"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Press any key to close",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        // Calculate centered position
        let width = 50;
        let height = help_text.len() as u16 + 2;
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;

        let help_area = Rect::new(x, y, width, height);

        // Clear the area first
        frame.render_widget(Clear, help_area);

        let help = Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help ")
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .border_style(Style::default().fg(Color::Cyan)),
        );

        frame.render_widget(help, help_area);
    }
}

/// Truncate a string to a maximum length
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Run the TUI application
pub fn run(findings: Vec<Finding>, stats: ScanStats) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = TuiApp::new(findings, stats);

    // Run the main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

/// The main application loop
fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
) -> Result<()> {
    loop {
        terminal.draw(|f| app.render(f))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key_event(key);
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

/// Run the TUI from analysis results
pub fn run_from_analysis(
    results: &[rma_analyzer::FileAnalysis],
    summary: &AnalysisSummary,
) -> Result<()> {
    // Collect all findings from results
    let findings: Vec<Finding> = results
        .iter()
        .flat_map(|r| r.findings.iter().cloned())
        .collect();

    let stats = ScanStats::from(summary);

    run(findings, stats)
}
