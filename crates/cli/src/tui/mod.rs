//! Interactive TUI (Terminal User Interface) for RMA findings viewer
//!
//! Provides an interactive terminal interface for browsing and filtering scan results
//! using ratatui and crossterm. Features multiple tabs for different analysis views.

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap},
};
use rma_analyzer::AnalysisSummary;
use rma_analyzer::project::is_test_file;
use rma_common::{CodeMetrics, Confidence, Finding, Language, Severity};
use std::collections::{BTreeSet, HashMap};
use std::io;

/// Cross-file taint flow information for display
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CrossFileFlow {
    pub source_file: String,
    pub source_function: String,
    pub source_line: usize,
    pub target_file: String,
    pub target_function: String,
    pub target_line: usize,
    pub variable: String,
    pub flow_kind: FlowKind,
    pub severity: Severity,
    // --- Rich fields from CrossFileTaint ---
    pub confidence: String,
    pub source_type: String,
    pub sink_type: String,
    pub description: String,
    pub bridge_type: String,
    pub reachability: String,
    pub sink_role: Option<String>,
    pub sink_arg_index: Option<usize>,
    pub sink_callsite_line: Option<usize>,
    pub sink_evidence_detail: String,
    pub sink_evidence_strong: bool,
    pub flow_path: Vec<String>,
}

/// Kind of cross-file data flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    DirectCall,
    EventEmission,
    SharedState,
    Return,
}

impl std::fmt::Display for FlowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowKind::DirectCall => write!(f, "Call"),
            FlowKind::EventEmission => write!(f, "Event"),
            FlowKind::SharedState => write!(f, "State"),
            FlowKind::Return => write!(f, "Return"),
        }
    }
}

/// Explore mode view in call graph
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExploreView {
    Callers,
    Callees,
}

/// Event binding display information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EventBindingDisplay {
    pub event_name: String,
    pub emit_count: usize,
    pub listen_count: usize,
    pub emit_files: Vec<String>,
    pub listen_files: Vec<String>,
}

/// Aggregated metrics for display
#[derive(Debug, Clone, Default)]
pub struct AggregatedMetrics {
    pub total_files: usize,
    pub total_loc: usize,
    pub total_comments: usize,
    pub total_blank: usize,
    pub total_functions: usize,
    pub total_classes: usize,
    pub avg_complexity: f64,
    pub max_complexity: usize,
    pub max_complexity_file: String,
    pub language_breakdown: HashMap<Language, LanguageStats>,
}

/// Per-language statistics
#[derive(Debug, Clone, Default)]
pub struct LanguageStats {
    pub files: usize,
    pub loc: usize,
    pub findings: usize,
    #[allow(dead_code)]
    pub avg_complexity: f64,
}

/// Call graph edge for display
#[derive(Debug, Clone)]
pub struct CallEdgeDisplay {
    pub caller_file: String,
    pub caller_func: String,
    pub caller_line: usize,
    pub callee_file: String,
    pub callee_func: String,
    pub callee_line: usize,
    pub call_site_line: usize,
    pub is_cross_file: bool,
    // Security classifications
    pub caller_is_source: bool,
    pub caller_source_kind: Option<String>,
    pub callee_contains_sinks: bool,
    pub callee_sink_kinds: Vec<String>,
    pub callee_calls_sanitizers: bool,
    pub callee_sanitizes: Vec<String>,
    // Additional metadata
    pub caller_language: String,
    pub callee_language: String,
    pub callee_is_exported: bool,
    pub classification_confidence: f32,
    pub source_sink_path: Vec<String>,
}

/// Call graph statistics for the summary panel
#[derive(Debug, Clone, Default)]
pub struct CallGraphStats {
    pub total_functions: usize,
    pub total_edges: usize,
    pub cross_file_edges: usize,
    pub source_functions: usize,
    pub sink_functions: usize,
    pub sanitizer_functions: usize,
    pub unresolved_calls: usize,
    pub source_to_sink_edges: usize,
    pub files_with_sources: usize,
    pub files_with_sinks: usize,
}

/// Statistics about the scan results
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    #[allow(dead_code)]
    pub total_findings: usize,
    pub critical_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub files_analyzed: usize,
    pub total_loc: usize,
    #[allow(dead_code)]
    pub total_complexity: usize,
    pub suppressed_generated: usize,
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
            total_complexity: summary.total_complexity,
            suppressed_generated: 0,
        }
    }
}

/// Active tab in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Findings,
    CrossFileFlows,
    Metrics,
    CallGraph,
}

impl ActiveTab {
    fn titles() -> Vec<&'static str> {
        vec!["Findings", "Cross-File Flows", "Metrics", "Call Graph"]
    }

    fn index(&self) -> usize {
        match self {
            ActiveTab::Findings => 0,
            ActiveTab::CrossFileFlows => 1,
            ActiveTab::Metrics => 2,
            ActiveTab::CallGraph => 3,
        }
    }

    fn from_index(idx: usize) -> Self {
        match idx {
            0 => ActiveTab::Findings,
            1 => ActiveTab::CrossFileFlows,
            2 => ActiveTab::Metrics,
            3 => ActiveTab::CallGraph,
            _ => ActiveTab::Findings,
        }
    }

    fn next(&self) -> Self {
        Self::from_index((self.index() + 1) % 4)
    }

    fn prev(&self) -> Self {
        Self::from_index((self.index() + 3) % 4)
    }
}

/// Active panel in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
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
    // === Findings Data ===
    findings: Vec<Finding>,
    filtered_findings: Vec<usize>,
    selected_finding: usize,

    // === Cross-File Flows Data ===
    cross_file_flows: Vec<CrossFileFlow>,
    filtered_flows: Vec<usize>,
    selected_flow: usize,

    // === Metrics Data ===
    metrics: AggregatedMetrics,
    file_metrics: Vec<(String, CodeMetrics)>,
    selected_metric_file: usize,

    // === Call Graph Data ===
    call_edges: Vec<CallEdgeDisplay>,
    filtered_edges: Vec<usize>,
    selected_edge: usize,
    call_graph_stats: CallGraphStats,
    filter_source_sink_only: bool,
    event_bindings: Vec<EventBindingDisplay>,

    // === UI State ===
    active_tab: ActiveTab,
    active_panel: ActivePanel,
    input_mode: InputMode,
    should_quit: bool,
    show_detail: bool,
    show_edge_detail: bool,
    show_flow_detail: bool,
    show_event_bindings: bool,

    // === Filters ===
    filter_severity: Option<Severity>,
    filter_subcategory: Option<String>,
    filter_confidence: Option<Confidence>,
    filter_rule: Option<String>,
    filter_file: Option<String>,
    search_query: String,
    // Flow-specific filters
    filter_flow_kind: Option<FlowKind>,
    filter_source_type: Option<String>,
    filter_sink_type: Option<String>,
    // Call graph filters
    filter_cross_file_only: bool,

    // === Explore Mode (Call Graph) ===
    explore_mode: bool,
    explore_function_name: String,
    explore_function_file: String,
    explore_callers: Vec<(String, String, usize)>,
    explore_callees: Vec<(String, String, usize)>,
    explore_selected: usize,
    explore_list_state: ListState,
    explore_view: ExploreView,

    // === Stats ===
    stats: ScanStats,

    // === List States ===
    list_state: ListState,
    flow_list_state: ListState,
    metric_list_state: ListState,
    edge_list_state: ListState,

    // === Scrollbar ===
    #[allow(dead_code)]
    scroll_state: ListState,
}

impl TuiApp {
    /// Create a new TUI application
    pub fn new(
        findings: Vec<Finding>,
        cross_file_flows: Vec<CrossFileFlow>,
        metrics: AggregatedMetrics,
        file_metrics: Vec<(String, CodeMetrics)>,
        call_edges: Vec<CallEdgeDisplay>,
        call_graph_stats: CallGraphStats,
        event_bindings: Vec<EventBindingDisplay>,
        stats: ScanStats,
    ) -> Self {
        let findings_len = findings.len();
        let flows_len = cross_file_flows.len();
        let edges_len = call_edges.len();

        let filtered_findings: Vec<usize> = (0..findings_len).collect();
        let filtered_flows: Vec<usize> = (0..flows_len).collect();
        let filtered_edges: Vec<usize> = (0..edges_len).collect();

        let mut list_state = ListState::default();
        if !filtered_findings.is_empty() {
            list_state.select(Some(0));
        }

        Self {
            findings,
            filtered_findings,
            selected_finding: 0,
            cross_file_flows,
            filtered_flows,
            selected_flow: 0,
            metrics,
            file_metrics,
            selected_metric_file: 0,
            call_edges,
            filtered_edges,
            selected_edge: 0,
            call_graph_stats,
            filter_source_sink_only: false,
            event_bindings,
            active_tab: ActiveTab::Findings,
            active_panel: ActivePanel::List,
            input_mode: InputMode::Normal,
            should_quit: false,
            show_detail: false,
            show_edge_detail: false,
            show_flow_detail: false,
            show_event_bindings: false,
            filter_severity: None,
            filter_subcategory: None,
            filter_confidence: None,
            filter_rule: None,
            filter_file: None,
            search_query: String::new(),
            filter_flow_kind: None,
            filter_source_type: None,
            filter_sink_type: None,
            filter_cross_file_only: false,
            explore_mode: false,
            explore_function_name: String::new(),
            explore_function_file: String::new(),
            explore_callers: Vec::new(),
            explore_callees: Vec::new(),
            explore_selected: 0,
            explore_list_state: ListState::default(),
            explore_view: ExploreView::Callers,
            stats,
            list_state,
            flow_list_state: ListState::default(),
            metric_list_state: ListState::default(),
            edge_list_state: ListState::default(),
            scroll_state: ListState::default(),
        }
    }

    /// Create a simple TUI with just findings (backwards compatible)
    #[allow(dead_code)]
    pub fn from_findings(findings: Vec<Finding>, stats: ScanStats) -> Self {
        Self::new(
            findings,
            Vec::new(),
            AggregatedMetrics::default(),
            Vec::new(),
            Vec::new(),
            CallGraphStats::default(),
            Vec::new(),
            stats,
        )
    }

    /// Apply filters to findings
    fn apply_filters(&mut self) {
        self.filtered_findings = self
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                // Severity filter
                if self.filter_severity.is_some_and(|sev| f.severity != sev) {
                    return false;
                }

                // Subcategory filter
                if let Some(ref subcat) = self.filter_subcategory {
                    let matches = f
                        .subcategory
                        .as_ref()
                        .is_some_and(|sc| sc.iter().any(|s| s == subcat));
                    if !matches {
                        return false;
                    }
                }

                // Confidence filter
                if self
                    .filter_confidence
                    .is_some_and(|conf| f.confidence != conf)
                {
                    return false;
                }

                // Rule filter
                if self
                    .filter_rule
                    .as_ref()
                    .is_some_and(|rule| !f.rule_id.contains(rule))
                {
                    return false;
                }

                // File filter
                if self
                    .filter_file
                    .as_ref()
                    .is_some_and(|file| !f.location.file.to_string_lossy().contains(file))
                {
                    return false;
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
                            .is_some_and(|s| s.to_lowercase().contains(&query));
                    if !matches {
                        return false;
                    }
                }

                true
            })
            .map(|(i, _)| i)
            .collect();

        // Reset selection if out of bounds
        if self.selected_finding >= self.filtered_findings.len() {
            self.selected_finding = self.filtered_findings.len().saturating_sub(1);
        }
        self.list_state.select(Some(self.selected_finding));
    }

    /// Apply filters to cross-file flows
    fn apply_flow_filters(&mut self) {
        self.filtered_flows = self
            .cross_file_flows
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                if self.filter_severity.is_some_and(|sev| f.severity != sev) {
                    return false;
                }
                if self.filter_flow_kind.is_some_and(|kind| f.flow_kind != kind) {
                    return false;
                }
                if let Some(ref src) = self.filter_source_type {
                    if &f.source_type != src {
                        return false;
                    }
                }
                if let Some(ref sink) = self.filter_sink_type {
                    if &f.sink_type != sink {
                        return false;
                    }
                }
                if !self.search_query.is_empty() {
                    let query = self.search_query.to_lowercase();
                    let matches = f.source_file.to_lowercase().contains(&query)
                        || f.target_file.to_lowercase().contains(&query)
                        || f.variable.to_lowercase().contains(&query)
                        || f.source_function.to_lowercase().contains(&query)
                        || f.target_function.to_lowercase().contains(&query)
                        || f.description.to_lowercase().contains(&query)
                        || f.sink_type.to_lowercase().contains(&query)
                        || f.source_type.to_lowercase().contains(&query);
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .map(|(i, _)| i)
            .collect();

        if self.selected_flow >= self.filtered_flows.len() {
            self.selected_flow = self.filtered_flows.len().saturating_sub(1);
        }
        if !self.filtered_flows.is_empty() {
            self.flow_list_state.select(Some(self.selected_flow));
        } else {
            self.flow_list_state.select(None);
        }
    }

    /// Handle keyboard events
    fn handle_key_event(&mut self, key: event::KeyEvent) {
        // Handle Ctrl+C globally
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        // Handle search mode input
        if self.input_mode == InputMode::Search {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => {
                    self.input_mode = InputMode::Normal;
                    self.apply_all_filters();
                }
                KeyCode::Char(c) => {
                    self.search_query.push(c);
                    self.apply_all_filters();
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                    self.apply_all_filters();
                }
                _ => {}
            }
            return;
        }

        // Normal mode key handling
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => {
                self.active_panel = if self.active_panel == ActivePanel::Help {
                    ActivePanel::List
                } else {
                    ActivePanel::Help
                };
            }

            // Tab navigation
            KeyCode::Tab | KeyCode::Right if key.modifiers.is_empty() => {
                self.active_tab = self.active_tab.next();
            }
            KeyCode::BackTab | KeyCode::Left if key.modifiers.is_empty() => {
                self.active_tab = self.active_tab.prev();
            }
            KeyCode::Char('1') => self.active_tab = ActiveTab::Findings,
            KeyCode::Char('2') => self.active_tab = ActiveTab::CrossFileFlows,
            KeyCode::Char('3') => self.active_tab = ActiveTab::Metrics,
            KeyCode::Char('4') => self.active_tab = ActiveTab::CallGraph,

            // List navigation
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_prev(),
            KeyCode::Char('g') => self.select_first(),
            KeyCode::Char('G') => self.select_last(),
            KeyCode::PageDown => {
                for _ in 0..10 {
                    self.select_next();
                }
            }
            KeyCode::PageUp => {
                for _ in 0..10 {
                    self.select_prev();
                }
            }
            KeyCode::Home => self.select_first(),
            KeyCode::End => self.select_last(),

            // View controls
            KeyCode::Enter => match self.active_tab {
                ActiveTab::Findings => self.show_detail = !self.show_detail,
                ActiveTab::CrossFileFlows => self.show_flow_detail = !self.show_flow_detail,
                ActiveTab::CallGraph => {
                    if self.explore_mode {
                        // Drill into selected function in explore mode
                        self.explore_drill_into_selected();
                    } else {
                        self.show_edge_detail = !self.show_edge_detail;
                    }
                }
                _ => {}
            },

            // Filtering
            KeyCode::Char('/') => self.input_mode = InputMode::Search,
            KeyCode::Char('s') => {
                self.filter_severity = match self.filter_severity {
                    None => Some(Severity::Critical),
                    Some(Severity::Critical) => Some(Severity::Error),
                    Some(Severity::Error) => Some(Severity::Warning),
                    Some(Severity::Warning) => Some(Severity::Info),
                    Some(Severity::Info) => None,
                };
                self.apply_all_filters();
            }
            KeyCode::Char('f') => {
                // Cycle subcategory: None → vuln → audit → style → None
                self.filter_subcategory = match self.filter_subcategory.as_deref() {
                    None => Some("vuln".to_string()),
                    Some("vuln") => Some("audit".to_string()),
                    Some("audit") => Some("style".to_string()),
                    _ => None,
                };
                self.apply_all_filters();
            }
            KeyCode::Char('d') => {
                // Cycle confidence: None → High → Medium → Low → None
                self.filter_confidence = match self.filter_confidence {
                    None => Some(Confidence::High),
                    Some(Confidence::High) => Some(Confidence::Medium),
                    Some(Confidence::Medium) => Some(Confidence::Low),
                    Some(Confidence::Low) => None,
                };
                self.apply_all_filters();
            }
            KeyCode::Char('x') => {
                // Toggle source→sink filter (only on CallGraph tab)
                if self.active_tab == ActiveTab::CallGraph {
                    self.filter_source_sink_only = !self.filter_source_sink_only;
                    self.apply_edge_filters();
                }
            }
            // --- Cross-File Flows tab filters ---
            KeyCode::Char('t') => {
                if self.active_tab == ActiveTab::CrossFileFlows {
                    self.filter_flow_kind = match self.filter_flow_kind {
                        None => Some(FlowKind::DirectCall),
                        Some(FlowKind::DirectCall) => Some(FlowKind::EventEmission),
                        Some(FlowKind::EventEmission) => Some(FlowKind::SharedState),
                        Some(FlowKind::SharedState) => Some(FlowKind::Return),
                        Some(FlowKind::Return) => None,
                    };
                    self.apply_flow_filters();
                }
            }
            KeyCode::Char('n') => {
                if self.active_tab == ActiveTab::CrossFileFlows {
                    let source_types: Vec<String> = self
                        .cross_file_flows
                        .iter()
                        .map(|f| f.source_type.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    self.filter_source_type =
                        cycle_filter(&self.filter_source_type, &source_types);
                    self.apply_flow_filters();
                }
            }
            KeyCode::Char('i') => {
                if self.active_tab == ActiveTab::CrossFileFlows {
                    let sink_types: Vec<String> = self
                        .cross_file_flows
                        .iter()
                        .map(|f| f.sink_type.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    self.filter_sink_type = cycle_filter(&self.filter_sink_type, &sink_types);
                    self.apply_flow_filters();
                }
            }
            // --- Call Graph tab keys ---
            KeyCode::Char('w') => {
                if self.active_tab == ActiveTab::CallGraph {
                    self.filter_cross_file_only = !self.filter_cross_file_only;
                    self.apply_edge_filters();
                }
            }
            KeyCode::Char('e') => {
                if self.active_tab == ActiveTab::CallGraph {
                    if self.explore_mode {
                        // Already in explore mode - drill into selected
                        self.explore_drill_into_selected();
                    } else {
                        self.enter_explore_mode();
                    }
                }
            }
            KeyCode::Char('l') => {
                if self.active_tab == ActiveTab::CallGraph && self.explore_mode {
                    self.explore_view = match self.explore_view {
                        ExploreView::Callers => ExploreView::Callees,
                        ExploreView::Callees => ExploreView::Callers,
                    };
                    self.explore_selected = 0;
                    self.explore_list_state.select(Some(0));
                }
            }
            KeyCode::Char('b') => {
                if self.active_tab == ActiveTab::CallGraph {
                    self.show_event_bindings = !self.show_event_bindings;
                }
            }
            KeyCode::Esc => {
                if self.explore_mode {
                    self.explore_mode = false;
                } else if !self.search_query.is_empty() {
                    self.search_query.clear();
                    self.apply_all_filters();
                } else if self.filter_severity.is_some() {
                    self.filter_severity = None;
                    self.apply_all_filters();
                } else if self.filter_subcategory.is_some() {
                    self.filter_subcategory = None;
                    self.apply_all_filters();
                } else if self.filter_confidence.is_some() {
                    self.filter_confidence = None;
                    self.apply_all_filters();
                } else if self.filter_flow_kind.is_some() {
                    self.filter_flow_kind = None;
                    self.apply_flow_filters();
                } else if self.filter_source_type.is_some() {
                    self.filter_source_type = None;
                    self.apply_flow_filters();
                } else if self.filter_sink_type.is_some() {
                    self.filter_sink_type = None;
                    self.apply_flow_filters();
                } else if self.filter_cross_file_only {
                    self.filter_cross_file_only = false;
                    self.apply_edge_filters();
                } else if self.active_panel == ActivePanel::Help {
                    self.active_panel = ActivePanel::List;
                }
            }
            KeyCode::Char('c') => {
                // Clear all filters
                self.search_query.clear();
                self.filter_severity = None;
                self.filter_subcategory = None;
                self.filter_confidence = None;
                self.filter_rule = None;
                self.filter_file = None;
                self.filter_flow_kind = None;
                self.filter_source_type = None;
                self.filter_sink_type = None;
                self.filter_cross_file_only = false;
                self.explore_mode = false;
                self.apply_all_filters();
            }
            _ => {}
        }
    }

    fn apply_all_filters(&mut self) {
        self.apply_filters();
        self.apply_flow_filters();
        self.apply_edge_filters();
    }

    /// Apply filters to call graph edges
    fn apply_edge_filters(&mut self) {
        self.filtered_edges = self
            .call_edges
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                // Source→Sink only filter
                if self.filter_source_sink_only && (!e.caller_is_source || !e.callee_contains_sinks)
                {
                    return false;
                }
                // Cross-file only filter
                if self.filter_cross_file_only && !e.is_cross_file {
                    return false;
                }
                // Search query filter
                if !self.search_query.is_empty() {
                    let query = self.search_query.to_lowercase();
                    let matches = e.caller_func.to_lowercase().contains(&query)
                        || e.callee_func.to_lowercase().contains(&query)
                        || e.caller_file.to_lowercase().contains(&query)
                        || e.callee_file.to_lowercase().contains(&query)
                        || e.callee_sink_kinds
                            .iter()
                            .any(|k| k.to_lowercase().contains(&query))
                        || e.caller_source_kind
                            .as_ref()
                            .is_some_and(|k| k.to_lowercase().contains(&query));
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .map(|(i, _)| i)
            .collect();

        if self.selected_edge >= self.filtered_edges.len() {
            self.selected_edge = self.filtered_edges.len().saturating_sub(1);
        }
        if !self.filtered_edges.is_empty() {
            self.edge_list_state.select(Some(self.selected_edge));
        } else {
            self.edge_list_state.select(None);
        }
    }

    fn select_next(&mut self) {
        match self.active_tab {
            ActiveTab::Findings => {
                if self.selected_finding < self.filtered_findings.len().saturating_sub(1) {
                    self.selected_finding += 1;
                    self.list_state.select(Some(self.selected_finding));
                }
            }
            ActiveTab::CrossFileFlows => {
                if self.selected_flow < self.filtered_flows.len().saturating_sub(1) {
                    self.selected_flow += 1;
                    self.flow_list_state.select(Some(self.selected_flow));
                }
            }
            ActiveTab::Metrics => {
                if self.selected_metric_file < self.file_metrics.len().saturating_sub(1) {
                    self.selected_metric_file += 1;
                    self.metric_list_state
                        .select(Some(self.selected_metric_file));
                }
            }
            ActiveTab::CallGraph => {
                if self.explore_mode {
                    let max = self.explore_current_list_len().saturating_sub(1);
                    if self.explore_selected < max {
                        self.explore_selected += 1;
                        self.explore_list_state.select(Some(self.explore_selected));
                    }
                } else if self.selected_edge < self.filtered_edges.len().saturating_sub(1) {
                    self.selected_edge += 1;
                    self.edge_list_state.select(Some(self.selected_edge));
                }
            }
        }
    }

    fn select_prev(&mut self) {
        match self.active_tab {
            ActiveTab::Findings => {
                if self.selected_finding > 0 {
                    self.selected_finding -= 1;
                    self.list_state.select(Some(self.selected_finding));
                }
            }
            ActiveTab::CrossFileFlows => {
                if self.selected_flow > 0 {
                    self.selected_flow -= 1;
                    self.flow_list_state.select(Some(self.selected_flow));
                }
            }
            ActiveTab::Metrics => {
                if self.selected_metric_file > 0 {
                    self.selected_metric_file -= 1;
                    self.metric_list_state
                        .select(Some(self.selected_metric_file));
                }
            }
            ActiveTab::CallGraph => {
                if self.explore_mode {
                    if self.explore_selected > 0 {
                        self.explore_selected -= 1;
                        self.explore_list_state.select(Some(self.explore_selected));
                    }
                } else if self.selected_edge > 0 {
                    self.selected_edge -= 1;
                    self.edge_list_state.select(Some(self.selected_edge));
                }
            }
        }
    }

    fn select_first(&mut self) {
        match self.active_tab {
            ActiveTab::Findings => {
                self.selected_finding = 0;
                self.list_state.select(Some(0));
            }
            ActiveTab::CrossFileFlows => {
                self.selected_flow = 0;
                self.flow_list_state.select(Some(0));
            }
            ActiveTab::Metrics => {
                self.selected_metric_file = 0;
                self.metric_list_state.select(Some(0));
            }
            ActiveTab::CallGraph => {
                self.selected_edge = 0;
                self.edge_list_state.select(Some(0));
            }
        }
    }

    fn select_last(&mut self) {
        match self.active_tab {
            ActiveTab::Findings => {
                self.selected_finding = self.filtered_findings.len().saturating_sub(1);
                self.list_state.select(Some(self.selected_finding));
            }
            ActiveTab::CrossFileFlows => {
                self.selected_flow = self.filtered_flows.len().saturating_sub(1);
                self.flow_list_state.select(Some(self.selected_flow));
            }
            ActiveTab::Metrics => {
                self.selected_metric_file = self.file_metrics.len().saturating_sub(1);
                self.metric_list_state
                    .select(Some(self.selected_metric_file));
            }
            ActiveTab::CallGraph => {
                self.selected_edge = self.filtered_edges.len().saturating_sub(1);
                self.edge_list_state.select(Some(self.selected_edge));
            }
        }
    }

    // === Explore Mode Helpers ===

    fn explore_current_list_len(&self) -> usize {
        match self.explore_view {
            ExploreView::Callers => self.explore_callers.len(),
            ExploreView::Callees => self.explore_callees.len(),
        }
    }

    fn enter_explore_mode(&mut self) {
        if self.filtered_edges.is_empty() {
            return;
        }
        let edge = &self.call_edges[self.filtered_edges[self.selected_edge]];
        self.populate_explore_for(&edge.callee_func.clone(), &edge.callee_file.clone());
        self.explore_mode = true;
    }

    fn populate_explore_for(&mut self, func_name: &str, func_file: &str) {
        self.explore_function_name = func_name.to_string();
        self.explore_function_file = func_file.to_string();
        self.explore_callers = self
            .call_edges
            .iter()
            .filter(|e| e.callee_func == func_name && e.callee_file == func_file)
            .map(|e| (e.caller_func.clone(), e.caller_file.clone(), e.call_site_line))
            .collect();
        self.explore_callees = self
            .call_edges
            .iter()
            .filter(|e| e.caller_func == func_name && e.caller_file == func_file)
            .map(|e| (e.callee_func.clone(), e.callee_file.clone(), e.callee_line))
            .collect();
        self.explore_selected = 0;
        self.explore_list_state.select(if self.explore_current_list_len() > 0 {
            Some(0)
        } else {
            None
        });
    }

    fn explore_drill_into_selected(&mut self) {
        let list = match self.explore_view {
            ExploreView::Callers => &self.explore_callers,
            ExploreView::Callees => &self.explore_callees,
        };
        if let Some((name, file, _)) = list.get(self.explore_selected) {
            let name = name.clone();
            let file = file.clone();
            self.populate_explore_for(&name, &file);
        }
    }

    /// Render the UI
    fn render(&mut self, frame: &mut Frame) {
        let size = frame.area();

        // Main layout: header with tabs, filter bar, content, status bar
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header with tabs
                Constraint::Length(3), // Stats bar
                Constraint::Min(10),   // Content
                Constraint::Length(1), // Status bar
            ])
            .split(size);

        self.render_header_with_tabs(frame, chunks[0]);
        self.render_stats_bar(frame, chunks[1]);
        self.render_tab_content(frame, chunks[2]);
        self.render_status_bar(frame, chunks[3]);

        // Render help overlay if active
        if self.active_panel == ActivePanel::Help {
            self.render_help_overlay(frame, size);
        }
    }

    /// Render header with tabs
    fn render_header_with_tabs(&self, frame: &mut Frame, area: Rect) {
        let titles: Vec<Line> = ActiveTab::titles()
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let style = if i == self.active_tab.index() {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                Line::from(Span::styled(format!(" {} ", t), style))
            })
            .collect();

        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(Span::styled(
                        " RMA Interactive Analyzer ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )),
            )
            .select(self.active_tab.index())
            .style(Style::default().fg(Color::White))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(Span::raw(" | "));

        frame.render_widget(tabs, area);
    }

    /// Render stats bar
    fn render_stats_bar(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(13),
                Constraint::Percentage(13),
                Constraint::Percentage(13),
                Constraint::Percentage(13),
                Constraint::Percentage(16),
                Constraint::Percentage(16),
                Constraint::Percentage(16),
            ])
            .split(area);

        // Critical count
        let critical = Paragraph::new(format!("{}", self.stats.critical_count))
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .title(" Critical "),
            );
        frame.render_widget(critical, chunks[0]);

        // Error count
        let errors = Paragraph::new(format!("{}", self.stats.error_count))
            .style(Style::default().fg(Color::LightRed))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::LightRed))
                    .title(" Errors "),
            );
        frame.render_widget(errors, chunks[1]);

        // Warning count
        let warnings = Paragraph::new(format!("{}", self.stats.warning_count))
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(" Warnings "),
            );
        frame.render_widget(warnings, chunks[2]);

        // Info count
        let info = Paragraph::new(format!("{}", self.stats.info_count))
            .style(Style::default().fg(Color::Blue))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue))
                    .title(" Info "),
            );
        frame.render_widget(info, chunks[3]);

        // Files analyzed
        let files = Paragraph::new(format!("{} files", self.stats.files_analyzed))
            .style(Style::default().fg(Color::Green))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green))
                    .title(" Analyzed "),
            );
        frame.render_widget(files, chunks[4]);

        // LOC
        let loc = Paragraph::new(format!("{} LOC", self.stats.total_loc))
            .style(Style::default().fg(Color::Magenta))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta))
                    .title(" Lines "),
            );
        frame.render_widget(loc, chunks[5]);

        // Suppressed generated files count
        let suppressed = Paragraph::new(format!("{} hidden", self.stats.suppressed_generated))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(" Generated "),
            );
        frame.render_widget(suppressed, chunks[6]);
    }

    /// Render content based on active tab
    fn render_tab_content(&mut self, frame: &mut Frame, area: Rect) {
        match self.active_tab {
            ActiveTab::Findings => self.render_findings_tab(frame, area),
            ActiveTab::CrossFileFlows => self.render_cross_file_tab(frame, area),
            ActiveTab::Metrics => self.render_metrics_tab(frame, area),
            ActiveTab::CallGraph => self.render_call_graph_tab(frame, area),
        }
    }

    /// Render the Findings tab
    fn render_findings_tab(&mut self, frame: &mut Frame, area: Rect) {
        // Filter bar at top
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(5)])
            .split(area);

        self.render_filter_bar(frame, chunks[0]);

        // Content area
        if self.show_detail {
            let content_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(chunks[1]);
            self.render_findings_list(frame, content_chunks[0]);
            self.render_finding_detail(frame, content_chunks[1]);
        } else {
            let content_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(5), Constraint::Length(8)])
                .split(chunks[1]);
            self.render_findings_list(frame, content_chunks[0]);
            self.render_finding_preview(frame, content_chunks[1]);
        }
    }

    /// Render filter bar
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
            Span::raw("] Sev: "),
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
            Span::styled("f", Style::default().fg(Color::Yellow)),
            Span::raw("] Sub: "),
            Span::styled(
                match self.filter_subcategory.as_deref() {
                    None => "All",
                    Some("vuln") => "Vuln",
                    Some("audit") => "Audit",
                    Some("style") => "Style",
                    _ => "?",
                },
                Style::default()
                    .fg(match self.filter_subcategory.as_deref() {
                        None => Color::Green,
                        Some("vuln") => Color::Red,
                        Some("audit") => Color::Yellow,
                        Some("style") => Color::Cyan,
                        _ => Color::Gray,
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  ["),
            Span::styled("d", Style::default().fg(Color::Yellow)),
            Span::raw("] Conf: "),
            Span::styled(
                match self.filter_confidence {
                    None => "All",
                    Some(Confidence::High) => "High",
                    Some(Confidence::Medium) => "Med",
                    Some(Confidence::Low) => "Low",
                },
                Style::default()
                    .fg(match self.filter_confidence {
                        None => Color::Green,
                        Some(Confidence::High) => Color::Green,
                        Some(Confidence::Medium) => Color::Yellow,
                        Some(Confidence::Low) => Color::Red,
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
            Span::raw("  ["),
            Span::styled("c", Style::default().fg(Color::Yellow)),
            Span::raw("] Clear"),
            Span::raw(format!(
                "  | {} of {}",
                self.filtered_findings.len(),
                self.findings.len()
            )),
        ]);

        let filter_bar = Paragraph::new(filter_text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        frame.render_widget(filter_bar, area);
    }

    /// Render the findings list
    fn render_findings_list(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .filtered_findings
            .iter()
            .enumerate()
            .map(|(list_idx, &idx)| {
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

                let prefix = if list_idx == self.selected_finding {
                    ">> "
                } else {
                    "   "
                };

                let subcat_chip = finding
                    .subcategory
                    .as_ref()
                    .and_then(|sc| sc.first())
                    .map(|s| match s.as_str() {
                        "vuln" => ("[V]", Color::Red),
                        "audit" => ("[A]", Color::Yellow),
                        "style" => ("[S]", Color::Cyan),
                        _ => ("[?]", Color::Gray),
                    });

                let line = Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::Yellow)),
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
                        format!("{:<20}", truncate_str(&finding.rule_id, 20)),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(" | "),
                    Span::styled(severity_str, severity_style),
                    Span::raw(" "),
                    Span::styled(
                        subcat_chip.map(|(t, _)| t).unwrap_or("   "),
                        Style::default()
                            .fg(subcat_chip.map(|(_, c)| c).unwrap_or(Color::DarkGray)),
                    ),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(format!(" Findings ({}) ", self.filtered_findings.len())),
            )
            .highlight_style(Style::default().bg(Color::DarkGray));

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    /// Render finding preview (compact)
    fn render_finding_preview(&self, frame: &mut Frame, area: Rect) {
        if self.filtered_findings.is_empty() {
            let empty = Paragraph::new("No findings to display")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL).title(" Preview "));
            frame.render_widget(empty, area);
            return;
        }

        let finding = &self.findings[self.filtered_findings[self.selected_finding]];

        let mut lines = vec![Line::from(vec![
            Span::styled("Message: ", Style::default().fg(Color::Yellow)),
            Span::raw(truncate_str(&finding.message, 80)),
        ])];

        if let Some(ref suggestion) = finding.suggestion {
            lines.push(Line::from(vec![
                Span::styled("Fix: ", Style::default().fg(Color::Green)),
                Span::raw(truncate_str(suggestion, 80)),
            ]));
        }

        if let Some(ref snippet) = finding.snippet {
            let snippet_line = snippet.lines().next().unwrap_or("").trim();
            lines.push(Line::from(vec![
                Span::styled("Code: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    truncate_str(snippet_line, 70),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }

        let preview = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Preview (Enter to expand) "),
        );

        frame.render_widget(preview, area);
    }

    /// Render finding detail (expanded)
    fn render_finding_detail(&self, frame: &mut Frame, area: Rect) {
        if self.filtered_findings.is_empty() {
            let empty = Paragraph::new("No finding selected")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL).title(" Detail "));
            frame.render_widget(empty, area);
            return;
        }

        let finding = &self.findings[self.filtered_findings[self.selected_finding]];

        let severity_color = match finding.severity {
            Severity::Critical => Color::Red,
            Severity::Error => Color::LightRed,
            Severity::Warning => Color::Yellow,
            Severity::Info => Color::Blue,
        };

        // Confidence color
        let confidence_color = match finding.confidence {
            rma_common::Confidence::High => Color::Green,
            rma_common::Confidence::Medium => Color::Yellow,
            rma_common::Confidence::Low => Color::Red,
        };

        let mut lines = vec![
            // Header section
            Line::from(Span::styled(
                "═══ RULE DETAILS ═══",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled(
                    "Rule ID:     ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&finding.rule_id, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Language:    ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{:?}", finding.language)),
            ]),
            Line::from(vec![
                Span::styled("Severity:    ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    finding.severity.to_string(),
                    Style::default()
                        .fg(severity_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Confidence:  ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    finding.confidence.to_string(),
                    Style::default().fg(confidence_color),
                ),
            ]),
            Line::from(vec![
                Span::styled("Category:    ", Style::default().fg(Color::Cyan)),
                Span::raw(format!("{:?}", finding.category)),
            ]),
        ];

        // Subcategory (if present)
        if let Some(ref subcats) = finding.subcategory {
            lines.push(Line::from(vec![
                Span::styled("Subcategory: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    subcats.join(", "),
                    Style::default()
                        .fg(match subcats.first().map(|s| s.as_str()) {
                            Some("vuln") => Color::Red,
                            Some("audit") => Color::Yellow,
                            Some("style") => Color::Cyan,
                            _ => Color::White,
                        })
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }

        // Technology (if present)
        if let Some(ref tech) = finding.technology {
            lines.push(Line::from(vec![
                Span::styled("Technology:  ", Style::default().fg(Color::Cyan)),
                Span::raw(tech.join(", ")),
            ]));
        }

        // Impact + Likelihood on one line (if either present)
        if finding.impact.is_some() || finding.likelihood.is_some() {
            let mut spans = vec![];
            if let Some(ref impact) = finding.impact {
                spans.push(Span::styled("Impact: ", Style::default().fg(Color::Cyan)));
                spans.push(Span::styled(
                    impact.as_str(),
                    Style::default().fg(match impact.to_uppercase().as_str() {
                        "HIGH" => Color::Red,
                        "MEDIUM" => Color::Yellow,
                        _ => Color::Green,
                    }),
                ));
            }
            if let Some(ref likelihood) = finding.likelihood {
                if !spans.is_empty() {
                    spans.push(Span::raw("  "));
                }
                spans.push(Span::styled(
                    "Likelihood: ",
                    Style::default().fg(Color::Cyan),
                ));
                spans.push(Span::styled(
                    likelihood.as_str(),
                    Style::default().fg(match likelihood.to_uppercase().as_str() {
                        "HIGH" => Color::Red,
                        "MEDIUM" => Color::Yellow,
                        _ => Color::Green,
                    }),
                ));
            }
            lines.push(Line::from(spans));
        }

        // Source engine
        lines.push(Line::from(vec![
            Span::styled("Source:      ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{}", finding.source)),
        ]));

        lines.extend(vec![
            Line::from(""),
            // Location section
            Line::from(Span::styled(
                "═══ LOCATION ═══",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("File:        ", Style::default().fg(Color::Cyan)),
                Span::raw(finding.location.file.to_string_lossy().to_string()),
            ]),
            Line::from(vec![
                Span::styled("Line:        ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{}", finding.location.start_line),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(format!(
                    " (col {} - {}:{})",
                    finding.location.start_column,
                    finding.location.end_line,
                    finding.location.end_column
                )),
            ]),
        ]);

        // Fingerprint (if present)
        if let Some(ref fp) = finding.fingerprint {
            lines.push(Line::from(vec![
                Span::styled("Fingerprint: ", Style::default().fg(Color::Cyan)),
                Span::styled(truncate_str(fp, 40), Style::default().fg(Color::DarkGray)),
            ]));
        }

        // Message section
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "═══ MESSAGE ═══",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
        for msg_line in finding.message.lines() {
            lines.push(Line::from(format!("  {}", msg_line)));
        }

        // Suggestion section
        if let Some(ref suggestion) = finding.suggestion {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "═══ FIX SUGGESTION ═══",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            for sug_line in suggestion.lines() {
                lines.push(Line::from(Span::styled(
                    format!("  {}", sug_line),
                    Style::default().fg(Color::Green),
                )));
            }
        }

        // Code snippet section (full, not truncated)
        if let Some(ref snippet) = finding.snippet {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "═══ CODE SNIPPET ═══",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            for (i, code_line) in snippet.lines().enumerate() {
                let line_num = finding.location.start_line + i;
                let is_target_line = i == 0; // First line is the finding line
                let line_style = if is_target_line {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                let prefix = if is_target_line { ">> " } else { "   " };
                lines.push(Line::from(Span::styled(
                    format!("{}{:4} │ {}", prefix, line_num, code_line),
                    line_style,
                )));
            }
        }

        // Properties section (if present and non-empty)
        if let Some(props) = finding.properties.as_ref().filter(|p| !p.is_empty()) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "═══ PROPERTIES ═══",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            )));
            for (key, value) in props.iter() {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Array(arr) => format!("[{} items]", arr.len()),
                    _ => format!("{}", value),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("  {}: ", key), Style::default().fg(Color::Cyan)),
                    Span::raw(truncate_str(&value_str, 50)),
                ]));
            }
        }

        let detail = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(" Detail (Enter to collapse) "),
            )
            .wrap(Wrap { trim: false });

        frame.render_widget(detail, area);
    }

    /// Render the Cross-File Flows tab
    fn render_cross_file_tab(&mut self, frame: &mut Frame, area: Rect) {
        if self.cross_file_flows.is_empty() {
            let empty = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No cross-file data flows detected",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Cross-file analysis tracks tainted data flowing between files",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  through function calls, event emissions, and shared state.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta))
                    .title(" Cross-File Data Flows "),
            );
            frame.render_widget(empty, area);
            return;
        }

        // Layout: filter bar at top, then content
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(5)])
            .split(area);

        self.render_flow_filter_bar(frame, outer[0]);

        // Content: list only, or list + detail panel
        if self.show_flow_detail {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(outer[1]);
            self.render_flow_list(frame, chunks[0]);
            self.render_flow_detail(frame, chunks[1]);
        } else {
            self.render_flow_list(frame, outer[1]);
        }
    }

    /// Render the flow filter bar
    fn render_flow_filter_bar(&self, frame: &mut Frame, area: Rect) {
        let kind_text = match self.filter_flow_kind {
            None => "All",
            Some(FlowKind::DirectCall) => "Call",
            Some(FlowKind::EventEmission) => "Event",
            Some(FlowKind::SharedState) => "State",
            Some(FlowKind::Return) => "Ret",
        };

        let src_text = self
            .filter_source_type
            .as_deref()
            .unwrap_or("All");
        let sink_text = self
            .filter_sink_type
            .as_deref()
            .unwrap_or("All");

        let search_display = if self.input_mode == InputMode::Search {
            format!("{}|", self.search_query)
        } else if self.search_query.is_empty() {
            "_".to_string()
        } else {
            self.search_query.clone()
        };

        let filter_text = Line::from(vec![
            Span::raw(" ["),
            Span::styled("t", Style::default().fg(Color::Yellow)),
            Span::raw("] Kind: "),
            Span::styled(
                kind_text,
                Style::default()
                    .fg(if self.filter_flow_kind.is_some() {
                        Color::Cyan
                    } else {
                        Color::Green
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  ["),
            Span::styled("n", Style::default().fg(Color::Yellow)),
            Span::raw("] Src: "),
            Span::styled(
                truncate_str(src_text, 12),
                Style::default()
                    .fg(if self.filter_source_type.is_some() {
                        Color::Red
                    } else {
                        Color::Green
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  ["),
            Span::styled("i", Style::default().fg(Color::Yellow)),
            Span::raw("] Sink: "),
            Span::styled(
                truncate_str(sink_text, 12),
                Style::default()
                    .fg(if self.filter_sink_type.is_some() {
                        Color::Magenta
                    } else {
                        Color::Green
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
                "  | {} of {}",
                self.filtered_flows.len(),
                self.cross_file_flows.len()
            )),
        ]);

        let bar = Paragraph::new(filter_text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        frame.render_widget(bar, area);
    }

    /// Render the flow list with rich items
    fn render_flow_list(&mut self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .filtered_flows
            .iter()
            .enumerate()
            .map(|(list_idx, &idx)| {
                let flow = &self.cross_file_flows[idx];
                let severity_color = match flow.severity {
                    Severity::Critical => Color::Red,
                    Severity::Error => Color::LightRed,
                    Severity::Warning => Color::Yellow,
                    Severity::Info => Color::Blue,
                };

                let prefix = if list_idx == self.selected_flow {
                    ">> "
                } else {
                    "   "
                };

                let sev_badge = match flow.severity {
                    Severity::Critical => "CRIT",
                    Severity::Error => "ERR ",
                    Severity::Warning => "WARN",
                    Severity::Info => "INFO",
                };

                let conf_letter = match flow.confidence.as_str() {
                    "High" => "H",
                    "Medium" => "M",
                    "Low" => "L",
                    _ => "?",
                };

                let src_chip = truncate_str(&flow.source_type, 6);
                let sink_chip = truncate_str(&flow.sink_type, 8);

                let line = Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::Magenta)),
                    Span::styled(
                        sev_badge,
                        Style::default()
                            .fg(severity_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        format!("[{}]", src_chip),
                        Style::default().fg(Color::Red),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        truncate_str(&flow.source_function, 14),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(
                        " -> ",
                        Style::default()
                            .fg(severity_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        truncate_str(&flow.target_function, 14),
                        Style::default().fg(Color::White),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        format!("[{}]", sink_chip),
                        Style::default().fg(Color::Magenta),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        conf_letter,
                        Style::default().fg(match flow.confidence.as_str() {
                            "High" => Color::Green,
                            "Medium" => Color::Yellow,
                            _ => Color::Red,
                        }),
                    ),
                ]);

                ListItem::new(line)
            })
            .collect();

        let title = if self.show_flow_detail {
            format!(" Data Flows ({}) ", self.filtered_flows.len())
        } else {
            format!(
                " Data Flows ({}) [Enter: detail] ",
                self.filtered_flows.len()
            )
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta))
                    .title(title),
            )
            .highlight_style(Style::default().bg(Color::DarkGray));

        frame.render_stateful_widget(list, area, &mut self.flow_list_state);
    }

    /// Render flow detail panel with taint metadata, path viz, evidence
    fn render_flow_detail(&self, frame: &mut Frame, area: Rect) {
        if self.filtered_flows.is_empty() {
            let empty = Paragraph::new("No flow selected")
                .style(Style::default().fg(Color::DarkGray))
                .block(Block::default().borders(Borders::ALL).title(" Flow Detail "));
            frame.render_widget(empty, area);
            return;
        }

        let flow = &self.cross_file_flows[self.filtered_flows[self.selected_flow]];
        let severity_color = match flow.severity {
            Severity::Critical => Color::Red,
            Severity::Error => Color::LightRed,
            Severity::Warning => Color::Yellow,
            Severity::Info => Color::Blue,
        };

        let conf_color = match flow.confidence.as_str() {
            "High" => Color::Green,
            "Medium" => Color::Yellow,
            _ => Color::Red,
        };

        let mut lines = vec![
            // Taint metadata section
            Line::from(Span::styled(
                "═══ TAINT FLOW ═══",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("Severity:    ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    flow.severity.to_string(),
                    Style::default()
                        .fg(severity_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Confidence:  ", Style::default().fg(Color::Cyan)),
                Span::styled(&flow.confidence, Style::default().fg(conf_color)),
            ]),
            Line::from(vec![
                Span::styled("Source Type: ", Style::default().fg(Color::Cyan)),
                Span::styled(&flow.source_type, Style::default().fg(Color::Red)),
            ]),
            Line::from(vec![
                Span::styled("Sink Type:   ", Style::default().fg(Color::Cyan)),
                Span::styled(&flow.sink_type, Style::default().fg(Color::Magenta)),
            ]),
            Line::from(vec![
                Span::styled("Reachability:", Style::default().fg(Color::Cyan)),
                Span::raw(" "),
                Span::styled(
                    &flow.reachability,
                    Style::default().fg(match flow.reachability.as_str() {
                        "prod" => Color::Green,
                        "test-only" => Color::Yellow,
                        _ => Color::DarkGray,
                    }),
                ),
            ]),
            Line::from(vec![
                Span::styled("Bridge:      ", Style::default().fg(Color::Cyan)),
                Span::raw(&flow.bridge_type),
            ]),
        ];

        // Flow path visualization
        if !flow.flow_path.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "═══ FLOW PATH ═══",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            let path_len = flow.flow_path.len();
            for (i, step) in flow.flow_path.iter().enumerate() {
                let step_color = if i == 0 {
                    Color::Red // source
                } else if i == path_len - 1 {
                    Color::Magenta // sink
                } else {
                    Color::White // intermediate
                };
                let prefix = if i == 0 {
                    "  [SRC] "
                } else if i == path_len - 1 {
                    "  [SNK] "
                } else {
                    "        "
                };
                lines.push(Line::from(Span::styled(
                    format!("{}{}", prefix, step),
                    Style::default().fg(step_color),
                )));
                if i < path_len - 1 {
                    lines.push(Line::from(Span::styled(
                        "        |",
                        Style::default().fg(Color::DarkGray),
                    )));
                    lines.push(Line::from(Span::styled(
                        "        v",
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
        }

        // Evidence section
        if !flow.sink_evidence_detail.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "═══ EVIDENCE ═══",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(vec![
                Span::styled("  Evidence:  ", Style::default().fg(Color::Cyan)),
                Span::raw(&flow.sink_evidence_detail),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Strength:  ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    if flow.sink_evidence_strong {
                        "STRONG"
                    } else {
                        "WEAK"
                    },
                    Style::default().fg(if flow.sink_evidence_strong {
                        Color::Green
                    } else {
                        Color::Yellow
                    }),
                ),
            ]));
            if let Some(ref role) = flow.sink_role {
                lines.push(Line::from(vec![
                    Span::styled("  Sink Role: ", Style::default().fg(Color::Cyan)),
                    Span::raw(role),
                ]));
            }
        }

        // Description section
        if !flow.description.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "═══ DESCRIPTION ═══",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            for desc_line in flow.description.lines() {
                lines.push(Line::from(format!("  {}", desc_line)));
            }
        }

        let detail = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta))
                    .title(" Flow Detail (Enter to collapse) "),
            )
            .wrap(Wrap { trim: false });

        frame.render_widget(detail, area);
    }

    /// Render the Metrics tab
    fn render_metrics_tab(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Left: Summary metrics
        let summary_lines = vec![
            Line::from(Span::styled(
                "PROJECT SUMMARY",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Total Files:      ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}", self.metrics.total_files)),
            ]),
            Line::from(vec![
                Span::styled("  Lines of Code:    ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}", self.metrics.total_loc)),
            ]),
            Line::from(vec![
                Span::styled("  Comment Lines:    ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}", self.metrics.total_comments)),
            ]),
            Line::from(vec![
                Span::styled("  Blank Lines:      ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}", self.metrics.total_blank)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Functions:        ", Style::default().fg(Color::Green)),
                Span::raw(format!("{}", self.metrics.total_functions)),
            ]),
            Line::from(vec![
                Span::styled("  Classes/Structs:  ", Style::default().fg(Color::Green)),
                Span::raw(format!("{}", self.metrics.total_classes)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Avg Complexity:   ", Style::default().fg(Color::Magenta)),
                Span::raw(format!("{:.1}", self.metrics.avg_complexity)),
            ]),
            Line::from(vec![
                Span::styled("  Max Complexity:   ", Style::default().fg(Color::Red)),
                Span::raw(format!("{}", self.metrics.max_complexity)),
            ]),
            Line::from(vec![
                Span::styled("  Highest in:       ", Style::default().fg(Color::DarkGray)),
                Span::raw(truncate_str(&self.metrics.max_complexity_file, 30)),
            ]),
        ];

        // Language breakdown
        let mut lang_lines: Vec<Line> = vec![
            Line::from(""),
            Line::from(Span::styled(
                "LANGUAGE BREAKDOWN",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
        ];

        for (lang, stats) in &self.metrics.language_breakdown {
            lang_lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:12}", format!("{:?}", lang)),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(format!(
                    "{:5} files | {:7} LOC | {:4} findings",
                    stats.files, stats.loc, stats.findings
                )),
            ]));
        }

        let mut all_lines = summary_lines;
        all_lines.extend(lang_lines);

        let summary = Paragraph::new(all_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title(" Metrics Overview "),
        );

        frame.render_widget(summary, chunks[0]);

        // Right: File metrics list
        if self.file_metrics.is_empty() {
            let empty = Paragraph::new("No per-file metrics available")
                .style(Style::default().fg(Color::DarkGray))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Per-File Metrics "),
                );
            frame.render_widget(empty, chunks[1]);
        } else {
            let items: Vec<ListItem> = self
                .file_metrics
                .iter()
                .enumerate()
                .map(|(i, (path, m))| {
                    let prefix = if i == self.selected_metric_file {
                        ">> "
                    } else {
                        "   "
                    };
                    let file = truncate_str(path, 25);

                    let complexity_color = if m.cyclomatic_complexity > 20 {
                        Color::Red
                    } else if m.cyclomatic_complexity > 10 {
                        Color::Yellow
                    } else {
                        Color::Green
                    };

                    let line = Line::from(vec![
                        Span::styled(prefix, Style::default().fg(Color::Green)),
                        Span::styled(format!("{:<25}", file), Style::default().fg(Color::White)),
                        Span::raw(" | "),
                        Span::styled(
                            format!("{:5} LOC", m.lines_of_code),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::raw(" | "),
                        Span::styled(
                            format!("CC:{:3}", m.cyclomatic_complexity),
                            Style::default().fg(complexity_color),
                        ),
                    ]);

                    ListItem::new(line)
                })
                .collect();

            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Green))
                        .title(format!(" Per-File Metrics ({}) ", self.file_metrics.len())),
                )
                .highlight_style(Style::default().bg(Color::DarkGray));

            frame.render_stateful_widget(list, chunks[1], &mut self.metric_list_state);
        }
    }

    /// Render the Call Graph tab
    fn render_call_graph_tab(&mut self, frame: &mut Frame, area: Rect) {
        if self.call_edges.is_empty() {
            let empty = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No call graph data available",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  The call graph shows function calls between files.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Test files are excluded by default.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(" Call Graph "),
            );
            frame.render_widget(empty, area);
            return;
        }

        // Stats area height depends on event bindings toggle
        let stats_height = if self.show_event_bindings { 8 } else { 5 };

        // Main layout: stats summary at top, then list/detail below
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(stats_height), Constraint::Min(10)])
            .split(area);

        // Render stats summary (includes event bindings if toggled)
        self.render_call_graph_stats(frame, main_chunks[0]);

        // If explore mode is active, render explore panel instead
        if self.explore_mode {
            self.render_explore_mode(frame, main_chunks[1]);
            return;
        }

        // Split into list and detail if detail is shown
        let list_area = main_chunks[1];
        let chunks = if self.show_edge_detail {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(list_area)
        } else {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(100)])
                .split(list_area)
        };

        let items: Vec<ListItem> = self
            .filtered_edges
            .iter()
            .enumerate()
            .map(|(list_idx, &idx)| {
                let edge = &self.call_edges[idx];
                let prefix = if list_idx == self.selected_edge {
                    ">> "
                } else {
                    "   "
                };

                // Badges for source/sink classification
                let mut badges = Vec::new();
                if edge.caller_is_source && edge.callee_contains_sinks {
                    // Highlight dangerous source→sink flows
                    badges.push(Span::styled("⚠", Style::default().fg(Color::Red)));
                    badges.push(Span::raw(" "));
                }
                if edge.caller_is_source {
                    let src_label = edge
                        .caller_source_kind
                        .as_ref()
                        .map(|k| format!("[{}]", truncate_str(k, 8)))
                        .unwrap_or_else(|| "[SRC]".to_string());
                    badges.push(Span::styled(src_label, Style::default().fg(Color::Red)));
                    badges.push(Span::raw(" "));
                }
                if edge.callee_contains_sinks {
                    let sink_label = if let Some(first_sink) = edge.callee_sink_kinds.first() {
                        format!("[{}]", truncate_str(first_sink, 8))
                    } else {
                        "[SINK]".to_string()
                    };
                    badges.push(Span::styled(
                        sink_label,
                        Style::default().fg(Color::Magenta),
                    ));
                    badges.push(Span::raw(" "));
                }
                if edge.callee_calls_sanitizers {
                    badges.push(Span::styled("[SAN]", Style::default().fg(Color::Green)));
                    badges.push(Span::raw(" "));
                }
                if edge.callee_is_exported {
                    badges.push(Span::styled("⬆", Style::default().fg(Color::Blue)));
                    badges.push(Span::raw(" "));
                }

                let edge_color = if edge.caller_is_source && edge.callee_contains_sinks {
                    Color::Red // Dangerous flow
                } else if edge.is_cross_file {
                    Color::Yellow
                } else {
                    Color::DarkGray
                };

                // Get just filename, not full path
                let caller_filename = std::path::Path::new(&edge.caller_file)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| edge.caller_file.clone());
                let callee_filename = std::path::Path::new(&edge.callee_file)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| edge.callee_file.clone());

                let mut spans = vec![Span::styled(prefix, Style::default().fg(Color::Yellow))];
                spans.extend(badges);
                spans.extend(vec![
                    Span::styled(
                        truncate_str(&caller_filename, 16),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(
                        format!(":{}", edge.call_site_line),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(" "),
                    Span::styled(&edge.caller_func, Style::default().fg(Color::Cyan)),
                    Span::styled(
                        if edge.is_cross_file { " ==> " } else { " --> " },
                        Style::default().fg(edge_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&edge.callee_func, Style::default().fg(Color::Green)),
                    Span::raw(" "),
                    Span::styled(
                        truncate_str(&callee_filename, 16),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled(
                        format!(":{}", edge.callee_line),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]);

                ListItem::new(Line::from(spans))
            })
            .collect();

        let mut filter_parts = Vec::new();
        if self.filter_source_sink_only {
            filter_parts.push("[x: SRC->SINK]");
        }
        if self.filter_cross_file_only {
            filter_parts.push("[w: cross-file]");
        }
        let filter_indicator = if filter_parts.is_empty() {
            String::new()
        } else {
            format!(" {}", filter_parts.join(" "))
        };
        let title = format!(
            " Edges ({}/{} shown){} ",
            self.filtered_edges.len(),
            self.call_edges.len(),
            filter_indicator
        );

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(title),
            )
            .highlight_style(Style::default().bg(Color::DarkGray));

        frame.render_stateful_widget(list, chunks[0], &mut self.edge_list_state);

        // Render detail panel if shown
        if self.show_edge_detail && chunks.len() > 1 {
            self.render_edge_detail(frame, chunks[1]);
        }
    }

    /// Render the call graph statistics summary
    fn render_call_graph_stats(&self, frame: &mut Frame, area: Rect) {
        let cg = &self.call_graph_stats;

        // Build stats lines
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Functions: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{}", cg.total_functions),
                    Style::default().fg(Color::White),
                ),
                Span::raw("  │  "),
                Span::styled("Edges: ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    format!("{}", cg.total_edges),
                    Style::default().fg(Color::White),
                ),
                Span::raw("  │  "),
                Span::styled("Cross-file: ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{}", cg.cross_file_edges),
                    Style::default().fg(Color::White),
                ),
                Span::raw("  │  "),
                Span::styled("Unresolved: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", cg.unresolved_calls),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("Sources: ", Style::default().fg(Color::Red)),
                Span::styled(
                    format!("{}", cg.source_functions),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!(" ({} files)", cg.files_with_sources),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("  │  "),
                Span::styled("Sinks: ", Style::default().fg(Color::Magenta)),
                Span::styled(
                    format!("{}", cg.sink_functions),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!(" ({} files)", cg.files_with_sinks),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw("  │  "),
                Span::styled("Sanitizers: ", Style::default().fg(Color::Green)),
                Span::styled(
                    format!("{}", cg.sanitizer_functions),
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "⚠ Source→Sink edges: ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", cg.source_to_sink_edges),
                    if cg.source_to_sink_edges > 0 {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                ),
                if cg.source_to_sink_edges > 0 {
                    Span::styled(
                        " (review for security issues)",
                        Style::default().fg(Color::Yellow),
                    )
                } else {
                    Span::styled(" (none detected)", Style::default().fg(Color::Green))
                },
            ]),
        ];

        // Event bindings (when toggled with 'b')
        if self.show_event_bindings && !self.event_bindings.is_empty() {
            let mut event_spans = vec![Span::styled(
                "Events: ",
                Style::default().fg(Color::Cyan),
            )];
            for (i, eb) in self.event_bindings.iter().take(6).enumerate() {
                if i > 0 {
                    event_spans.push(Span::raw(" | "));
                }
                let color = if eb.emit_count > 0 && eb.listen_count == 0 {
                    Color::Red // Dead event - emitted but never listened
                } else if eb.emit_count == 0 && eb.listen_count > 0 {
                    Color::Yellow // Orphan listener
                } else {
                    Color::White
                };
                event_spans.push(Span::styled(
                    format!(
                        "\"{}\" ({}->{})",
                        truncate_str(&eb.event_name, 12),
                        eb.emit_count,
                        eb.listen_count
                    ),
                    Style::default().fg(color),
                ));
            }
            if self.event_bindings.len() > 6 {
                event_spans.push(Span::styled(
                    format!(" +{} more", self.event_bindings.len() - 6),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            lines.push(Line::from(event_spans));
        }

        // Severity distribution bar
        let total = self.stats.critical_count
            + self.stats.error_count
            + self.stats.warning_count
            + self.stats.info_count;
        if total > 0 {
            let available_width = area.width.saturating_sub(4) as usize; // border + padding
            let crit_w = (self.stats.critical_count * available_width / total).max(if self.stats.critical_count > 0 { 1 } else { 0 });
            let err_w = (self.stats.error_count * available_width / total).max(if self.stats.error_count > 0 { 1 } else { 0 });
            let warn_w = (self.stats.warning_count * available_width / total).max(if self.stats.warning_count > 0 { 1 } else { 0 });
            let info_w = available_width.saturating_sub(crit_w + err_w + warn_w);
            let mut bar_spans = vec![Span::raw(" ")];
            if crit_w > 0 {
                bar_spans.push(Span::styled(
                    "\u{2588}".repeat(crit_w),
                    Style::default().fg(Color::Red),
                ));
            }
            if err_w > 0 {
                bar_spans.push(Span::styled(
                    "\u{2588}".repeat(err_w),
                    Style::default().fg(Color::LightRed),
                ));
            }
            if warn_w > 0 {
                bar_spans.push(Span::styled(
                    "\u{2588}".repeat(warn_w),
                    Style::default().fg(Color::Yellow),
                ));
            }
            if info_w > 0 {
                bar_spans.push(Span::styled(
                    "\u{2588}".repeat(info_w),
                    Style::default().fg(Color::Blue),
                ));
            }
            lines.push(Line::from(bar_spans));
        }

        let stats_widget = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Call Graph Statistics "),
        );
        frame.render_widget(stats_widget, area);
    }

    /// Render the call graph edge detail panel
    fn render_edge_detail(&self, frame: &mut Frame, area: Rect) {
        if self.filtered_edges.is_empty() {
            let empty = Paragraph::new("No edge selected")
                .style(Style::default().fg(Color::DarkGray))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Edge Detail "),
                );
            frame.render_widget(empty, area);
            return;
        }

        let edge = &self.call_edges[self.filtered_edges[self.selected_edge]];

        let mut lines = vec![
            // CALLER section
            Line::from(Span::styled(
                "═══ CALLER (Source) ═══",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("Function:    ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    &edge.caller_func,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("File:        ", Style::default().fg(Color::Yellow)),
                Span::raw(truncate_str(&edge.caller_file, 45)),
            ]),
            Line::from(vec![
                Span::styled("Line:        ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{}", edge.caller_line),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw("  "),
                Span::styled("Language: ", Style::default().fg(Color::Yellow)),
                Span::raw(&edge.caller_language),
            ]),
        ];

        // Source classification details
        if edge.caller_is_source {
            let source_kind = edge
                .caller_source_kind
                .clone()
                .unwrap_or_else(|| "Unknown".to_string());
            lines.push(Line::from(vec![
                Span::styled("⚡ Taint Source: ", Style::default().fg(Color::Red)),
                Span::styled(
                    source_kind,
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]));
        }

        // CALL SITE section
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "═══ CALL SITE ═══",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(vec![
            Span::styled("Call Line:   ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{}", edge.call_site_line),
                Style::default().fg(Color::Cyan),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Cross-File:  ", Style::default().fg(Color::Yellow)),
            if edge.is_cross_file {
                Span::styled(
                    "YES (inter-module)",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("No (intra-module)", Style::default().fg(Color::DarkGray))
            },
        ]));

        // CALLEE section
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "═══ CALLEE (Target) ═══",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(vec![
            Span::styled("Function:    ", Style::default().fg(Color::Yellow)),
            Span::styled(
                &edge.callee_func,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            if edge.callee_is_exported {
                Span::styled(" [EXPORTED]", Style::default().fg(Color::Blue))
            } else {
                Span::raw("")
            },
        ]));
        lines.push(Line::from(vec![
            Span::styled("File:        ", Style::default().fg(Color::Yellow)),
            Span::raw(truncate_str(&edge.callee_file, 45)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Line:        ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{}", edge.callee_line),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  "),
            Span::styled("Language: ", Style::default().fg(Color::Yellow)),
            Span::raw(&edge.callee_language),
        ]));

        // Sink classification details
        if edge.callee_contains_sinks {
            lines.push(Line::from(vec![Span::styled(
                "⚠ Contains Sinks: ",
                Style::default().fg(Color::Magenta),
            )]));
            for sink_kind in &edge.callee_sink_kinds {
                lines.push(Line::from(vec![
                    Span::raw("   • "),
                    Span::styled(sink_kind, Style::default().fg(Color::Magenta)),
                ]));
            }
        }

        // Sanitizer details
        if edge.callee_calls_sanitizers {
            lines.push(Line::from(vec![Span::styled(
                "✓ Calls Sanitizers: ",
                Style::default().fg(Color::Green),
            )]));
            for sanitizes in &edge.callee_sanitizes {
                lines.push(Line::from(vec![
                    Span::raw("   • "),
                    Span::styled(sanitizes, Style::default().fg(Color::Green)),
                ]));
            }
        }

        // Confidence
        if edge.classification_confidence > 0.0 {
            let conf_color = if edge.classification_confidence >= 0.8 {
                Color::Green
            } else if edge.classification_confidence >= 0.5 {
                Color::Yellow
            } else {
                Color::Red
            };
            lines.push(Line::from(vec![
                Span::styled("Confidence:  ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{:.0}%", edge.classification_confidence * 100.0),
                    Style::default().fg(conf_color),
                ),
            ]));
        }

        // Source→Sink path visualization
        if !edge.source_sink_path.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "═══ SOURCE→SINK PATH ═══",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )));
            let path_len = edge.source_sink_path.len();
            for (i, step) in edge.source_sink_path.iter().enumerate() {
                let step_color = if i == 0 {
                    Color::Red
                } else if i == path_len - 1 {
                    Color::Magenta
                } else {
                    Color::White
                };
                lines.push(Line::from(Span::styled(
                    format!("  {}", step),
                    Style::default().fg(step_color),
                )));
                if i < path_len - 1 {
                    lines.push(Line::from(Span::styled(
                        "  |",
                        Style::default().fg(Color::DarkGray),
                    )));
                    lines.push(Line::from(Span::styled(
                        "  v",
                        Style::default().fg(Color::DarkGray),
                    )));
                }
            }
        }

        // Security warning if this is a source->sink flow
        if edge.caller_is_source && edge.callee_contains_sinks {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "════════════════════════════════════════",
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "⚠⚠⚠ POTENTIAL SECURITY ISSUE ⚠⚠⚠",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(Span::styled(
                "════════════════════════════════════════",
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(Span::styled(
                "This call flows DIRECTLY from a taint",
                Style::default().fg(Color::Yellow),
            )));
            lines.push(Line::from(Span::styled(
                "SOURCE to a function containing SINK",
                Style::default().fg(Color::Yellow),
            )));
            lines.push(Line::from(Span::styled(
                "operations. This is a potential:",
                Style::default().fg(Color::Yellow),
            )));
            for sink_kind in &edge.callee_sink_kinds {
                lines.push(Line::from(vec![
                    Span::raw("  → "),
                    Span::styled(
                        sink_kind,
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" vulnerability", Style::default().fg(Color::Red)),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "ACTION: Review data flow and ensure",
                Style::default().fg(Color::Cyan),
            )));
            lines.push(Line::from(Span::styled(
                "proper input validation/sanitization.",
                Style::default().fg(Color::Cyan),
            )));
        }

        let detail = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .title(" Edge Detail (Enter to close) "),
            )
            .wrap(Wrap { trim: false });

        frame.render_widget(detail, area);
    }

    /// Render call graph explore mode
    fn render_explore_mode(&mut self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // Left: Function info + list of callers/callees
        let func_name = self.explore_function_name.clone();
        let func_file = self.explore_function_file.clone();
        let func_filename = std::path::Path::new(&func_file)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| func_file.clone());

        // Find classifications from edges
        let has_sinks: Vec<String> = self
            .call_edges
            .iter()
            .filter(|e| e.callee_func == func_name && e.callee_file == func_file)
            .flat_map(|e| e.callee_sink_kinds.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let has_sanitizers: Vec<String> = self
            .call_edges
            .iter()
            .filter(|e| e.callee_func == func_name && e.callee_file == func_file)
            .flat_map(|e| e.callee_sanitizes.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let mut info_lines = vec![
            Line::from(Span::styled(
                format!("=== EXPLORING: {} ===", func_name),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled("File: ", Style::default().fg(Color::Yellow)),
                Span::raw(&func_filename),
            ]),
        ];
        if !has_sinks.is_empty() {
            info_lines.push(Line::from(vec![
                Span::styled("Contains Sinks: ", Style::default().fg(Color::Magenta)),
                Span::styled(has_sinks.join(", "), Style::default().fg(Color::Magenta)),
            ]));
        }
        if !has_sanitizers.is_empty() {
            info_lines.push(Line::from(vec![
                Span::styled("Sanitizers: ", Style::default().fg(Color::Green)),
                Span::styled(
                    has_sanitizers.join(", "),
                    Style::default().fg(Color::Green),
                ),
            ]));
        }
        info_lines.push(Line::from(""));

        // Show callers/callees based on view
        let (view_title, list_data) = match self.explore_view {
            ExploreView::Callers => ("CALLERS", &self.explore_callers),
            ExploreView::Callees => ("CALLEES", &self.explore_callees),
        };

        info_lines.push(Line::from(Span::styled(
            format!(
                "--- {} ({}) --- [l: toggle]",
                view_title,
                list_data.len()
            ),
            Style::default().fg(Color::Yellow),
        )));

        let items: Vec<ListItem> = list_data
            .iter()
            .enumerate()
            .map(|(i, (name, file, line))| {
                let filename = std::path::Path::new(file)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| file.clone());
                let prefix = if i == self.explore_selected {
                    "  >> "
                } else {
                    "     "
                };
                ListItem::new(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::Yellow)),
                    Span::styled(name, Style::default().fg(Color::Cyan)),
                    Span::raw(" "),
                    Span::styled(
                        format!("({}:{})", filename, line),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();

        let info_para = Paragraph::new(info_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Explore (Esc: back, e/Enter: drill, l: toggle) "),
        );
        frame.render_widget(info_para, chunks[0]);

        let explore_list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(format!(" {} ", view_title)),
            )
            .highlight_style(Style::default().bg(Color::DarkGray));
        frame.render_stateful_widget(explore_list, chunks[1], &mut self.explore_list_state);
    }

    /// Render the status bar
    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let help_text = if self.input_mode == InputMode::Search {
            "Type to search | Enter/Esc: finish"
        } else {
            match self.active_tab {
                ActiveTab::Findings => {
                    "Tab/1-4: switch | j/k: nav | Enter: detail | s: sev | f: subcat | d: conf | /: search | c: clear | ?: help | q: quit"
                }
                ActiveTab::CrossFileFlows => {
                    "Tab/1-4: switch | j/k: nav | Enter: detail | t: kind | n: src | i: sink | /: search | c: clear | ?: help | q: quit"
                }
                ActiveTab::Metrics => "Tab/1-4: switch tabs | j/k: navigate files | q: quit",
                ActiveTab::CallGraph => {
                    if self.explore_mode {
                        "j/k: nav | l: callers/callees | e/Enter: drill | Esc: back | ?: help | q: quit"
                    } else {
                        "Tab/1-4: switch | j/k: nav | Enter: detail | e: explore | x: src->sink | w: cross-file | b: events | ?: help | q: quit"
                    }
                }
            }
        };

        let status = Paragraph::new(help_text)
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);

        frame.render_widget(status, area);
    }

    /// Render help overlay
    fn render_help_overlay(&self, frame: &mut Frame, area: Rect) {
        let help_width = 60;
        let help_height = 34;
        let x = (area.width.saturating_sub(help_width)) / 2;
        let y = (area.height.saturating_sub(help_height)) / 2;
        let help_area = Rect::new(x, y, help_width, help_height);

        frame.render_widget(Clear, help_area);

        let help_text = vec![
            Line::from(Span::styled(
                "KEYBOARD SHORTCUTS",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "Navigation",
                Style::default().fg(Color::Yellow),
            )),
            Line::from("  Tab/1-4    Switch between tabs"),
            Line::from("  j/k        Move up/down"),
            Line::from("  g/G        Jump to first/last"),
            Line::from("  PgUp/PgDn  Page up/down"),
            Line::from(""),
            Line::from(Span::styled("Views", Style::default().fg(Color::Yellow))),
            Line::from("  Enter      Toggle detail view"),
            Line::from(""),
            Line::from(Span::styled(
                "Findings Tab",
                Style::default().fg(Color::Yellow),
            )),
            Line::from("  s          Cycle severity filter"),
            Line::from("  f          Cycle subcategory (All/Vuln/Audit/Style)"),
            Line::from("  d          Cycle confidence filter"),
            Line::from(""),
            Line::from(Span::styled(
                "Cross-File Flows Tab",
                Style::default().fg(Color::Yellow),
            )),
            Line::from("  Enter      Toggle detail panel"),
            Line::from("  t          Cycle flow kind filter"),
            Line::from("  n          Cycle source type filter"),
            Line::from("  i          Cycle sink type filter"),
            Line::from(""),
            Line::from(Span::styled(
                "Call Graph Tab",
                Style::default().fg(Color::Yellow),
            )),
            Line::from("  e          Explore function (drill-down)"),
            Line::from("  w          Toggle cross-file only"),
            Line::from("  x          Toggle source->sink only"),
            Line::from("  b          Toggle event bindings"),
            Line::from("  l          Switch callers/callees (explore)"),
            Line::from(""),
            Line::from(Span::styled("General", Style::default().fg(Color::Yellow))),
            Line::from("  /          Search mode"),
            Line::from("  c          Clear all filters"),
            Line::from("  Esc        Clear search/filter/mode"),
            Line::from("  ?          Toggle this help"),
            Line::from("  q          Quit"),
        ];

        let help = Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Help (press any key to close) "),
        );

        frame.render_widget(help, help_area);
    }
}

/// Truncate a string to a maximum length
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - (max_len - 3)..])
    }
}

/// Cycle through a dynamic set of filter options: None → first → second → ... → None
fn cycle_filter(current: &Option<String>, options: &[String]) -> Option<String> {
    if options.is_empty() {
        return None;
    }
    match current {
        None => Some(options[0].clone()),
        Some(val) => {
            if let Some(idx) = options.iter().position(|o| o == val) {
                if idx + 1 < options.len() {
                    Some(options[idx + 1].clone())
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

/// Run the TUI application
#[allow(dead_code)]
pub fn run(findings: Vec<Finding>, stats: ScanStats) -> Result<()> {
    let mut app = TuiApp::from_findings(findings, stats);
    run_app_internal(&mut app)
}

/// Run the TUI with all analysis data
pub fn run_full(
    findings: Vec<Finding>,
    cross_file_flows: Vec<CrossFileFlow>,
    metrics: AggregatedMetrics,
    file_metrics: Vec<(String, CodeMetrics)>,
    call_edges: Vec<CallEdgeDisplay>,
    call_graph_stats: CallGraphStats,
    event_bindings: Vec<EventBindingDisplay>,
    stats: ScanStats,
) -> Result<()> {
    let mut app = TuiApp::new(
        findings,
        cross_file_flows,
        metrics,
        file_metrics,
        call_edges,
        call_graph_stats,
        event_bindings,
        stats,
    );
    run_app_internal(&mut app)
}

fn run_app_internal(app: &mut TuiApp) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run the app
    let result = run_app_loop(&mut terminal, app);

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

fn run_app_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
) -> Result<()> {
    loop {
        terminal.draw(|f| app.render(f))?;

        if event::poll(std::time::Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            app.handle_key_event(key);
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

/// Run the TUI from analysis results (backwards compatible)
#[allow(dead_code)]
pub fn run_from_analysis(
    results: &[rma_analyzer::FileAnalysis],
    summary: &AnalysisSummary,
) -> Result<()> {
    run_from_analysis_with_project(results, summary, None, 0)
}

/// Run the TUI with full project analysis data including cross-file flows and call graph
pub fn run_from_analysis_with_project(
    results: &[rma_analyzer::FileAnalysis],
    summary: &AnalysisSummary,
    project_result: Option<&rma_analyzer::project::ProjectAnalysisResult>,
    suppressed_count: usize,
) -> Result<()> {
    // Collect all findings from results
    let findings: Vec<Finding> = results
        .iter()
        .flat_map(|r| r.findings.iter().cloned())
        .collect();

    // Collect file metrics
    let file_metrics: Vec<(String, CodeMetrics)> = results
        .iter()
        .map(|r| (r.path.clone(), r.metrics.clone()))
        .collect();

    // Aggregate metrics
    let mut total_loc = 0usize;
    let mut total_comments = 0usize;
    let mut total_blank = 0usize;
    let mut total_functions = 0usize;
    let mut total_classes = 0usize;
    let mut max_complexity = 0usize;
    let mut max_complexity_file = String::new();
    let mut total_complexity = 0usize;
    let mut language_breakdown: HashMap<Language, LanguageStats> = HashMap::new();

    for r in results {
        total_loc += r.metrics.lines_of_code;
        total_comments += r.metrics.lines_of_comments;
        total_blank += r.metrics.blank_lines;
        total_functions += r.metrics.function_count;
        total_classes += r.metrics.class_count;
        total_complexity += r.metrics.cyclomatic_complexity;

        if r.metrics.cyclomatic_complexity > max_complexity {
            max_complexity = r.metrics.cyclomatic_complexity;
            max_complexity_file = r.path.clone();
        }

        // Language breakdown
        let entry = language_breakdown.entry(r.language).or_default();
        entry.files += 1;
        entry.loc += r.metrics.lines_of_code;
        entry.findings += r.findings.len();
    }

    let metrics = AggregatedMetrics {
        total_files: results.len(),
        total_loc,
        total_comments,
        total_blank,
        total_functions,
        total_classes,
        avg_complexity: if results.is_empty() {
            0.0
        } else {
            total_complexity as f64 / results.len() as f64
        },
        max_complexity,
        max_complexity_file,
        language_breakdown,
    };

    let mut stats = ScanStats::from(summary);
    stats.suppressed_generated = suppressed_count;

    // Convert cross-file taints to display format
    let cross_file_flows = if let Some(proj) = project_result {
        proj.cross_file_taints
            .iter()
            .map(|taint| {
                let source_type_str = taint.source_type.to_string();
                let sink_type_str = taint.sink_type.to_string();

                // Derive flow kind from source_type string for more accuracy
                let flow_kind = if source_type_str.contains("Event")
                    || taint.description.contains("Event")
                {
                    FlowKind::EventEmission
                } else if taint.description.contains("return") {
                    FlowKind::Return
                } else if taint.description.contains("state")
                    || taint.description.contains("shared")
                {
                    FlowKind::SharedState
                } else {
                    FlowKind::DirectCall
                };

                // Build flow_path from taint.path
                let flow_path: Vec<String> = {
                    let mut path = Vec::new();
                    // Add source as first entry
                    let src_filename = taint
                        .source
                        .file
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("?");
                    path.push(format!(
                        "{} ({}:{})",
                        taint.source.function, src_filename, taint.source.line
                    ));
                    // Add intermediate steps
                    for step in &taint.path {
                        let step_filename = step
                            .file
                            .file_name()
                            .and_then(|f| f.to_str())
                            .unwrap_or("?");
                        path.push(format!(
                            "{} ({}:{})",
                            step.function, step_filename, step.line
                        ));
                    }
                    // Add sink as last entry
                    let sink_filename = taint
                        .sink
                        .file
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("?");
                    path.push(format!(
                        "{} ({}:{})",
                        taint.sink.function, sink_filename, taint.sink.line
                    ));
                    path
                };

                CrossFileFlow {
                    source_file: taint.source.file.display().to_string(),
                    source_function: taint.source.function.clone(),
                    source_line: taint.source.line,
                    target_file: taint.sink.file.display().to_string(),
                    target_function: taint.sink.function.clone(),
                    target_line: taint.sink.line,
                    variable: taint.source.name.clone(),
                    flow_kind,
                    severity: taint.severity,
                    confidence: taint.confidence.to_string(),
                    source_type: source_type_str,
                    sink_type: sink_type_str,
                    description: taint.description.clone(),
                    bridge_type: taint.bridge_type.to_string(),
                    reachability: taint.reachability.to_string(),
                    sink_role: taint.sink_role.clone(),
                    sink_arg_index: taint.sink_arg_index,
                    sink_callsite_line: taint.sink_callsite_line,
                    sink_evidence_detail: taint.sink_evidence.details.clone(),
                    sink_evidence_strong: taint.sink_evidence.is_strong(),
                    flow_path,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    // Convert call graph edges to display format (filter out test files, cross-file highlighted)
    let (call_edges, call_graph_stats) = if let Some(proj) = project_result {
        if let Some(ref cg) = proj.call_graph {
            // Compute stats first
            let all_edges: Vec<_> = cg.all_edges();
            let source_funcs = cg.source_functions();
            let sink_funcs = cg.sink_functions();
            let sanitizer_funcs = cg.sanitizer_functions();

            // Count files with sources and sinks
            let files_with_sources: std::collections::HashSet<_> =
                source_funcs.iter().map(|f| f.file.clone()).collect();
            let files_with_sinks: std::collections::HashSet<_> =
                sink_funcs.iter().map(|f| f.file.clone()).collect();

            let stats = CallGraphStats {
                total_functions: cg.function_count(),
                total_edges: cg.edge_count(),
                cross_file_edges: cg.cross_file_edges().len(),
                source_functions: source_funcs.len(),
                sink_functions: sink_funcs.len(),
                sanitizer_functions: sanitizer_funcs.len(),
                unresolved_calls: cg.unresolved_calls().len(),
                source_to_sink_edges: all_edges
                    .iter()
                    .filter(|e| {
                        e.caller.classification.is_source && e.callee.classification.contains_sinks
                    })
                    .count(),
                files_with_sources: files_with_sources.len(),
                files_with_sinks: files_with_sinks.len(),
            };

            let edges = all_edges
                .iter()
                // Filter out test files from both caller and callee
                .filter(|edge| !is_test_file(&edge.caller.file) && !is_test_file(&edge.callee.file))
                .map(|edge| CallEdgeDisplay {
                    caller_file: edge.caller.file.display().to_string(),
                    caller_func: edge.caller.name.clone(),
                    caller_line: edge.caller.line,
                    callee_file: edge.callee.file.display().to_string(),
                    callee_func: edge.callee.name.clone(),
                    callee_line: edge.callee.line,
                    call_site_line: edge.call_site.line,
                    is_cross_file: edge.is_cross_file,
                    // Security classifications
                    caller_is_source: edge.caller.classification.is_source,
                    caller_source_kind: edge
                        .caller
                        .classification
                        .source_kind
                        .as_ref()
                        .map(|k| k.to_string()),
                    callee_contains_sinks: edge.callee.classification.contains_sinks,
                    callee_sink_kinds: edge
                        .callee
                        .classification
                        .sink_kinds
                        .iter()
                        .map(|k| k.to_string())
                        .collect(),
                    callee_calls_sanitizers: edge.callee.classification.calls_sanitizers,
                    callee_sanitizes: edge.callee.classification.sanitizes.clone(),
                    // Additional metadata
                    caller_language: format!("{:?}", edge.caller.language),
                    callee_language: format!("{:?}", edge.callee.language),
                    callee_is_exported: edge.callee.is_exported,
                    classification_confidence: edge.callee.classification.confidence,
                    source_sink_path: Vec::new(),
                })
                .collect();

            (edges, stats)
        } else {
            (Vec::new(), CallGraphStats::default())
        }
    } else {
        (Vec::new(), CallGraphStats::default())
    };

    // Convert event bindings to display format
    let event_bindings = if let Some(proj) = project_result {
        if let Some(ref cg) = proj.call_graph {
            cg.all_event_bindings()
                .map(|eb| EventBindingDisplay {
                    event_name: eb.event_name.clone(),
                    emit_count: eb.emit_sites.len(),
                    listen_count: eb.listen_sites.len(),
                    emit_files: eb
                        .emit_sites
                        .iter()
                        .map(|s| {
                            s.file
                                .file_name()
                                .and_then(|f| f.to_str())
                                .unwrap_or("?")
                                .to_string()
                        })
                        .collect(),
                    listen_files: eb
                        .listen_sites
                        .iter()
                        .map(|s| {
                            s.file
                                .file_name()
                                .and_then(|f| f.to_str())
                                .unwrap_or("?")
                                .to_string()
                        })
                        .collect(),
                })
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    run_full(
        findings,
        cross_file_flows,
        metrics,
        file_metrics,
        call_edges,
        call_graph_stats,
        event_bindings,
        stats,
    )
}
