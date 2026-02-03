//! Event-Driven Data Flow Analysis
//!
//! This module provides event binding detection and tracking for analyzing
//! data flow through event-driven patterns like:
//!
//! - JavaScript: `emitter.emit('name', data)` -> `emitter.on('name', handler)`
//! - Java: `publisher.publishEvent(event)` -> `@EventListener`
//! - Python: `signal.send(data)` -> `@receiver(signal)`
//!
//! Event bindings are used to connect producers and consumers for taint analysis,
//! allowing us to track data flow across event boundaries.

use rma_common::Language;
use std::collections::HashMap;
use std::path::PathBuf;

/// Represents a site where an event is emitted or listened to
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventSite {
    /// File containing this event site
    pub file: PathBuf,
    /// Line number of the event site
    pub line: usize,
    /// Function containing this event site (if known)
    pub function: Option<String>,
    /// The expression text (e.g., "emitter.emit('data', userInput)")
    pub expression: String,
    /// Arguments passed to emit (for emit sites) or handler parameters (for listen sites)
    pub arguments: Vec<String>,
}

impl EventSite {
    /// Create a new event site
    pub fn new(file: PathBuf, line: usize, expression: String) -> Self {
        Self {
            file,
            line,
            function: None,
            expression,
            arguments: Vec::new(),
        }
    }

    /// Set the function containing this event site
    pub fn with_function(mut self, function: String) -> Self {
        self.function = Some(function);
        self
    }

    /// Set the arguments
    pub fn with_arguments(mut self, arguments: Vec<String>) -> Self {
        self.arguments = arguments;
        self
    }
}

/// Represents a binding between event emitters and listeners
#[derive(Debug, Clone)]
pub struct EventBinding {
    /// Name of the event (e.g., "data", "user.created", "click")
    pub event_name: String,
    /// Sites where this event is emitted (producers)
    pub emit_sites: Vec<EventSite>,
    /// Sites where this event is listened to (consumers)
    pub listen_sites: Vec<EventSite>,
}

impl EventBinding {
    /// Create a new event binding for the given event name
    pub fn new(event_name: String) -> Self {
        Self {
            event_name,
            emit_sites: Vec::new(),
            listen_sites: Vec::new(),
        }
    }

    /// Add an emit site
    pub fn add_emit_site(&mut self, site: EventSite) {
        self.emit_sites.push(site);
    }

    /// Add a listen site
    pub fn add_listen_site(&mut self, site: EventSite) {
        self.listen_sites.push(site);
    }

    /// Check if this event has any emitters
    pub fn has_emitters(&self) -> bool {
        !self.emit_sites.is_empty()
    }

    /// Check if this event has any listeners
    pub fn has_listeners(&self) -> bool {
        !self.listen_sites.is_empty()
    }

    /// Check if this event has both emitters and listeners (complete flow)
    pub fn is_complete(&self) -> bool {
        self.has_emitters() && self.has_listeners()
    }
}

/// Registry of all event bindings in a project
#[derive(Debug, Default)]
pub struct EventRegistry {
    /// Event bindings indexed by event name
    bindings: HashMap<String, EventBinding>,
}

impl EventRegistry {
    /// Create a new empty event registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an emit site for an event
    pub fn register_emit(&mut self, event_name: &str, site: EventSite) {
        self.bindings
            .entry(event_name.to_string())
            .or_insert_with(|| EventBinding::new(event_name.to_string()))
            .add_emit_site(site);
    }

    /// Register a listen site for an event
    pub fn register_listen(&mut self, event_name: &str, site: EventSite) {
        self.bindings
            .entry(event_name.to_string())
            .or_insert_with(|| EventBinding::new(event_name.to_string()))
            .add_listen_site(site);
    }

    /// Get a binding by event name
    pub fn get(&self, event_name: &str) -> Option<&EventBinding> {
        self.bindings.get(event_name)
    }

    /// Get all listeners for an event
    pub fn listeners_of(&self, event_name: &str) -> Vec<&EventSite> {
        self.bindings
            .get(event_name)
            .map(|b| b.listen_sites.iter().collect())
            .unwrap_or_default()
    }

    /// Get all emitters for an event
    pub fn emitters_of(&self, event_name: &str) -> Vec<&EventSite> {
        self.bindings
            .get(event_name)
            .map(|b| b.emit_sites.iter().collect())
            .unwrap_or_default()
    }

    /// Get all event names
    pub fn event_names(&self) -> impl Iterator<Item = &String> {
        self.bindings.keys()
    }

    /// Get all bindings
    pub fn all_bindings(&self) -> impl Iterator<Item = &EventBinding> {
        self.bindings.values()
    }

    /// Get all complete bindings (have both emitters and listeners)
    pub fn complete_bindings(&self) -> impl Iterator<Item = &EventBinding> {
        self.bindings.values().filter(|b| b.is_complete())
    }
}

/// Event detection patterns for different languages
pub struct EventPatterns {
    /// Patterns that indicate event emission
    pub emit_patterns: &'static [&'static str],
    /// Patterns that indicate event listening
    pub listen_patterns: &'static [&'static str],
}

impl EventPatterns {
    /// Get event patterns for a specific language
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self {
                emit_patterns: &[
                    ".emit(",
                    ".trigger(",
                    ".dispatch(",
                    ".dispatchEvent(",
                    ".publish(",
                    ".fire(",
                    ".send(",
                    "postMessage(",
                ],
                listen_patterns: &[
                    ".on(",
                    ".once(",
                    ".addEventListener(",
                    ".addListener(",
                    ".subscribe(",
                    ".off(",
                    ".removeListener(",
                    "onmessage",
                ],
            },
            Language::Java => Self {
                emit_patterns: &[
                    ".publishEvent(",
                    ".publish(",
                    ".fire(",
                    ".notify(",
                    ".send(",
                    ".post(",
                ],
                listen_patterns: &[
                    "@EventListener",
                    "@Subscribe",
                    "@Async",
                    ".onApplicationEvent(",
                    "implements ApplicationListener",
                ],
            },
            Language::Python => Self {
                emit_patterns: &[
                    ".send(",
                    ".send_robust(",
                    ".emit(",
                    ".publish(",
                    ".dispatch(",
                    "signal.send(",
                ],
                listen_patterns: &["@receiver(", ".connect(", "@on(", "def on_", "def handle_"],
            },
            Language::Go => Self {
                emit_patterns: &["chan <-", "<- ch", ".Publish(", ".Emit(", ".Send("],
                listen_patterns: &["<- chan", "for msg := range", ".Subscribe(", ".On("],
            },
            _ => Self {
                emit_patterns: &[],
                listen_patterns: &[],
            },
        }
    }

    /// Check if a line contains an emit pattern
    pub fn is_emit(&self, line: &str) -> bool {
        self.emit_patterns.iter().any(|p| line.contains(p))
    }

    /// Check if a line contains a listen pattern
    pub fn is_listen(&self, line: &str) -> bool {
        self.listen_patterns.iter().any(|p| line.contains(p))
    }
}

/// Extract event name from an emit or listen expression
///
/// Examples:
/// - `emitter.emit('data', value)` -> Some("data")
/// - `emitter.on('click', handler)` -> Some("click")
/// - `@EventListener(UserCreatedEvent.class)` -> Some("UserCreatedEvent")
pub fn extract_event_name(line: &str, language: Language) -> Option<String> {
    let trimmed = line.trim();

    match language {
        Language::JavaScript | Language::TypeScript => {
            // Look for emit('name', ...) or on('name', ...)
            let patterns = [
                ".emit(",
                ".on(",
                ".once(",
                ".trigger(",
                ".addEventListener(",
            ];

            for pattern in patterns {
                if let Some(pos) = trimmed.find(pattern) {
                    let after_paren = &trimmed[pos + pattern.len()..];
                    // Extract the first string argument
                    if let Some(name) = extract_string_arg(after_paren) {
                        return Some(name);
                    }
                }
            }
            None
        }
        Language::Java => {
            // Look for @EventListener(EventClass.class) or publishEvent(new EventClass(...))
            if trimmed.contains("@EventListener") {
                // Extract class name from annotation
                if let Some(start) = trimmed.find('(') {
                    let after_paren = &trimmed[start + 1..];
                    // Get the class name before .class or just the identifier
                    let end = after_paren.find('.').or(after_paren.find(')'));
                    if let Some(end_pos) = end {
                        let class_name = after_paren[..end_pos].trim();
                        if !class_name.is_empty() {
                            return Some(class_name.to_string());
                        }
                    }
                }
            }
            // Look for publishEvent(new EventClass(...))
            if trimmed.contains("publishEvent(")
                && let Some(start) = trimmed.find("new ")
            {
                let after_new = &trimmed[start + 4..];
                let end = after_new.find('(');
                if let Some(end_pos) = end {
                    let class_name = after_new[..end_pos].trim();
                    if !class_name.is_empty() {
                        return Some(class_name.to_string());
                    }
                }
            }
            None
        }
        Language::Python => {
            // Look for signal.send(...) or @receiver(signal)
            if trimmed.contains("@receiver(")
                && let Some(start) = trimmed.find("@receiver(")
            {
                let after_paren = &trimmed[start + 10..];
                let end = after_paren.find(')');
                if let Some(end_pos) = end {
                    let signal_name = after_paren[..end_pos].trim();
                    if !signal_name.is_empty() {
                        return Some(signal_name.to_string());
                    }
                }
            }
            // Look for signal.send(...)
            if let Some(dot_pos) = trimmed.find(".send(") {
                // Get the signal name before .send
                let before_dot = &trimmed[..dot_pos];
                let words: Vec<&str> = before_dot.split_whitespace().collect();
                if let Some(signal_name) = words.last() {
                    return Some(signal_name.to_string());
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract a string argument from the start of a string
fn extract_string_arg(s: &str) -> Option<String> {
    let trimmed = s.trim();

    // Handle single-quoted strings
    if let Some(rest) = trimmed.strip_prefix('\'') {
        let end = rest.find('\'')?;
        return Some(rest[..end].to_string());
    }

    // Handle double-quoted strings
    if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }

    // Handle template literals
    if let Some(rest) = trimmed.strip_prefix('`') {
        let end = rest.find('`')?;
        return Some(rest[..end].to_string());
    }

    None
}

/// Extract event data/arguments from an emit expression
///
/// Examples:
/// - `emitter.emit('data', userInput, extra)` -> ["userInput", "extra"]
/// - `signal.send(sender=self, data=value)` -> ["value"]
pub fn extract_emit_args(line: &str, language: Language) -> Vec<String> {
    let trimmed = line.trim();
    let mut args = Vec::new();

    match language {
        Language::JavaScript | Language::TypeScript => {
            // Find emit pattern and extract args after event name
            let patterns = [".emit(", ".trigger(", ".publish("];
            for pattern in patterns {
                if let Some(pos) = trimmed.find(pattern) {
                    let after_paren = &trimmed[pos + pattern.len()..];
                    // Skip the event name (first string arg)
                    if let Some(comma_pos) = after_paren.find(',') {
                        let rest = &after_paren[comma_pos + 1..];
                        // Extract remaining arguments
                        args.extend(extract_args_list(rest));
                    }
                    break;
                }
            }
        }
        Language::Java => {
            // For publishEvent(new Event(data)), extract constructor args
            if let Some(new_pos) = trimmed.find("new ")
                && let Some(paren_pos) = trimmed[new_pos..].find('(')
            {
                let start = new_pos + paren_pos + 1;
                if let Some(end) = find_matching_paren(&trimmed[start..]) {
                    let args_str = &trimmed[start..start + end];
                    args.extend(extract_args_list(args_str));
                }
            }
        }
        Language::Python => {
            // For signal.send(sender=self, data=value), extract keyword args
            if let Some(send_pos) = trimmed.find(".send(") {
                let after_paren = &trimmed[send_pos + 6..];
                if let Some(end) = find_matching_paren(after_paren) {
                    let args_str = &after_paren[..end];
                    // Extract values from keyword arguments
                    for part in args_str.split(',') {
                        let part = part.trim();
                        if let Some(eq_pos) = part.find('=') {
                            let value = part[eq_pos + 1..].trim();
                            if value != "self" && !value.is_empty() {
                                args.push(value.to_string());
                            }
                        } else if !part.is_empty() {
                            args.push(part.to_string());
                        }
                    }
                }
            }
        }
        _ => {}
    }

    args
}

/// Extract arguments from a comma-separated list
fn extract_args_list(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0;
    let mut current = String::new();

    for ch in s.chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' => {
                if depth > 0 {
                    depth -= 1;
                    current.push(ch);
                } else {
                    // End of args
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        args.push(trimmed.to_string());
                    }
                    return args;
                }
            }
            ',' if depth == 0 => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    args.push(trimmed.to_string());
                }
                current = String::new();
            }
            _ => {
                current.push(ch);
            }
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        args.push(trimmed.to_string());
    }

    args
}

/// Find the position of the matching closing parenthesis
fn find_matching_paren(s: &str) -> Option<usize> {
    let mut depth = 1;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_site_creation() {
        let site = EventSite::new(
            PathBuf::from("test.js"),
            10,
            "emitter.emit('data', value)".to_string(),
        )
        .with_function("handleClick".to_string())
        .with_arguments(vec!["value".to_string()]);

        assert_eq!(site.file, PathBuf::from("test.js"));
        assert_eq!(site.line, 10);
        assert_eq!(site.function, Some("handleClick".to_string()));
        assert_eq!(site.arguments, vec!["value".to_string()]);
    }

    #[test]
    fn test_event_binding() {
        let mut binding = EventBinding::new("data".to_string());
        assert!(!binding.has_emitters());
        assert!(!binding.has_listeners());

        binding.add_emit_site(EventSite::new(
            PathBuf::from("producer.js"),
            10,
            "emitter.emit('data', value)".to_string(),
        ));
        assert!(binding.has_emitters());
        assert!(!binding.is_complete());

        binding.add_listen_site(EventSite::new(
            PathBuf::from("consumer.js"),
            20,
            "emitter.on('data', handler)".to_string(),
        ));
        assert!(binding.is_complete());
    }

    #[test]
    fn test_event_registry() {
        let mut registry = EventRegistry::new();

        registry.register_emit(
            "data",
            EventSite::new(PathBuf::from("a.js"), 10, "emit".to_string()),
        );
        registry.register_listen(
            "data",
            EventSite::new(PathBuf::from("b.js"), 20, "on".to_string()),
        );

        assert_eq!(registry.emitters_of("data").len(), 1);
        assert_eq!(registry.listeners_of("data").len(), 1);
        assert_eq!(registry.complete_bindings().count(), 1);
    }

    #[test]
    fn test_js_event_name_extraction() {
        assert_eq!(
            extract_event_name("emitter.emit('data', value)", Language::JavaScript),
            Some("data".to_string())
        );
        assert_eq!(
            extract_event_name("emitter.on('click', handler)", Language::JavaScript),
            Some("click".to_string())
        );
        assert_eq!(
            extract_event_name("el.addEventListener('click', fn)", Language::JavaScript),
            Some("click".to_string())
        );
    }

    #[test]
    fn test_java_event_name_extraction() {
        assert_eq!(
            extract_event_name("@EventListener(UserCreatedEvent.class)", Language::Java),
            Some("UserCreatedEvent".to_string())
        );
        assert_eq!(
            extract_event_name(
                "publisher.publishEvent(new OrderCreatedEvent(order))",
                Language::Java
            ),
            Some("OrderCreatedEvent".to_string())
        );
    }

    #[test]
    fn test_python_event_name_extraction() {
        assert_eq!(
            extract_event_name("@receiver(user_created)", Language::Python),
            Some("user_created".to_string())
        );
        assert_eq!(
            extract_event_name(
                "post_save.send(sender=User, instance=user)",
                Language::Python
            ),
            Some("post_save".to_string())
        );
    }

    #[test]
    fn test_js_emit_args_extraction() {
        let args = extract_emit_args(
            "emitter.emit('data', userInput, extra)",
            Language::JavaScript,
        );
        assert_eq!(args, vec!["userInput", "extra"]);
    }

    #[test]
    fn test_event_patterns() {
        let patterns = EventPatterns::for_language(Language::JavaScript);
        assert!(patterns.is_emit("emitter.emit('data', value)"));
        assert!(patterns.is_listen("emitter.on('data', handler)"));
        assert!(!patterns.is_emit("emitter.on('data', handler)"));
    }
}
