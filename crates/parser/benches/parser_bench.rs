//! Parser benchmarks

use criterion::{Criterion, criterion_group, criterion_main};
use rma_common::RmaConfig;
use rma_parser::ParserEngine;
use std::hint::black_box;
use std::path::Path;

fn bench_parse_rust(c: &mut Criterion) {
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config);

    let rust_code = r#"
use std::collections::HashMap;

fn main() {
    let mut map = HashMap::new();
    map.insert("key", "value");

    for (k, v) in &map {
        println!("{}: {}", k, v);
    }

    if let Some(value) = map.get("key") {
        println!("Found: {}", value);
    }
}

fn complex_function(input: &str) -> Result<i32, String> {
    let parsed: i32 = input.parse().map_err(|e| format!("{}", e))?;

    match parsed {
        0 => Ok(0),
        1..=10 => Ok(parsed * 2),
        11..=100 => Ok(parsed / 2),
        _ => Err("Out of range".to_string()),
    }
}
"#;

    c.bench_function("parse_rust_50_lines", |b| {
        b.iter(|| parser.parse_file(black_box(Path::new("test.rs")), black_box(rust_code)))
    });
}

fn bench_parse_python(c: &mut Criterion) {
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config);

    let python_code = r#"
import os
from typing import Dict, List

def main():
    data: Dict[str, int] = {}
    data["key"] = 42

    for key, value in data.items():
        print(f"{key}: {value}")

    if "key" in data:
        print(f"Found: {data['key']}")

def complex_function(input_str: str) -> int:
    try:
        parsed = int(input_str)
    except ValueError as e:
        raise ValueError(f"Parse error: {e}")

    if parsed == 0:
        return 0
    elif 1 <= parsed <= 10:
        return parsed * 2
    elif 11 <= parsed <= 100:
        return parsed // 2
    else:
        raise ValueError("Out of range")

class DataProcessor:
    def __init__(self, name: str):
        self.name = name
        self.items: List[int] = []

    def add(self, item: int) -> None:
        self.items.append(item)

    def process(self) -> int:
        return sum(self.items)
"#;

    c.bench_function("parse_python_50_lines", |b| {
        b.iter(|| parser.parse_file(black_box(Path::new("test.py")), black_box(python_code)))
    });
}

fn bench_parse_javascript(c: &mut Criterion) {
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config);

    let js_code = r#"
import { useState, useEffect } from 'react';

function App() {
    const [data, setData] = useState({});

    useEffect(() => {
        fetchData();
    }, []);

    async function fetchData() {
        const response = await fetch('/api/data');
        const json = await response.json();
        setData(json);
    }

    return (
        <div className="app">
            <h1>Hello World</h1>
            {Object.entries(data).map(([key, value]) => (
                <div key={key}>{key}: {value}</div>
            ))}
        </div>
    );
}

class DataService {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    async get(endpoint) {
        const response = await fetch(`${this.baseUrl}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP error: ${response.status}`);
        }
        return response.json();
    }
}

export { App, DataService };
"#;

    c.bench_function("parse_javascript_50_lines", |b| {
        b.iter(|| parser.parse_file(black_box(Path::new("test.js")), black_box(js_code)))
    });
}

criterion_group!(
    benches,
    bench_parse_rust,
    bench_parse_python,
    bench_parse_javascript
);
criterion_main!(benches);
