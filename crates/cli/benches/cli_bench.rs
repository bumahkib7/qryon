//! CLI benchmarks

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_placeholder(c: &mut Criterion) {
    c.bench_function("placeholder", |b| {
        b.iter(|| {
            // Placeholder benchmark
            black_box(42)
        })
    });
}

criterion_group!(benches, bench_placeholder);
criterion_main!(benches);
