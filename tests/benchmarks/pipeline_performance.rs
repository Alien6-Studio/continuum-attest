//! Performance benchmarks for ATTEST pipelines

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tempfile::TempDir;

fn benchmark_pipeline_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_parsing");

    let simple_pipeline = r#"
version: "0.1"
name: "simple"
steps:
  step1:
    run: "echo 'hello'"
"#;

    let complex_pipeline = r#"
version: "0.1"
name: "complex"
env:
  GLOBAL_VAR: "test"
steps:
  build:
    run: "cargo build"
    env:
      BUILD_MODE: "release"
  test:
    run: "cargo test"
    needs: ["build"]
  lint:
    run: "cargo clippy"
    needs: ["build"]
  coverage:
    run: "cargo tarpaulin"
    needs: ["test", "lint"]
"#;

    group.bench_function("simple_pipeline_yaml_parsing", |b| {
        b.iter(|| {
            black_box(serde_yaml::from_str::<serde_yaml::Value>(simple_pipeline).unwrap());
        });
    });

    group.bench_function("complex_pipeline_yaml_parsing", |b| {
        b.iter(|| {
            black_box(serde_yaml::from_str::<serde_yaml::Value>(complex_pipeline).unwrap());
        });
    });

    group.finish();
}

fn benchmark_string_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_operations");

    group.bench_function("hash_computation", |b| {
        b.iter(|| {
            let content = "test content for hashing benchmarks with some data";
            black_box(blake3::hash(content.as_bytes()));
        });
    });

    group.bench_function("temp_dir_creation", |b| {
        b.iter(|| {
            black_box(TempDir::new().unwrap());
        });
    });

    group.finish();
}

fn benchmark_json_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_operations");

    let json_data = r#"
    {
        "name": "test",
        "version": "0.1.0",
        "steps": [
            {"id": "1", "command": "echo hello"},
            {"id": "2", "command": "echo world"}
        ]
    }
    "#;

    group.bench_function("json_parsing", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<serde_json::Value>(json_data).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_pipeline_parsing,
    benchmark_string_operations,
    benchmark_json_operations
);
criterion_main!(benches);
