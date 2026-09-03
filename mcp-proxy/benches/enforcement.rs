//! Reproducible enforcement-path benchmarks (Criterion).
//!
//! Stages measured separately:
//! - action normalization (MCP adapter)
//! - policy evaluation (scaled rule counts)
//! - secret / DLP detection (`RiskStage::scan` / mask path)
//! - risk evaluation (`RiskStage::evaluate`)
//! - behavioral detection (`BehaviorEngine::evaluate`)
//! - total gateway evaluation (`AgentExecutionGateway::evaluate`)
//!
//! See `docs/BENCHMARKS.md` at the repo root (or `../docs` via monorepo) and
//! `mcp-proxy/README.md` for how to run and interpret results.
//!
//! Security correctness is not relaxed for these benches: the same PolicyEngine /
//! RiskStage / gateway code paths as production are used. Approvals are
//! auto-approved only so the bench does not block on a TTY.

mod support;

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use mcp_proxy::gateway::{FailurePolicy, PolicyStage};
use mcp_proxy::risk::mask_secrets_in_text;
use support::{
    behavior_engine, gateway, mcp_params_json, mcp_params_with_synthetic_secret, normalize_mcp,
    policy_engine, policy_stage, print_rss, risk_stage, PayloadSize,
};

const POLICY_COUNTS: &[usize] = &[1, 10, 100, 1_000];
const PAYLOADS: &[PayloadSize] = &[PayloadSize::Small, PayloadSize::Medium, PayloadSize::Large];

fn bench_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalization");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &size in PAYLOADS {
        let params = mcp_params_json(size, "/tmp/sqreen-bench-ok.txt");
        group.throughput(Throughput::Bytes(params.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("mcp_decode", size.label()),
            &params,
            |b, params| {
                b.iter(|| {
                    let action = normalize_mcp(params);
                    black_box(action.tool_name());
                });
            },
        );
    }
    group.finish();
}

fn bench_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluation");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(4));

    let action = normalize_mcp(&mcp_params_json(
        PayloadSize::Small,
        "/tmp/sqreen-bench-ok.txt",
    ));
    let failure = FailurePolicy::default();

    for &count in POLICY_COUNTS {
        let stage = policy_stage(count);
        // Touch once so compile cost is outside the timed loop (engine already compiled).
        let _ = stage.evaluate(&action, None, None, &failure);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(count), &stage, |b, stage| {
            b.iter(|| {
                black_box(stage.evaluate(black_box(&action), None, None, black_box(&failure)));
            });
        });
    }
    group.finish();
}

fn bench_dlp(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp_detection");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    let stage = risk_stage();

    for &size in PAYLOADS {
        let clean = normalize_mcp(&mcp_params_json(size, "/tmp/sqreen-bench-ok.txt"));
        let dirty = normalize_mcp(&mcp_params_with_synthetic_secret(size));

        group.throughput(Throughput::Bytes(clean.canonical_params_json().len() as u64));
        group.bench_with_input(
            BenchmarkId::new("scan_clean", size.label()),
            &clean,
            |b, action| {
                b.iter(|| black_box(stage.scan(black_box(action))));
            },
        );

        group.throughput(Throughput::Bytes(dirty.canonical_params_json().len() as u64));
        group.bench_with_input(
            BenchmarkId::new("scan_secret", size.label()),
            &dirty,
            |b, action| {
                b.iter(|| black_box(stage.scan(black_box(action))));
            },
        );

        let text = dirty.canonical_params_json().to_string();
        group.bench_with_input(
            BenchmarkId::new("mask_secrets_in_text", size.label()),
            &text,
            |b, text| {
                b.iter(|| black_box(mask_secrets_in_text(black_box(text))));
            },
        );
    }
    group.finish();
}

fn bench_risk(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk_evaluation");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    let stage = risk_stage();
    for &size in PAYLOADS {
        let action = normalize_mcp(&mcp_params_json(size, "/tmp/sqreen-bench-ok.txt"));
        let analysis = stage.scan(&action);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("evaluate", size.label()),
            &(action, analysis),
            |b, (action, analysis)| {
                b.iter(|| {
                    black_box(stage.evaluate(
                        black_box(action),
                        black_box(analysis.clone()),
                        Some(70),
                        None,
                    ));
                });
            },
        );
    }
    group.finish();
}

fn bench_behavior(c: &mut Criterion) {
    let mut group = c.benchmark_group("behavioral_detection");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    let engine = behavior_engine();
    // Seed a short history so profile work is representative.
    for i in 0..8 {
        let path = format!("/tmp/sqreen-bench-hist-{i}.txt");
        let action = normalize_mcp(&mcp_params_json(PayloadSize::Small, &path));
        engine.record(&action);
    }
    let probe = normalize_mcp(&mcp_params_json(
        PayloadSize::Small,
        "/tmp/sqreen-bench-ok.txt",
    ));

    group.throughput(Throughput::Elements(1));
    group.bench_function("evaluate", |b| {
        b.iter(|| black_box(engine.evaluate(black_box(&probe))));
    });
    group.finish();
}

fn bench_gateway_total(c: &mut Criterion) {
    let mut group = c.benchmark_group("gateway_total");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    for &count in POLICY_COUNTS {
        for &size in &[PayloadSize::Small, PayloadSize::Large] {
            let gw = gateway(count, true);
            let action = normalize_mcp(&mcp_params_json(size, "/tmp/sqreen-bench-ok.txt"));
            // One warm evaluation outside the timer.
            let _ = rt.block_on(gw.evaluate(&action));

            let id = format!("rules_{count}/{}", size.label());
            group.throughput(Throughput::Elements(1));
            group.bench_with_input(
                BenchmarkId::from_parameter(id),
                &(gw, action),
                |b, (gw, action)| {
                    b.to_async(&rt).iter(|| async {
                        black_box(gw.evaluate(black_box(action)).await);
                    });
                },
            );
        }
    }
    group.finish();
}

/// One-shot RSS sample around a fixed batch — Criterion does not report memory itself.
fn memory_spot_check() {
    eprintln!("=== memory spot-check (not Criterion; approximate RSS via ps) ===");
    print_rss("before_setup");

    let engines: Vec<_> = POLICY_COUNTS
        .iter()
        .copied()
        .map(|n| {
            let engine = policy_engine(n);
            let stage = PolicyStage::new(Some(Arc::clone(&engine)), None);
            (n, engine, stage)
        })
        .collect();

    let gw = gateway(100, true);
    let action = normalize_mcp(&mcp_params_json(
        PayloadSize::Large,
        "/tmp/sqreen-bench-ok.txt",
    ));
    let risk = risk_stage();
    let failure = FailurePolicy::default();

    print_rss("after_setup");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio");

    const BATCH: usize = 2_000;
    for _ in 0..BATCH {
        let _ = engines[engines.len() - 1]
            .2
            .evaluate(&action, None, None, &failure);
        let _ = risk.scan(&action);
        let _ = rt.block_on(gw.evaluate(&action));
    }

    print_rss(&format!("after_{BATCH}_mixed_evals"));
    // Keep engines alive until after the sample.
    black_box(engines);
}

fn enforcement_benches(c: &mut Criterion) {
    memory_spot_check();
    bench_normalization(c);
    bench_policy(c);
    bench_dlp(c);
    bench_risk(c);
    bench_behavior(c);
    bench_gateway_total(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = enforcement_benches
}
criterion_main!(benches);
