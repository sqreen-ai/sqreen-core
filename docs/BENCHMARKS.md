# Enforcement benchmarks

Reproducible Criterion suite for the Sqreen **local enforcement path** (`mcp-proxy`).

**Goal:** establish baseline latency / throughput / rough memory before any optimization.  
**Rule:** security correctness is never traded for speed — benches call the same engines as production.

## What is measured

| Criterion group | Code path |
|-----------------|-----------|
| `normalization` | MCP `McpAdapter::decode` → `AgentAction` |
| `policy_evaluation` | `PolicyStage::evaluate` with **1 / 10 / 100 / 1_000** tool rules |
| `dlp_detection` | `RiskStage::scan` (clean + synthetic secret) and `mask_secrets_in_text` |
| `risk_evaluation` | `RiskStage::evaluate` after a precomputed scan |
| `behavioral_detection` | `BehaviorEngine::evaluate` on a warmed profile |
| `gateway_total` | Full `AgentExecutionGateway::evaluate` (policy + risk + behavior + auto-approve) |

Payload sizes: **small** (~100 B), **medium** (~4 KiB), **large** (~64 KiB). Gateway total also runs large × policy counts. An **xlarge** (~256 KiB) fixture exists in the harness for ad-hoc use.

Approvals use `AllowAllApprovalEngine` so benches never block on `/dev/tty`. Audit uses `NullAuditSink`. No cloud I/O.

## Reproduce locally

From `mcp-proxy/`:

```bash
# Full suite (release, HTML report under target/criterion/)
cargo bench --bench enforcement

# Or via helper script (same command + tips)
./scripts/run-benchmarks.sh

# Filter a single group
cargo bench --bench enforcement -- normalization
cargo bench --bench enforcement -- policy_evaluation
cargo bench --bench enforcement -- gateway_total

# Save / compare baselines
cargo bench --bench enforcement -- --save-baseline $(git rev-parse --short HEAD)
cargo bench --bench enforcement -- --baseline <prior-short-sha>
```

Requirements: Rust toolchain able to build `mcp-proxy` (same as `cargo test`). First run downloads Criterion.

### Interpreting Criterion output

- Criterion’s primary `time: [lo mid hi]` line is a **confidence interval around the estimated mean** of samples (not literal p50/p95/p99). For distribution detail, open `target/criterion/*/report/index.html` (histogram / PDF plots).
- **Throughput** — elements/s (evaluations) or bytes/s (payload size for normalize/DLP).
- **Memory** — Criterion does not track RSS. The suite prints a **memory spot-check** via `ps` RSS before setup, after setup, and after a fixed batch of mixed evals. On macOS you can also run:

```bash
/usr/bin/time -l cargo bench --bench enforcement -- policy_evaluation
```

Treat RSS numbers as approximate (allocator + Criterion overhead).

## Policy scale notes

“N policies” here means **N tool entries** in a generated YAML document (`read_file` + `N-1` decoy tools), compiled once outside the timed loop. That stresses the compiled rule list the way a large corporate policy would. If wall-clock for **1_000** is unacceptable on a laptop, filter:

```bash
cargo bench --bench enforcement -- 'policy_evaluation/1$'
```

## First baseline (illustrative)

Captured when the suite was introduced. **Not a product SLO** — re-run locally and `--save-baseline`.

| Group | Config | Approx. Criterion mid | Notes |
|-------|--------|----------------------|-------|
| normalization | small | ~4.4 µs | |
| normalization | large (~64 KiB) | ~74 µs | Scales with payload |
| policy_evaluation | 1 rule | ~2.9 µs | |
| policy_evaluation | 1_000 rules | ~15.6 µs | ~5× vs 1 rule |
| dlp_detection | scan_clean small | ~2.9 µs | |
| dlp_detection | scan_clean large | ~3.5 **ms** | Dominates large path |
| dlp_detection | mask_secrets_in_text large | ~20 µs | Cheaper than full `scan` |
| risk_evaluation | evaluate (pre-scanned) | ~0.4 µs | Scan cost is elsewhere |
| behavioral_detection | evaluate | ~0.7 µs | |
| gateway_total | 1 rule / small | ~12 µs | |
| gateway_total | 1 rule / large | ~3.5 **ms** | Tracks DLP scan |
| gateway_total | 1_000 rules / small | ~25 µs | Policy scale visible |
| gateway_total | 1_000 rules / large | ~3.6 ms | Still DLP-bound |

**Memory spot-check (RSS via `ps`):** ~7 MiB → ~15 MiB after setup → ~19 MiB after 2_000 mixed evals.

### Obvious bottlenecks (from that baseline)

1. **`RiskStage::scan` / `analyze_params` on large payloads** (~3.5 ms) — drives `gateway_total` for large args. Highest leverage if optimization is ever justified.
2. **Normalization cost grows with payload size** — secondary to DLP for large bodies.
3. **Policy rule count (1 → 1_000)** — ~2.9 µs → ~15.6 µs; meaningful for small actions, drowned by DLP on large ones.
4. **Not bottlenecks at this scale:** risk evaluate-after-scan, behavioral evaluate (sub-µs).

No optimizations applied in this change — baselines first.

If a change improves a number but weakens fail-closed behavior, reject the change.

## Security invariants for bench changes

- Do not stub `PolicyEngine` / `RiskStage` with “fast fake” implementations in this suite.
- Do not disable DLP or lower risk thresholds to make charts look better.
- Synthetic secrets must remain **fake shapes** only (see `support.rs`).
- Keep auto-approve confined to the bench harness; production defaults stay fail-closed on missing approval.
