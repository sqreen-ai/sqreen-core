# mcp-proxy-sdk

Author custom WebAssembly security plugins for the [`mcp-proxy`](../mcp-proxy) sandbox.

## Build a plugin

```rust
use mcp_proxy_sdk::{export_policy_plugin, Decision, EvaluationContext, PolicyPlugin};

struct DemoPlugin;

impl PolicyPlugin for DemoPlugin {
    fn evaluate(ctx: &EvaluationContext) -> Decision {
        if ctx.tool_name() == "execute_bash" {
            Decision::block("shell execution denied by demo plugin")
        } else {
            Decision::allow()
        }
    }
}

export_policy_plugin!(DemoPlugin);
```

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

Point the proxy at the artifact:

```bash
export MCP_WASM_POLICY=target/wasm32-unknown-unknown/release/your_plugin.wasm
```

## Guest ABI

| Export | Signature |
|--------|-----------|
| `memory` | linear memory (provided by Rust) |
| `input_ptr` | `() -> i32` |
| `evaluate_policy` | `(i32) -> i32` |

| Import (`env`) | Signature |
|----------------|-----------|
| `log_violation` | `(ptr, len)` |
| `report_block` | `(ptr, len)` |
| `report_rewrite` | `(ptr, len)` |

Return codes: `0` Allow · `1` Block · `2` Rewrite
