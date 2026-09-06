# Provider / runtime adapters

Contributors add new agent runtimes **only** in `mcp-proxy/src/adapters/`. The policy
engine, risk engine, approval engine, and Agent Execution Gateway must not grow
provider-specific branches.

## Lifecycle

```text
1. intercept   provider-specific wire value (hook JSON, tools/call params, …)
2. decode      ToolCallAdapter::decode → AgentAction
3. evaluate    AgentExecutionGateway (identity → policy → risk → approval)
4. enforce     RuntimeAdapter::enforce → provider-native effect
5. emit        RuntimeAdapter::emit_outcome (privacy-safe AdapterExecutionRecord)
```

Prefer [`process_with_adapter`](../mcp-proxy/src/adapters/framework.rs) (or
`process_with_adapter_owned` when the wire type is not `Copy`) so the order stays
identical across transports.

## Traits

| Trait | Responsibility |
|---|---|
| `ToolCallAdapter` | Wire → `AgentAction` only |
| `RuntimeAdapter` | Extends decode with `enforce` + `emit_outcome` |

`NormalizationContext` supplies ambient identity (`SQREEN_*` env vars, session, org).
Always build actions through `NormalizationContext::begin` so classification and identity
stay centralized.

## Public support matrix

Source of truth: `PUBLIC_INTEGRATION_MATRIX` and `RUNTIME_CATALOG` in
`mcp-proxy/src/adapters/framework.rs` (unit-tested).

| Integration | Label |
|---|---|
| Generic MCP stdio (`mcp-proxy -- run`) | **PRODUCTION_SUPPORTED** |
| Cursor via Core MCP wrap | **PILOT_SUPPORTED** |
| OpenAI-compatible HTTP (`serve` Chat Completions, non-stream response `tool_calls`) | **PILOT_SUPPORTED — LIMITED** |
| Anthropic Messages HTTP via `serve` | **EXPERIMENTAL** (adapter foundation; not wired) |
| Cursor IDE hooks | **EXPERIMENTAL / SECONDARY** |

## Adapter catalog vs public claims

See `RUNTIME_CATALOG` in `mcp-proxy/src/adapters/framework.rs`.

| Adapter id | Support | Notes |
|---|---|---|
| `mcp` | PRODUCTION_SUPPORTED | Stdio wrap engine; Cursor Core wrap uses this path |
| `openai` | PILOT_SUPPORTED | Limited HTTP serve scope (see matrix) |
| `anthropic` | EXPERIMENTAL | Adapter only — Messages proxy not wired |
| `cursor` | EXPERIMENTAL | Hooks secondary path |
| `claude_code` | EXPERIMENTAL | Hooks secondary path |
| `generic` | EXPERIMENTAL | Embedders / custom intercepts |

**Planned (do not implement in this change):** `gemini`, `langchain`, `crewai`,
`openai_agents_sdk`, `browser_computer_use`, `shell`, `rest_api_gateway`, `database`.

Until a planned adapter exists, use `GenericAdapter` with `Runtime::custom("…")` or the
helpers (`shell_command`, `filesystem_op`, `http_request`, …).

Adapter code existing in-tree is **not** the same as a production/pilot public claim.
## How to add a new adapter

1. **Pick an id and runtime slug.** Add a `RuntimeDescriptor` row to `RUNTIME_CATALOG`
   (set `RuntimeSupport` to the honest public label — not “adapter exists ⇒ production”).
   Prefer a real `Runtime` constant in `action.rs` if
   the transport is first-class; otherwise `Runtime::custom("your_runtime")`. Update
   `PUBLIC_INTEGRATION_MATRIX` when the claim surface changes.
2. **Create `mcp-proxy/src/adapters/<name>.rs`.** Define:
   - a `Wire` type (usually a thin borrow over the provider payload)
   - `YourAdapter` unit struct
   - `impl ToolCallAdapter` with `decode`
   - `impl RuntimeAdapter` with an `Effect` enum and `enforce`

3. **Register the module** in `adapters/mod.rs` (`pub mod …` + `pub use …`).

4. **Wire the transport** (stdio hook binary, HTTP middleware, sidecar) to call
   `process_with_adapter::<YourAdapter>(…)` or decode → `gateway.evaluate` →
   `YourAdapter::enforce` when the transport needs custom I/O around the effect.

5. **Tests.** Unit-test decode (happy path + malformed). Add at least one pipeline test
   that asserts `enforce` maps `Deny` / `RequireApproval` to a stopping effect and never
   puts secrets into `Effect` or `AdapterExecutionRecord`.

6. **Docs.** Link the new adapter from this file’s catalog table if you add a dedicated
   section.

### Minimal skeleton

```rust
use mcp_proxy::adapters::{
    AdapterError, NormalizationContext, RuntimeAdapter, ToolCallAdapter,
};
use mcp_proxy::action::{AgentAction, Arguments, Runtime, SourceRef};
use mcp_proxy::gateway::EvaluationOutcome;

pub struct AcmeCall<'a> {
    pub name: &'a str,
    pub arguments: &'a serde_json::Value,
}

pub struct AcmeAdapter;

pub enum AcmeEffect {
    Forward { rewritten_params_json: Option<String> },
    Deny { reason: String },
}

impl<'wire> ToolCallAdapter<'wire> for AcmeAdapter {
    type Wire = AcmeCall<'wire>;
    const ADAPTER_ID: &'static str = "acme";
    const RUNTIME: Runtime = Runtime::UNKNOWN; // or Runtime::custom("acme")

    fn decode(
        context: &NormalizationContext,
        wire: Self::Wire,
    ) -> Result<AgentAction, AdapterError> {
        let arguments = Arguments::from_name_and_arguments(wire.name, wire.arguments);
        let source = SourceRef::new(Runtime::custom("acme"), Self::ADAPTER_ID);
        Ok(context.begin(wire.name, arguments, source).build()?)
    }
}

impl<'wire> RuntimeAdapter<'wire> for AcmeAdapter {
    type Effect = AcmeEffect;

    fn enforce(
        _wire: &Self::Wire,
        _action: &AgentAction,
        outcome: &EvaluationOutcome,
    ) -> Result<Self::Effect, AdapterError> {
        if outcome.stops_execution() {
            return Ok(AcmeEffect::Deny {
                reason: outcome
                    .primary_detail()
                    .unwrap_or("blocked by mcp-proxy")
                    .to_string(),
            });
        }
        Ok(AcmeEffect::Forward {
            rewritten_params_json: outcome.rewritten_arguments.clone(),
        })
    }
}
```

## Rules that keep the core clean

- Never match on `Runtime` or adapter id inside `gateway/`, `policy/`, `scoring/`, or
  `approval/`.
- Preserve payload fidelity when existing policy regexes depend on exact bytes (see MCP /
  OpenAI adapters).
- Enforcement effects must prefer `outcome.rewritten_arguments` over raw wire args when
  present so secrets stay masked.
- `AdapterExecutionRecord` must not include arguments, headers, or file bodies.

## Existing transport wiring

| Runtime | Decode | Enforce used by | Public label |
|---|---|---|---|
| MCP stdio | `McpAdapter` | `mcp-proxy` binary (`main.rs`) | PRODUCTION_SUPPORTED (Cursor wrap: PILOT) |
| OpenAI HTTP | `OpenAiAdapter` | `http_serve.rs` via `process_with_adapter` | PILOT_SUPPORTED — LIMITED |
| Anthropic | `AnthropicAdapter` | Tests / future Messages proxy | EXPERIMENTAL |
| Cursor hooks | `CursorAdapter` | Hook bridge (effect → `to_hook_response`) | EXPERIMENTAL / SECONDARY |
| Claude Code | `ClaudeCodeAdapter` | Hook bridge (effect → `to_hook_response`) | EXPERIMENTAL / SECONDARY |
| Custom / intercepts | `GenericAdapter` | Embedders and planned runtimes | EXPERIMENTAL |
Related: [Agent Execution Gateway](./AGENT_EXECUTION_GATEWAY.md), [Failure modes](./FAILURE_MODES.md).
