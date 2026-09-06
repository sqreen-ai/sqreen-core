# Privacy — what Sqreen Core keeps local

Standalone Sqreen Core (`mcp-proxy`) is **local-first**. This document describes
what the open-core edge binary does on a developer machine.

## Stays on the device

| Data | Notes |
|------|--------|
| Full MCP / HTTP tool payloads | Evaluated locally by policy, DLP, and risk |
| Policy file (`mcp-policy.yaml`) | On disk under the config dir or `MCP_POLICY_PATH` |
| Local shell env for PATH / policy | Typically `~/.config/mcp-proxy/env` (prefer mode `0600`) |
| Local debug log | `mcp-proxy.log` / `MCP_PROXY_LOG` — secrets masked when logged |
| Prompts and source files | **Not** read or uploaded by Core by default |
| Support bundle contents until you share them | Written under `/tmp` or `--out`; inspect first |

## Redaction and minimization

- Secret-shaped values are redacted by policy / DLP when enabled.
- CLI `status`, `doctor`, `integrations`, and `support-bundle` print sensitive
  presence as `[SET]` / `[EMPTY]` only — never echo secret values.
- Debug logs mask common secret patterns before append.

## Prompts and files

Sqreen Core enforces at the **tool-call boundary**. It does **not** by default:

- Upload chat prompts or IDE buffers anywhere
- Scan or exfiltrate repository contents outside intercepted tool arguments
- Replace your model provider’s data handling

If a tool call includes file contents or secrets in arguments, those bytes are
subject to **local** policy and DLP on the device.

## Operator controls

- Local-only is the default: install, load policy, wrap a runtime, verify traffic.
- Inspect before share: `mcp-proxy support-bundle`.

## Related

- [QUICKSTART.md](QUICKSTART.md) — local install → wrap → ALLOW/DENY
- [FAILURE_MODES.md](FAILURE_MODES.md) — broken-control behavior
- [RELEASE_INTEGRITY.md](RELEASE_INTEGRITY.md) — installer verification

Managed cloud services and remote workflows are available separately from Sqreen
Enterprise and are out of scope for this Core privacy document.
