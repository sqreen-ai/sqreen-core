# Privacy — what Sqreen sends where

Concrete defaults for design-partner conversations. Edge binary: `mcp-proxy` (Sqreen Core).

## Stays on the device (local)

| Data | Notes |
|------|--------|
| Full MCP / HTTP tool payloads | Evaluated locally by policy, DLP, risk |
| Policy file (`mcp-policy.yaml`) | On disk under config dir or `MCP_POLICY_PATH` |
| Device token | `~/.config/mcp-proxy/env` (prefer mode `0600`); **never printed** by CLI |
| Local debug log | `mcp-proxy.log` / `MCP_PROXY_LOG` — secrets masked when logged |
| Prompts and source files | **Not** read or uploaded by default |
| Support bundle contents until you share them | Written under `/tmp` or `--out`; inspect first |

## May go to the control plane (when enrolled)

Enrollment requires **both** `MCP_CONTROL_PLANE_URL` and `MCP_DEVICE_TOKEN`.

| Data | Purpose |
|------|---------|
| Device id (non-secret) | Attribution / fleet inventory |
| Org id (non-secret) | Tenancy |
| Telemetry security events | Tool name, risk score, matched pattern summary, allow/block/confirm decision, agent labels |
| Policy sync / threat-intel sync | Pull signed policy & indicators |
| Remote approval requests | Sanitized arguments + risk metadata for human gate |

## Redaction and minimization

- Secret-shaped values are redacted by policy / DLP when enabled.
- CLI status, doctor, integrations, and support-bundle print tokens as `[SET]` / `[EMPTY]` only.
- Remote approval payloads use **sanitized** arguments, not raw secret material when DLP applies.
- Debug logs mask common secret patterns before append.

## Identifiers

| Identifier | Secret? |
|------------|---------|
| `SQREEN_DEVICE_ID` / `MCP_DEVICE_ID` | No — opaque device identity |
| `SQREEN_ORG_ID` | No |
| `MCP_DEVICE_TOKEN` | **Yes** — bearer for device API |
| Approval ids | No — correlation handles |

## Prompts and files

Sqreen enforces at the **tool-call boundary**. It does **not** by default:

- Upload chat prompts or IDE buffers to Cloud SOC  
- Scan or exfiltrate repository contents outside intercepted tool arguments  
- Replace your model provider’s data handling  

If a tool call includes file contents or secrets in arguments, those bytes are subject to local policy/DLP and — only if enrolled — may appear in **redacted/sanitized** telemetry or approval records.

## Operator controls

- Stay local-only: omit control-plane env vars (doctor reports WARN, not FAIL).
- Limit cloud: enroll only pilot devices; revoke tokens in Agent Identities.
- Inspect before share: `mcp-proxy support-bundle`.

## Related

- [OPEN_CORE_SPLIT.md](OPEN_CORE_SPLIT.md) — public edge vs private cloud  
- [THREAT_MODEL.md](THREAT_MODEL.md) — trust boundaries  
- [CREDENTIALS.md](CREDENTIALS.md) — token handling  
