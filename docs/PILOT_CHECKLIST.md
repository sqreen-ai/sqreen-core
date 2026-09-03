# Design partner — pilot checklist

Use with [QUICKSTART.md](QUICKSTART.md) and [DESIGN_PARTNER.md](DESIGN_PARTNER.md).

## PRE-PILOT

- [ ] Agree scope: **5–25 developers**, Cursor/MCP first, **non-prod** workloads
- [ ] Identify pilot owner + Cloud SOC approver(s) for Confirm / destructive actions
- [ ] Control plane + dashboard reachable (self-hosted or Sqreen-hosted)
- [ ] OIDC / human auth configured for the dashboard ([HUMAN_AUTH.md](HUMAN_AUTH.md))
- [ ] Org membership + seat limit sized for pilot headcount
- [ ] Edge binary install path decided (`install.sh` or internal package)
- [ ] Privacy expectations shared ([PRIVACY.md](PRIVACY.md))
- [ ] Success metrics agreed (see Exit criteria)

## DAY 1

- [ ] Install: `curl -fsSL https://sqreen.ai/install.sh | bash`
- [ ] `source ~/.config/mcp-proxy/env && mcp-proxy demo` — allow / block / confirm
- [ ] `mcp-proxy status` shows **Protection: ACTIVE**
- [ ] `mcp-proxy doctor` is PASS or PASS-with-WARN (no FAIL)
- [ ] Wrap at least one MCP server (or `serve` + `OPENAI_BASE_URL`)
- [ ] Mint device token → `mcp-proxy enroll --control-plane … --device-token …`
- [ ] Confirm telemetry appears on dashboard Security Events
- [ ] Approvals queue reachable; set `SQREEN_APPROVAL_MODE=remote` or `auto` if using Cloud SOC

## WEEK 1

- [ ] All pilot developers enrolled and wrapped
- [ ] At least one real BLOCK observed and understood (WHAT / WHY / RULE / NEXT)
- [ ] At least one Confirm / remote approval exercised end-to-end
- [ ] Policy overlays published without disabling the security baseline
- [ ] Doctor clean on a sample of devices; support-bundle collected once for dry-run
- [ ] No production/prod credential workloads in scope without explicit exception
- [ ] Weekly sync: false positives, missing wraps, approval latency

## EXIT CRITERIA

Pilot succeeds when:

1. **Coverage** — ≥80% of pilot developers have ACTIVE protection (`mcp-proxy status`) on their primary agent path  
2. **Signal** — Blocked / Confirm actions are visible in Cloud SOC with actionable context  
3. **Approvals** — Destructive-shaped Confirm path has a working human gate (local TTY or remote)  
4. **Ops** — `mcp-proxy doctor` is runnable by developers; support-bundle used once with redaction verified  
5. **No baseline bypass** — Team did not “fix” blocks by removing mandatory security baseline patterns  
6. **Go / no-go** — Written decision: expand cohort, adjust policy, or pause  

## Command cheat sheet

```bash
mcp-proxy demo
mcp-proxy status
mcp-proxy doctor
mcp-proxy integrations
mcp-proxy support-bundle
mcp-proxy enroll --control-plane URL --device-token TOKEN [--device-id ID]
```
