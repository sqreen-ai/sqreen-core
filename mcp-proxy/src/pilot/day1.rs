//! Shared Day-1 onboarding copy — one primary path (Cursor + MCP).

/// Primary supported Day-1 runtime.
pub const PRIMARY_RUNTIME: &str = "Cursor + MCP";

/// Exact next command when wrap is NOT CONFIGURED (manual / repair / post-install gap).
pub const INTEGRATE_COMMAND: &str = "mcp-proxy integrate cursor";

/// Exact next command to exercise the real gateway (not `demo`).
pub const PROVE_COMMAND: &str = "mcp-proxy prove";

/// Synthetic allow path (never a real project secret).
pub const DAY1_ALLOW_PATH: &str = "/tmp/sqreen-demo-ok.txt";

/// Synthetic deny path (credential-shaped fixture under /tmp — not ~/.ssh).
pub const DAY1_DENY_PATH: &str = "/tmp/sqreen-demo.ssh/id_rsa";

/// Prints the primary wrap step.
pub fn print_integrate_next() {
    println!("  {INTEGRATE_COMMAND}");
    println!("  Then: restart Cursor (or Reload MCP), ask Cursor to read {DAY1_ALLOW_PATH}");
    println!("        (`{PROVE_COMMAND}` = gateway self-check only — does not mint VERIFIED_ACTIVE).");
}

/// Prints restart + real wrap traffic when wrap exists but traffic is unverified.
pub fn print_verify_traffic_next() {
    println!("  Wrap configured ✓ — traffic is NOT verified yet.");
    println!("  1. Restart Cursor / Reload Window (or MCP: Restart Servers)");
    println!("  2. Ask Cursor to read {DAY1_ALLOW_PATH} (real wrapped tools/call)");
    println!("     `{PROVE_COMMAND}` only self-checks the gateway — it does not verify wrap traffic.");
    println!("  3. `mcp-proxy status`  → expect Runtime coverage: VERIFIED_ACTIVE");
}

/// Prints optional Cloud step after local VERIFIED_ACTIVE (enterprise builds only).
pub fn print_optional_cloud_next() {
    #[cfg(feature = "enterprise")]
    {
        println!("  Optional Cloud:");
        println!("    mcp-proxy enroll --control-plane URL --device-token TOKEN");
        println!("    Restart Cursor / reload MCP, take one wrapped tools/call, then `mcp-proxy status`");
        println!("    → Cloud Enrollment: CONFIGURED · Connection: VERIFIED (when reachable)");
    }
    #[cfg(not(feature = "enterprise"))]
    {
        println!("  Enterprise management and remote workflows are available separately.");
    }
}
